#!/usr/bin/env bash

set -Eeuo pipefail

SCENARIO_FILTER="${1:-all}"
RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
radar_load_env "$RADAR_ROOT"

bash "$RADAR_ROOT/radar_deploy/manager-revoke-token.sh" --if-expired || \
  echo "FAIL - an expired enrollment token could not be revoked; run radar_deploy/manager-revoke-token.sh"

MANAGER_CONTAINERS="$(radar_manager_containers "$RADAR_ROOT")"
if [[ -z "$MANAGER_CONTAINERS" ]]; then
  echo "FAIL - no manager nodes registered in infra.yaml"
  exit 1
fi

if [[ "$SCENARIO_FILTER" == "all" ]]; then
  SCENARIOS="$(PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli list-scenarios)"
else
  SCENARIOS="$SCENARIO_FILTER"
fi

has() { [[ " $SCENARIOS " == *" $1 "* ]]; }
INDEXER_CONTAINER="$(PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.infra container indexer 2>/dev/null)" || INDEXER_CONTAINER="wazuh.indexer"
WEBHOOK_CONTAINER="${WEBHOOK_CONTAINER_NAME:-ad-webhook}"
RUNNING_CONTAINERS="$(docker ps --format '{{.Names}}')"
is_container_running() { grep -qx "$1" <<< "$RUNNING_CONTAINERS"; }

is_container_running "$WEBHOOK_CONTAINER" \
  && echo "OK - container $WEBHOOK_CONTAINER running" \
  || echo "FAIL - container $WEBHOOK_CONTAINER not running"

check_file() {
  local label="$1" path="$2" severity="${3:-FAIL}" grp
  grp=$(dexec_quiet "test -f '$path' && stat -c '%G' '$path'") || true
  if [[ -z "$grp" ]]; then
    echo "$severity - $label not found at $path"
  elif [[ "$grp" == "wazuh" ]]; then
    echo "OK - $label present (group: wazuh)"
  else
    echo "WARN - $label group is '$grp' (expected wazuh)"
  fi
}

check_reachable() {
  local label="$1" from_container="$2" url="$3"; shift 3
  local out
  if ! is_container_running "$from_container"; then
    echo "SKIP - $label check (container $from_container not running)"
    return
  fi
  out=$(docker exec "$from_container" curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" "$url" 2>&1) || true
  if [[ "$out" =~ ^[0-9]{3}$ ]]; then
    echo "OK - $label reachable from $from_container (HTTP $out)"
  else
    echo "FAIL - $label NOT reachable from $from_container: ${out:-no response}"
  fi
}

RESOLVED_INDEXER_HOST="$(PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.infra address indexer 2>/dev/null)" || RESOLVED_INDEXER_HOST="${WAZUH_INDEXER_HOST:-}"

check_manager_node() {
  CONTAINER="$1"

  is_container_running "$CONTAINER" \
    && echo "OK - container $CONTAINER running" \
    || { echo "FAIL - container $CONTAINER not running"; return; }

  check_file "radar_ar.py" /var/ossec/active-response/bin/radar_ar.py
  check_file "ar.yaml" /var/ossec/active-response/bin/ar.yaml
  check_file "active_responses.env" /var/ossec/active-response/bin/active_responses.env
  check_file "ossec.conf" /var/ossec/etc/ossec.conf
  check_file "agent.conf" /var/ossec/etc/shared/default/agent.conf WARN

  if has suspicious_login || has geoip_detection; then
    PYVER=$(dexec_quiet "/var/ossec/framework/python/bin/python3 --version 2>&1") || true
    [[ "$PYVER" == Python* ]] && echo "OK - framework $PYVER available" || echo "FAIL - framework python3 not found"
    dexec_quiet "/var/ossec/framework/python/bin/python3 -c 'import maxminddb'" >/dev/null 2>&1 \
      && echo "OK - maxminddb available" || echo "FAIL - maxminddb not available"
  fi

  if has log_volume; then
    dexec_quiet "grep -q log_volume_metric /usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json" \
      && echo "OK - log_volume pipeline patch present" || echo "FAIL - log_volume pipeline patch missing (run build-radar.sh)"
  fi

  if has suspicious_login; then
    for f in custom-radar-enrich radar_enrichment/geoip.py radar_enrichment/state_store.py radar_enrichment/enrichment.py; do
      check_file "$(basename "$f")" "/var/ossec/integrations/$f"
    done
    for db in GeoLite2-City.mmdb GeoLite2-ASN.mmdb; do
      check_file "$db" "/var/ossec/etc/radar/$db"
    done

    STORE=$(dexec_quiet "test -f /var/ossec/etc/radar/user_state.sqlite3 && (test -w /var/ossec/etc/radar/user_state.sqlite3 && echo writable || echo readonly) || echo missing") || true
    case "$STORE" in
      writable) echo "OK - user_state.sqlite3 present and writable" ;;
      readonly) echo "FAIL - user_state.sqlite3 present but not writable" ;;
      *) echo "WARN - user_state.sqlite3 not created yet (no logins enriched since setup?)" ;;
    esac

    ERRLOG=$(dexec_quiet "test -f /var/ossec/logs/radar/enrichment_errors.log && tail -n 20 /var/ossec/logs/radar/enrichment_errors.log") || true
    [[ -z "$ERRLOG" ]] && echo "OK - enrichment_errors.log empty/absent" || echo "FAIL - enrichment_errors.log has recent entries (see manager logs)"
  fi

  if [[ -n "$RESOLVED_INDEXER_HOST" ]]; then
    check_reachable "OpenSearch ($RESOLVED_INDEXER_HOST)" "$CONTAINER" "${RESOLVED_INDEXER_HOST%/}/_cluster/health" -k
  fi

  if [[ -n "${DECIPHER_BASE_URL:-}" ]]; then
    check_reachable "DECIPHER ($DECIPHER_BASE_URL)" "$CONTAINER" "${DECIPHER_BASE_URL%/}/health" -k
  fi
}

FIRST=1
while IFS= read -r node; do
  [[ -z "$node" ]] && continue
  [[ "$FIRST" -eq 1 ]] && FIRST=0 || echo ""
  echo "--- $node ---"
  check_manager_node "$node"
done <<< "$MANAGER_CONTAINERS"

RESOLVED_WEBHOOK_URL="${WEBHOOK_URL:-}"
if has log_volume && [[ -n "$RESOLVED_WEBHOOK_URL" ]]; then
  echo ""
  check_reachable "Webhook ($RESOLVED_WEBHOOK_URL)" "$INDEXER_CONTAINER" "$RESOLVED_WEBHOOK_URL"
fi