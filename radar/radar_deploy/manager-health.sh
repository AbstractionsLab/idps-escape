#!/usr/bin/env bash

set -Eeuo pipefail

SCENARIO_FILTER="${1:-all}"
CONTAINER="wazuh.manager"
RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"

if [[ "$SCENARIO_FILTER" == "all" ]]; then
  SCENARIOS="$(PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli list-scenarios)"
else
  SCENARIOS="$SCENARIO_FILTER"
fi

has() { [[ " $SCENARIOS " == *" $1 "* ]]; }

for c in "$CONTAINER" ad-webhook; do
  docker ps --format '{{.Names}}' | grep -qx "$c" && echo "OK - container $c running" || echo "FAIL - container $c not running"
done

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