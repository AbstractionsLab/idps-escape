#!/usr/bin/env bash
set -Eeuo pipefail

SCENARIO="${1:?Usage: manager-apply-scenario.sh <scenario>}"
RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VOLUMES_YML="$RADAR_ROOT/volumes.yml"
CONTAINER="wazuh.manager"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
radar_load_env "$RADAR_ROOT"

hostpath() { grep -E ":${1//\//\\/}\$" "$VOLUMES_YML" | head -1 | sed -E 's/^ *- *//; s/:[^:]*$//'; }
INTEGRATIONS_DIR=$(hostpath '/var/ossec/integrations')
OSSEC_ETC=$(hostpath '/var/ossec/etc')
OSSEC_LOGS=$(hostpath '/var/ossec/logs')
AR_BIN=$(hostpath '/var/ossec/active-response/bin')
FILEBEAT_ETC=$(hostpath '/etc/filebeat')
PIPELINE_JSON=$(hostpath '/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json')

echo ">>> Active response files..."
mkdir -p "$AR_BIN"
[[ -f "$RADAR_ROOT/.env" ]] && cp "$RADAR_ROOT/.env" "$AR_BIN/active_responses.env" && echo "OK - copied active_responses.env"
[[ -f "$RADAR_ROOT/scenarios/active_responses/radar_ar.py" ]] && cp "$RADAR_ROOT/scenarios/active_responses/radar_ar.py" "$AR_BIN/radar_ar.py" && echo "OK - copied radar_ar.py"
[[ -f "$RADAR_ROOT/scenarios/active_responses/ar.yaml" ]] && cp "$RADAR_ROOT/scenarios/active_responses/ar.yaml" "$AR_BIN/ar.yaml" && echo "OK - copied ar.yaml"

dexec "dnf -y install python3-pyyaml python3-requests >/dev/null 2>&1 || true"
dexec "chown root:wazuh /var/ossec/active-response/bin/active_responses.env /var/ossec/active-response/bin/radar_ar.py /var/ossec/active-response/bin/ar.yaml 2>/dev/null || true
chmod 0660 /var/ossec/active-response/bin/active_responses.env 2>/dev/null || true
chmod 0750 /var/ossec/active-response/bin/radar_ar.py 2>/dev/null || true
chmod 0640 /var/ossec/active-response/bin/ar.yaml 2>/dev/null || true"

echo ">>> Enrichment..."
case "$SCENARIO" in
  suspicious_login) ENRICH_SCRIPTS="custom-radar-enrich" ;;
  geoip_detection)   ENRICH_SCRIPTS="custom-radar-enrich custom-radar-web-enrich" ;;
  *) ENRICH_SCRIPTS="" ;;
esac

enrich_modules_for() {
  case "$1" in
    custom-radar-enrich)     echo "geoip.py state_store.py enrichment.py" ;;
    custom-radar-web-enrich) echo "geoip.py web_enrichment.py" ;;
  esac
}

if [[ -n "$ENRICH_SCRIPTS" ]]; then
  mkdir -p "$INTEGRATIONS_DIR/radar_enrichment" "$OSSEC_ETC/radar" "$OSSEC_LOGS/radar"
  touch "$OSSEC_LOGS/radar/enriched_web_access.log" || true
  touch "$OSSEC_LOGS/radar/enriched_auth.log" || true
  touch "$OSSEC_LOGS/radar/enrichment_errors.log" || true
  chown root:wazuh "$OSSEC_LOGS/radar/enriched_web_access.log" 2>/dev/null || true
  chown root:wazuh "$OSSEC_LOGS/radar/enriched_auth.log" 2>/dev/null || true
  chown root:wazuh "$OSSEC_LOGS/radar/enrichment_errors.log" 2>/dev/null || true
  chmod 0660 "$OSSEC_LOGS/radar/enriched_web_access.log" 2>/dev/null || true
  chmod 0660 "$OSSEC_LOGS/radar/enriched_auth.log" 2>/dev/null || true
  chmod 0660 "$OSSEC_LOGS/radar/enrichment_errors.log" 2>/dev/null || true
  for ENRICH_SCRIPT in $ENRICH_SCRIPTS; do
    cp "$RADAR_ROOT/manager-enrichment/$ENRICH_SCRIPT" "$INTEGRATIONS_DIR/$ENRICH_SCRIPT"
    chmod 0750 "$INTEGRATIONS_DIR/$ENRICH_SCRIPT"
    for m in $(enrich_modules_for "$ENRICH_SCRIPT"); do
      cp "$RADAR_ROOT/manager-enrichment/$m" "$INTEGRATIONS_DIR/radar_enrichment/$m"
      chmod 0640 "$INTEGRATIONS_DIR/radar_enrichment/$m"
    done
    echo "OK - copied $ENRICH_SCRIPT + modules"
  done

  dexec "chown root:wazuh /var/ossec/integrations/custom-radar-enrich /var/ossec/integrations/custom-radar-web-enrich /var/ossec/integrations/radar_enrichment/*.py 2>/dev/null || true
chown -R root:wazuh /var/ossec/etc/radar /var/ossec/logs/radar 2>/dev/null || true
chmod 0770 /var/ossec/etc/radar /var/ossec/logs/radar 2>/dev/null || true"

  echo ">>> Ensuring maxminddb python package in manager container..."
  dexec "/var/ossec/framework/python/bin/python3 -m pip show maxminddb >/dev/null 2>&1 || /var/ossec/framework/python/bin/python3 -m pip install --no-cache-dir maxminddb"

  for edition in City ASN; do
    DEST="$OSSEC_ETC/radar/GeoLite2-${edition}.mmdb"
    if [[ -f "$DEST" ]]; then
      echo "OK - GeoLite2-${edition}.mmdb already present"
      continue
    fi
    if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
      echo "[!] GeoLite2-${edition}.mmdb missing and no MAXMIND_LICENSE_KEY set -- skipping"
      continue
    fi
    echo ">>> Downloading GeoLite2-${edition}..."
    TMPDIR=$(mktemp -d)
    if curl --fail --silent --show-error --location \
      "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-${edition}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
      -o "$TMPDIR/${edition}.tar.gz"; then
      tar -xzf "$TMPDIR/${edition}.tar.gz" -C "$TMPDIR"
      find "$TMPDIR" -name "GeoLite2-${edition}.mmdb" -exec cp {} "$DEST" \;
      echo "OK - installed GeoLite2-${edition}.mmdb"
    else
      echo "[!] MaxMind download failed for ${edition}"
    fi
    rm -rf "$TMPDIR"
  done
  dexec "chown root:wazuh /var/ossec/etc/radar/*.mmdb 2>/dev/null || true; chmod 0640 /var/ossec/etc/radar/*.mmdb 2>/dev/null || true"
fi

echo ">>> Agent enrollment (authd) config..."
bash "$RADAR_ROOT/radar_deploy/manager-harden-enrollment.sh"

CHANGED=false

echo ">>> Filebeat / OpenSearch pipeline..."

if [[ "$SCENARIO" == "log_volume" ]]; then
  TEMPLATE="$RADAR_ROOT/scenarios/templates/$SCENARIO/radar-template.json"
  if [[ ! -f "$TEMPLATE" ]]; then
    echo "[ERROR] log_volume requires $TEMPLATE, but it's missing from the repository." >&2
    exit 1
  fi
  if [[ -z "${OS_URL:-}" ]]; then
    echo "[ERROR] log_volume requires OS_URL to be set in .env to register its index template." >&2
    exit 1
  fi

  STATUS=$(curl -s -o /dev/null -w '%{http_code}' -u "${OS_USER}:${OS_PASS}" -k -X PUT \
    "${OS_URL%/}/_index_template/radar-log-volume" -H 'Content-Type: application/json' --data-binary "@$TEMPLATE") || true
  if [[ "$STATUS" == "200" || "$STATUS" == "201" ]]; then
    echo "OK - index template PUT ($STATUS)"
  else
    echo "[ERROR] Could not register the log_volume index template (HTTP ${STATUS:-000}) at" >&2
    echo "        ${OS_URL%/}/_index_template/radar-log-volume" >&2
    exit 1
  fi

  SNIPPET="$RADAR_ROOT/scenarios/pipelines/$SCENARIO/radar-pipeline.txt"
  if [[ -f "$SNIPPET" && -f "$PIPELINE_JSON" ]]; then
    if grep -qF "log_volume_metric" "$PIPELINE_JSON"; then
      echo "OK - log_volume date_index_name already patched into pipeline.json"
    else
      PRE_HASH=$(md5sum "$PIPELINE_JSON" | awk '{print $1}')
      SNIPPET_CONTENT="$(cat "$SNIPPET")" perl -0777 -i -pe '
        s/\{\s*"date_index_name"\s*:\s*\{.*?"index_name_prefix"\s*:\s*"\{\{fields\.index_prefix\}\}".*?"ignore_failure"\s*:\s*(true|false)\s*\}\s*\},/$ENV{SNIPPET_CONTENT}/s
      ' "$PIPELINE_JSON"
      POST_HASH=$(md5sum "$PIPELINE_JSON" | awk '{print $1}')
      [[ "$PRE_HASH" != "$POST_HASH" ]] && { echo "OK - patched log_volume date_index_name into pipeline.json"; CHANGED=true; }
    fi
  fi
fi

FILEBEAT_YML="$FILEBEAT_ETC/filebeat.yml"
if [[ -f "$FILEBEAT_YML" ]]; then
  PRE_HASH=$(md5sum "$FILEBEAT_YML" | awk '{print $1}')
  sed -i -E 's/^([ \t]*enabled:[ \t]*).*$/\1true/' "$FILEBEAT_YML"
  perl -0777 -i -pe 's/archives:[\s\S]*?var\.paths:[\s\S]*?-.*(?:\n|$)/archives:\n  enabled: true\n  var.paths:\n    - \/var\/ossec\/logs\/archives\/archives.json\n/s' "$FILEBEAT_YML"
  POST_HASH=$(md5sum "$FILEBEAT_YML" | awk '{print $1}')
  if [[ "$PRE_HASH" != "$POST_HASH" ]]; then
    echo "OK - filebeat.yml archives.enabled patched"
    CHANGED=true
    dexec "chown root:root /etc/filebeat/filebeat.yml 2>/dev/null || true; chmod 0644 /etc/filebeat/filebeat.yml 2>/dev/null || true"
  fi
fi

if [[ "$CHANGED" == "true" ]]; then
  echo ">>> Restarting manager container to pick up filebeat/pipeline changes..."
  docker restart "$CONTAINER" >/dev/null
  echo ">>> Waiting for the Wazuh API to become reachable after restart..."
  PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli wait-for-api --timeout 120
fi

dexec "filebeat setup --pipelines --modules wazuh >/tmp/fb-setup.out 2>&1 || true; cat /tmp/fb-setup.out"