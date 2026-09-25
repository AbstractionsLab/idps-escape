#!/usr/bin/env bash

set -Eeuo pipefail

RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RADAR_ROOT"
export PYTHONPATH="$RADAR_ROOT${PYTHONPATH:+:$PYTHONPATH}"
# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: rotate-credentials needs root (docker compose, bind mounts). Re-run with sudo." >&2
  exit 1
fi

MANAGER="$(radar_manager_container "$RADAR_ROOT")"
INDEXER="$(python3 -m wazuh_api.infra container indexer 2>/dev/null)" || INDEXER="wazuh.indexer"

python3 -m wazuh_api.credentials rotate --radar-root "$RADAR_ROOT" --indexer "$INDEXER" --manager "$MANAGER"
radar_load_env "$RADAR_ROOT"

echo ">>> Recreating the core stack with the new credentials..."
OVERLAY_YAML="$(python3 -m wazuh_api.cli core-volumes-overlay)"
echo "$OVERLAY_YAML" | docker compose -f docker-compose.core.yml -f - up -d --force-recreate

export WAZUH_API_URL WAZUH_AUTH_USER WAZUH_AUTH_PASS OS_URL OS_USER OS_PASS
echo ">>> Verifying the Wazuh API with the new password..."
python3 -m wazuh_api.cli wait-for-api --timeout 180
echo ">>> Verifying OpenSearch with the new password..."
python3 -m wazuh_api.cli wait-for-opensearch --timeout 180

AR_BIN="$(radar_hostpath "$RADAR_ROOT" /var/ossec/active-response/bin "$MANAGER" || true)"
if [[ -n "$AR_BIN" && -f "$AR_BIN/active_responses.env" ]]; then
  echo ">>> Refreshing active_responses.env..."
  # shellcheck disable=SC2034  # read by dexec() in _lib.sh
  CONTAINER="$MANAGER"
  RESOLVED_OS_URL="$(python3 -m wazuh_api.infra resolve manager indexer 2>/dev/null)" || RESOLVED_OS_URL="${OS_URL:-}"
  python3 -m wazuh_api.ar_env write "$AR_BIN/active_responses.env" --env-file "$RADAR_ROOT/.env" \
    --os-url "$RESOLVED_OS_URL" --manager-address "${WAZUH_MANAGER_ADDRESS:-$(detect_manager_address)}"
  dexec "chown root:wazuh /var/ossec/active-response/bin/active_responses.env && chmod 0440 /var/ossec/active-response/bin/active_responses.env"
fi

echo ""
echo "=== Credentials rotated. The dashboard 'admin' login now uses OS_PASS from .env. ==="
echo "Restart the RADAR GUI if it is running, so it re-reads .env."
