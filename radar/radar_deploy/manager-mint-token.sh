#!/usr/bin/env bash
set -Eeuo pipefail

GROUP="${1:?Usage: manager-mint-token.sh <group>[,<group>...] [expiry_minutes] [manager_address]}"
EXPIRY_MINUTES="${2:-60}"
detect_manager_address() {
  local addr
  addr="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')"
  if [[ -z "$addr" ]]; then
    addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  printf '%s' "$addr"
}

MANAGER_ADDRESS="${3:-$(detect_manager_address)}"
CONTAINER="wazuh.manager"
RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
radar_load_env "$RADAR_ROOT"

TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '=+/' | head -c 32)

echo ">>> Setting enrollment token (expires in ${EXPIRY_MINUTES}m)..."
dexec "echo '${TOKEN}' > /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass"

echo ">>> Restarting manager to activate the token..."
dexec "/var/ossec/bin/wazuh-control restart"

echo ">>> Waiting for the Wazuh API to become reachable..."
PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli wait-for-api --timeout 120

echo ">>> Scheduling automatic revocation in ${EXPIRY_MINUTES} minutes..."
docker exec -d "$CONTAINER" bash -lc \
  "sleep $((EXPIRY_MINUTES * 60)) && head -c 24 /dev/urandom | base64 > /var/ossec/etc/authd.pass && /var/ossec/bin/wazuh-control restart"

echo ">>> Opening the port 1515 enrollment window for ${EXPIRY_MINUTES} minutes (same lifetime as the token)..."
if ! bash "$RADAR_ROOT/radar_deploy/manager-enrollment-window.sh" open --minutes "$EXPIRY_MINUTES"; then
  echo "NOTE: could not open the port 1515 window automatically (needs root/sudo)."
  echo "    Run manually: sudo ./radar.sh enrollment open --minutes ${EXPIRY_MINUTES}"
fi

echo ""
echo "=== Token minted, expires in ${EXPIRY_MINUTES} minutes ==="
echo "Run this on the target endpoint:"
echo ""
echo "  sudo ./bootstrap-agent.sh --manager ${MANAGER_ADDRESS} --token ${TOKEN} --group ${GROUP}"
echo ""
echo "Note: activating and revoking this token each restart the manager, briefly"
echo "disconnecting all currently-connected agents. This is a real cost of"
echo "short-lived tokens with Wazuh's built-in authd password mechanism, which"
echo "only re-reads its password file at process start -- not a bug in this script."
echo ""
echo "TOKEN_VALUE=${TOKEN}"