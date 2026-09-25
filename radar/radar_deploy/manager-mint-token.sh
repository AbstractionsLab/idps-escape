#!/usr/bin/env bash
set -Eeuo pipefail

GROUP="${1:?Usage: manager-mint-token.sh <group>[,<group>...] [expiry_minutes] [manager_address]}"
EXPIRY_MINUTES="${2:-60}"
RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! "$EXPIRY_MINUTES" =~ ^[1-9][0-9]{0,3}$ ]] || (( EXPIRY_MINUTES > 1440 )); then
  echo "ERROR: expiry_minutes must be an integer between 1 and 1440 (got '$EXPIRY_MINUTES')" >&2
  exit 2
fi

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
radar_load_env "$RADAR_ROOT"
CONTAINER="$(radar_manager_container "$RADAR_ROOT")"

MANAGER_ADDRESS="${3:-$(detect_manager_address)}"

TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '=+/' | head -c 32)

echo ">>> Ensuring the manager accepts password-based enrollment..."
PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli ensure-password-auth || \
  echo "NOTE: could not confirm/set <use_password>yes</use_password> via the API -- if enrollment below" \
       "fails with 'Invalid request for new agent', check this manager's <auth> block manually."

echo ">>> Setting enrollment token (expires in ${EXPIRY_MINUTES}m)..."
printf '%s\n' "$TOKEN" | docker exec -i -u root "$CONTAINER" sh -c \
  'cat > /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass'

STATE_DIR="$RADAR_ROOT/.radar-state"
mkdir -p "$STATE_DIR"
[[ -f "$STATE_DIR/.gitignore" ]] || echo '*' > "$STATE_DIR/.gitignore"
chmod 0700 "$STATE_DIR"
EXPIRES_AT=$(( $(date +%s) + EXPIRY_MINUTES * 60 ))
echo "$EXPIRES_AT $CONTAINER" > "$STATE_DIR/enrollment-token.expires"
chmod 0600 "$STATE_DIR/enrollment-token.expires"
if [[ $EUID -eq 0 ]]; then
  chown --reference="$RADAR_ROOT" "$STATE_DIR" "$STATE_DIR/.gitignore" "$STATE_DIR/enrollment-token.expires" 2>/dev/null || true
fi

echo ">>> Restarting manager to activate the token..."
dexec "/var/ossec/bin/wazuh-control restart"

echo ">>> Waiting for the Wazuh API to become reachable..."
PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli wait-for-api --timeout 120

echo ">>> Scheduling automatic revocation in ${EXPIRY_MINUTES} minutes (on the host)..."
REVOKE=("$RADAR_ROOT/radar_deploy/manager-revoke-token.sh" --if-expired)
if [[ $EUID -eq 0 ]] && command -v systemd-run >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl stop radar-token-revoke.timer radar-token-revoke.service >/dev/null 2>&1 || true
  systemctl reset-failed radar-token-revoke.timer radar-token-revoke.service >/dev/null 2>&1 || true
  systemd-run --quiet --unit=radar-token-revoke --on-active="${EXPIRY_MINUTES}m" \
    --timer-property=AccuracySec=10s /bin/bash "${REVOKE[@]}"
  echo "OK - systemd timer radar-token-revoke scheduled"
else
  PID_FILE="$STATE_DIR/revoke-timer.pid"
  if [[ -f "$PID_FILE" ]]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
  fi
  nohup bash -c 'sleep "$1"; exec bash "${@:2}"' _ "$(( EXPIRY_MINUTES * 60 + 5 ))" "${REVOKE[@]}" \
    >> "$STATE_DIR/revoke-timer.log" 2>&1 &
  echo $! > "$PID_FILE"
  disown || true
  echo "OK - background revocation timer started (no systemd/root: it does not survive a"
  echo "     host reboot, but manager-health.sh and build-radar.sh revoke an expired token)"
fi

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
echo "MANAGER_ADDRESS_VALUE=${MANAGER_ADDRESS}"