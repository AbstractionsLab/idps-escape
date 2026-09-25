#!/usr/bin/env bash

set -Eeuo pipefail

RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
STATE_FILE="$RADAR_ROOT/.radar-state/enrollment-token.expires"

if [[ "${1:-}" == "--if-expired" ]]; then
  [[ -f "$STATE_FILE" ]] || exit 0
  read -r expires_at container < "$STATE_FILE" || true
  if [[ ! "${expires_at:-}" =~ ^[0-9]+$ ]]; then
    echo "WARN - unreadable $STATE_FILE; revoking to be safe"
  elif (( $(date +%s) < expires_at )); then
    exit 0
  else
    echo "WARN - enrollment token expired at $(date -d "@$expires_at" 2>/dev/null || echo "$expires_at") and was still active; revoking now"
  fi
fi

CONTAINER="${container:-}"
if [[ ! "$CONTAINER" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  CONTAINER="$(radar_manager_container "$RADAR_ROOT")"
fi

head -c 48 /dev/urandom | base64 | tr -d '=+/\n' | head -c 48 \
  | docker exec -i -u root "$CONTAINER" sh -c \
      'cat > /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass'
docker exec -u root "$CONTAINER" /var/ossec/bin/wazuh-control restart >/dev/null
rm -f "$STATE_FILE"
echo "OK - enrollment token revoked on $CONTAINER"
