#!/bin/sh
set -e

if [ -s /var/ossec/etc/client.keys ]; then
  echo ">>> Already enrolled (client.keys present); skipping agent-auth."
else
  if [ -z "${WAZUH_REGISTRATION_TOKEN:-}" ]; then
    echo "ERROR: not yet enrolled, and WAZUH_REGISTRATION_TOKEN is not set." >&2
    echo "This is normally minted automatically by build-radar.sh or the GUI right" >&2
    echo "before this container starts." >&2
    exit 1
  fi
  AGENT_NAME="${WEBHOOK_AGENT_NAME:-ad-webhook}"
  case "$AGENT_NAME" in
    ''|*[!A-Za-z0-9._-]*) echo "ERROR: WEBHOOK_AGENT_NAME must match [A-Za-z0-9._-]+" >&2; exit 1 ;;
  esac
  echo ">>> Not yet enrolled; enrolling with the manager as '${AGENT_NAME}'..."
  /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER_ADDRESS}" -p 1515 -P "${WAZUH_REGISTRATION_TOKEN}" -A "${AGENT_NAME}"
fi

/var/ossec/bin/wazuh-control start
PORT="${WEBHOOK_INTERNAL_PORT:-8080}"
case "$PORT" in
  ''|*[!0-9]*) echo "ERROR: WEBHOOK_INTERNAL_PORT must be a number (got '$PORT')." >&2; exit 1 ;;
esac

exec su -s /bin/sh appuser -c "cd /app && exec python3 -m gunicorn --bind 0.0.0.0:$PORT \
  --workers 1 --threads 4 --timeout 30 --limit-request-line 4096 ad_alerts_webhook:app"