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
  echo ">>> Not yet enrolled; enrolling with the manager as 'ad-webhook'..."
  /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER_ADDRESS}" -p 1515 -P "${WAZUH_REGISTRATION_TOKEN}" -A ad-webhook
fi

/var/ossec/bin/wazuh-control start
exec su -s /bin/sh appuser -c 'python3 /app/ad_alerts_webhook.py'