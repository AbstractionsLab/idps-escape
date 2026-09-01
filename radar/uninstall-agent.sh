#!/usr/bin/env bash
# uninstall-agent.sh
#
# Fully removes the Wazuh agent from this endpoint.
#
# Usage:
#   sudo ./uninstall-agent.sh [--purge-data]
#
# --purge-data also removes /var/ossec entirely (logs, enrollment state,
# active-response scripts).

set -Eeuo pipefail

PURGE_DATA=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-data)  PURGE_DATA=true; shift ;;
    --help|-h)
      grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -20
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo ./uninstall-agent.sh)" >&2
  exit 1
fi

echo "=== uninstall-agent.sh ==="

if command -v systemctl >/dev/null 2>&1; then
  echo ">>> Stopping and disabling the wazuh-agent service..."
  systemctl stop wazuh-agent >/dev/null 2>&1 || true
  systemctl disable wazuh-agent >/dev/null 2>&1 || true
fi

if [[ -f /etc/systemd/system/radar-log-volume.timer ]]; then
  echo ">>> Removing the RADAR log_volume metric collector..."
  systemctl stop radar-log-volume.timer >/dev/null 2>&1 || true
  systemctl disable radar-log-volume.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/radar-log-volume.timer /etc/systemd/system/radar-log-volume.service
  rm -f /usr/local/bin/radar-log-volume-metric.sh
  rm -f /etc/logrotate.d/radar-log-volume
  systemctl daemon-reload
  if [[ "$PURGE_DATA" == "true" ]]; then
    rm -rf /var/log/radar
  fi
fi

if command -v apt-get >/dev/null 2>&1; then
  echo ">>> Removing wazuh-agent package (apt)..."
  apt-mark unhold wazuh-agent >/dev/null 2>&1 || true
  apt-get remove -y --purge wazuh-agent >/dev/null 2>&1 || true
  rm -f /etc/apt/sources.list.d/wazuh.list
  rm -f /usr/share/keyrings/wazuh.gpg
  apt-get update -qq || true

elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PKG_MGR=$(command -v dnf || command -v yum)
  echo ">>> Removing wazuh-agent package (${PKG_MGR})..."
  "$PKG_MGR" versionlock delete wazuh-agent >/dev/null 2>&1 || true
  "$PKG_MGR" remove -y wazuh-agent >/dev/null 2>&1 || true
  rm -f /etc/yum.repos.d/wazuh.repo

else
  echo "WARNING: no supported package manager found (apt-get/yum/dnf)." >&2
  echo "The wazuh-agent package was not removed -- remove it manually for your distro." >&2
fi

if [[ "$PURGE_DATA" == "true" ]]; then
  echo ">>> Removing /var/ossec (--purge-data)..."
  rm -rf /var/ossec
else
  if [[ -d /var/ossec ]]; then
    echo "NOTE: /var/ossec still exists (config/logs may remain)."
    echo "      Re-run with --purge-data to remove it entirely."
  fi
fi

echo ""
echo "=== Uninstall complete ==="
if command -v systemctl >/dev/null 2>&1; then
  systemctl status wazuh-agent >/dev/null 2>&1 && echo "WARNING: wazuh-agent service still registered with systemd." || echo "Confirmed: wazuh-agent service no longer registered."
fi