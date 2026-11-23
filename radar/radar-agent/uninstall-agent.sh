#!/usr/bin/env bash
# uninstall-agent.sh
#
# Fully removes the Wazuh agent from this endpoint.
#
# Usage:
#   sudo ./uninstall-agent.sh [--purge-data]
#
# Run it from inside the radar-agent folder, like bootstrap-agent.sh.
#
# Removes the RADAR collectors this folder ships (collectors/<group>/), the
# RADAR active response dispatchers and /var/ossec/radar-agent, then the
# Wazuh agent package.
#
# --purge-data also removes /var/ossec entirely (logs, enrollment state,
# active-response scripts), the collected metrics in /var/log/radar and the
# kept agent key: use it when the endpoint leaves RADAR for good.

set -Eeuo pipefail

PURGE_DATA=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-data)  PURGE_DATA=true; shift ;;
    --help|-h)
      awk 'NR == 1 { next } /^#/ { sub(/^#/, ""); sub(/^  ?/, ""); print; next } { exit }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo ./uninstall-agent.sh)" >&2
  exit 1
fi

die() {
  echo "ERROR: $1" >&2
  echo "=== Uninstall NOT complete ===" >&2
  exit 1
}

RADAR_AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTORS_LIB="$RADAR_AGENT_DIR/helpers/collectors.sh"
AR_BIN=/var/ossec/active-response/bin
KEY_BACKUP_DIR=/var/lib/radar-agent
AR_DISPATCHER_MARKER="# RADAR active response dispatcher."

# Checked before anything is removed, so a partial copy of the folder never
# leaves the endpoint half uninstalled.
[[ -f "$COLLECTORS_LIB" ]] \
  || die "$COLLECTORS_LIB not found -- run uninstall-agent.sh from inside the full radar-agent folder"
# shellcheck source-path=SCRIPTDIR source=helpers/collectors.sh
source "$COLLECTORS_LIB"

dpkg_registered() {
  local s
  s=$(dpkg-query -W -f='${db:Status-Status}' wazuh-agent 2>/dev/null) || return 1
  [[ -n "$s" && "$s" != "not-installed" ]]
}

echo "=== uninstall-agent.sh ==="

if command -v systemctl >/dev/null 2>&1; then
  echo ">>> Stopping and disabling the wazuh-agent service..."
  systemctl stop wazuh-agent >/dev/null 2>&1 || true
  systemctl disable wazuh-agent >/dev/null 2>&1 || true
fi

for COLLECTOR in "$RADAR_AGENT_DIR/$COLLECTORS_DIR_NAME"/*/; do
  [[ -d "$COLLECTOR" ]] || continue
  COLLECTOR="${COLLECTOR%/}"
  REMOVED=$(collector_uninstall "$COLLECTOR")
  if [[ "$REMOVED" -gt 0 ]]; then
    echo "OK - removed the ${COLLECTOR##*/} metric collector (${REMOVED} files)"
  fi
done
if [[ "$PURGE_DATA" == "true" && -d "$COLLECTOR_LOG_DIR" ]]; then
  rm -rf "$COLLECTOR_LOG_DIR"
  echo "OK - removed $COLLECTOR_LOG_DIR (--purge-data)"
fi

echo ">>> Removing RADAR active response files..."
if [[ -d "$AR_BIN" ]]; then
  for AR_FILE in "$AR_BIN"/*; do
    [[ -f "$AR_FILE" ]] || continue
    grep -qxF "$AR_DISPATCHER_MARKER" "$AR_FILE" 2>/dev/null || continue
    rm -f "$AR_FILE"
    echo "OK - removed ${AR_FILE##*/}"
  done
fi
rm -rf /var/ossec/radar-agent /var/ossec/radar-agent.new
rm -f /var/ossec/etc/radar-terminable-services

KEY_KEPT=false
rm -rf "$KEY_BACKUP_DIR"
if [[ "$PURGE_DATA" != "true" && -s /var/ossec/etc/client.keys ]]; then
  install -d -o root -g root -m 0700 "$KEY_BACKUP_DIR"
  install -o root -g root -m 0600 /var/ossec/etc/client.keys "$KEY_BACKUP_DIR/client.keys"
  sed -n 's|.*<address>\([^<]*\)</address>.*|\1|p' /var/ossec/etc/ossec.conf 2>/dev/null | head -1 \
    > "$KEY_BACKUP_DIR/manager"
  chmod 0600 "$KEY_BACKUP_DIR/manager"
  KEY_KEPT=true
  echo "OK - kept this endpoint's agent key in $KEY_BACKUP_DIR (removed by --purge-data)"
fi

if command -v apt-get >/dev/null 2>&1; then
  echo ">>> Removing wazuh-agent package (apt, waits up to 120 s if dpkg is locked)..."
  if dpkg_registered; then
    apt-get -qq -o DPkg::Lock::Timeout=120 remove -y --purge --allow-change-held-packages wazuh-agent \
      || die "apt-get remove failed; /var/ossec left in place"
  fi
  if dpkg_registered; then
    die "wazuh-agent still registered in dpkg; /var/ossec left in place"
  fi
  rm -f /etc/apt/sources.list.d/wazuh.list
  rm -f /usr/share/keyrings/wazuh.gpg
  apt-get update -qq || true

elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PKG_MGR=$(command -v dnf || command -v yum)
  echo ">>> Removing wazuh-agent package (${PKG_MGR})..."
  "$PKG_MGR" versionlock delete wazuh-agent >/dev/null 2>&1 || true
  if rpm -q wazuh-agent >/dev/null 2>&1; then
    "$PKG_MGR" remove -y wazuh-agent \
      || die "${PKG_MGR} remove failed; /var/ossec left in place"
  fi
  if rpm -q wazuh-agent >/dev/null 2>&1; then
    die "wazuh-agent still installed according to rpm; /var/ossec left in place"
  fi
  rm -f /etc/yum.repos.d/wazuh.repo

else
  die "no supported package manager found (apt-get/yum/dnf); wazuh-agent was not removed -- remove it manually for your distro"
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
if [[ "$KEY_KEPT" == "true" ]]; then
  echo "NOTE: re-running bootstrap-agent.sh reconnects this endpoint as the same agent."
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl status wazuh-agent >/dev/null 2>&1 && echo "WARNING: wazuh-agent service still registered with systemd." || echo "Confirmed: wazuh-agent service no longer registered."
fi