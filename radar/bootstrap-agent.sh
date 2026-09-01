#!/usr/bin/env bash
# Usage:
#   bootstrap-agent.sh --manager <address> --token <secret> --group <group-name> [--agent-name <name>]
#
# --manager      Wazuh manager address (host or IP) the agent should enroll to
# --token        Enrollment password (matches the manager's authd shared
#                password -- mint one with `python3 -m wazuh_api.cli
#                mint-enrollment-token` on the manager)
# --group        Wazuh group to assign this agent to. Repeat for multiple
#                groups, e.g. --group default --group suspicious_login
# --agent-name   Name to register as (defaults to this host's hostname)
# --version      Agent package version to install. Defaults to
#                WAZUH_AGENT_VERSION if set in the environment, else 4.14.1-1
#
# After install, this script pins wazuh-agent to the installed version and
# disables automatic updates for it (apt-mark hold / yum|dnf versionlock),
# per Wazuh's own recommendation -- otherwise a routine, unrelated fleet-wide
# OS package update can silently bump the agent version on this endpoint.
# Note: since the install step above is skipped entirely when the agent is
# already present, re-running this script with a different --version will
# NOT move an already-enrolled endpoint to that version -- deliberately
# upgrading a pinned agent is a separate, explicit action (unhold/versionlock
# delete, install the target version, re-hold/versionlock), not this script.

set -Eeuo pipefail

AGENT_NAME="$(hostname)"
MANAGER=""
TOKEN=""
AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.14.1-1}"
TARGET_GROUPS=()

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -20
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager)     MANAGER="$2";        shift 2 ;;
    --token)       TOKEN="$2";          shift 2 ;;
    --group)
      IFS=',' read -ra _groups_split <<< "$2"
      TARGET_GROUPS+=("${_groups_split[@]}")
      shift 2
      ;;
    --agent-name)  AGENT_NAME="$2";     shift 2 ;;
    --version)     AGENT_VERSION="$2";  shift 2 ;;
    --help|-h)     usage ;;
    *) echo "Unknown option: $1"; usage 2 ;;
  esac
done

[[ -n "$MANAGER" ]] || { echo "ERROR: --manager is required"; usage 2; }
[[ -n "$TOKEN" ]] || { echo "ERROR: --token is required"; usage 2; }

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run this as root"; exit 1
fi

fail() {
  echo "FAILED: $1" >&2
  echo "Next step: $2" >&2
  exit 1
}

echo "=== bootstrap-agent.sh ==="
echo "Manager  : $MANAGER"
echo "Groups   : ${TARGET_GROUPS[*]}"
echo "Name     : $AGENT_NAME"
echo "Version  : $AGENT_VERSION"
echo "==========================="

if [[ ! -x /var/ossec/bin/agent-auth ]]; then
  echo ">>> Installing Wazuh agent package..."
  if command -v apt-get >/dev/null 2>&1; then
    KEYRING=/usr/share/keyrings/wazuh.gpg
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor --yes -o "$KEYRING" \
      || fail "could not import Wazuh GPG key check network access to packages.wazuh.com"
    chmod 644 "$KEYRING"
    echo "deb [signed-by=$KEYRING] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq || fail "apt-get update failed" "check network access and apt sources"
    WAZUH_MANAGER="$MANAGER" apt-get install -y "wazuh-agent=${AGENT_VERSION}" \
      || fail "package install failed for wazuh-agent=${AGENT_VERSION}" \
              "confirm this version exists: apt-cache madison wazuh-agent"
  elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    PKG_MGR=$(command -v dnf || command -v yum)
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      || fail "could not import Wazuh GPG key check network access to packages.wazuh.com"
    cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    WAZUH_MANAGER="$MANAGER" "$PKG_MGR" install -y "wazuh-agent-${AGENT_VERSION}" \
      || fail "package install failed for wazuh-agent-${AGENT_VERSION}" \
              "confirm this version exists: ${PKG_MGR} --showduplicates list wazuh-agent"
  else
    fail "no supported package manager found (need apt-get, yum, or dnf)" \
         "install the Wazuh agent manually, then re-run this script"
  fi
  echo "OK - package installed"
else
  echo "OK - Wazuh agent already installed, skipping package install"
fi

warn() {
  echo "WARNING: $1" >&2
}

echo ">>> Pinning wazuh-agent to ${AGENT_VERSION} and disabling automatic updates..."
if command -v apt-get >/dev/null 2>&1; then
  if apt-mark hold wazuh-agent >/dev/null; then
    echo "OK - wazuh-agent held (apt-mark hold); 'apt upgrade' will not touch it"
  else
    warn "'apt-mark hold wazuh-agent' failed on agent. Run 'apt-mark hold wazuh-agent' manually."
  fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PIN_PKG_MGR=$(command -v dnf || command -v yum)
  "$PIN_PKG_MGR" install -y 'dnf-command(versionlock)' >/dev/null 2>&1 || true
  "$PIN_PKG_MGR" install -y dnf-plugin-versionlock >/dev/null 2>&1 || true
  "$PIN_PKG_MGR" install -y yum-plugin-versionlock >/dev/null 2>&1 || true
  if "$PIN_PKG_MGR" versionlock add wazuh-agent >/dev/null 2>&1; then
    echo "OK - wazuh-agent version-locked (${PIN_PKG_MGR} versionlock); a fleet-wide update will not touch it"
  else
    warn "'${PIN_PKG_MGR} versionlock add wazuh-agent' failed"
  fi
else
  warn "no supported package manager found to pin wazuh-agent"
fi

echo ">>> Setting manager address in ossec.conf..."
OSSEC_CONF=/var/ossec/etc/ossec.conf
if grep -q "<address>" "$OSSEC_CONF"; then
  sed -i "s|<address>[^<]*</address>|<address>${MANAGER}</address>|" "$OSSEC_CONF"
else
  fail "no <address> tag found in $OSSEC_CONF" "check the <server> block manually"
fi

echo ">>> Registering with manager $MANAGER..."
GROUPS_CSV=$(IFS=','; echo "${TARGET_GROUPS[*]}")
if ! /var/ossec/bin/agent-auth -m "$MANAGER" -P "$TOKEN" -A "$AGENT_NAME" -G "$GROUPS_CSV" 2>/tmp/agent-auth.err; then
  if grep -q "Duplicate agent name" /tmp/agent-auth.err; then
    echo "OK - agent name already registered"
  elif grep -qi "Invalid password\|Unable to connect" /tmp/agent-auth.err; then
    cat /tmp/agent-auth.err
    fail "enrollment rejected by manager" \
           "check the token is correct and not expired, and that $MANAGER:1515 is reachable"
  else
    cat /tmp/agent-auth.err
    fail "agent-auth failed" "see error above"
  fi
fi

if [[ ",$GROUPS_CSV," == *",log_volume,"* ]]; then
  echo ">>> Installing local log-volume metric collector (systemd timer)..."
  mkdir -p /var/log/radar
  chmod 0755 /var/log/radar

  cat > /usr/local/bin/radar-log-volume-metric.sh << 'METRIC_SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/radar/log_volume_metric.log"
BYTES=$(du -sb /var/log 2>/dev/null | awk '{print $1}')
printf '%s %s log_volume_metric: /var/log %s\n' \
  "$(date '+%b %d %H:%M:%S')" "$(hostname)" "${BYTES:-0}" >> "$LOG_FILE"
METRIC_SCRIPT_EOF
  chown root:root /usr/local/bin/radar-log-volume-metric.sh
  chmod 0750 /usr/local/bin/radar-log-volume-metric.sh

  cat > /etc/systemd/system/radar-log-volume.service << 'SERVICE_EOF'
[Unit]
Description=RADAR log_volume metric collector

[Service]
Type=oneshot
ExecStart=/usr/local/bin/radar-log-volume-metric.sh
SERVICE_EOF

  cat > /etc/systemd/system/radar-log-volume.timer << 'TIMER_EOF'
[Unit]
Description=Run the RADAR log_volume metric collector every 30 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Unit=radar-log-volume.service

[Install]
WantedBy=timers.target
TIMER_EOF

  chown root:root /etc/systemd/system/radar-log-volume.service /etc/systemd/system/radar-log-volume.timer
  chmod 0644 /etc/systemd/system/radar-log-volume.service /etc/systemd/system/radar-log-volume.timer

  cat > /etc/logrotate.d/radar-log-volume << 'LOGROTATE_EOF'
/var/log/radar/log_volume_metric.log {
  daily
  rotate 7
  compress
  missingok
  notifempty
  copytruncate
}
LOGROTATE_EOF

  systemctl daemon-reload
  systemctl enable --now radar-log-volume.timer
  echo "OK - installed and started radar-log-volume.timer"
fi

echo ">>> Enabling and starting the Wazuh agent service..."
systemctl enable wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent \
  || fail "wazuh-agent service failed to start" "check: journalctl -u wazuh-agent -n 50"

echo ">>> Installing active response scripts..."
mkdir -p /var/ossec/active-response/bin
chown root:wazuh /var/ossec/active-response/bin
chmod 0755 /var/ossec/active-response/bin

write_ar_script() {
  local name="$1"
  cat > "/var/ossec/active-response/bin/${name}"
  chown root:wazuh "/var/ossec/active-response/bin/${name}"
  chmod 0750 "/var/ossec/active-response/bin/${name}"
  echo "OK - installed ${name}"
}

has_group() {
  local needle="$1"
  for g in "${TARGET_GROUPS[@]}"; do
    [[ "$g" == "$needle" ]] && return 0
  done
  return 1
}

if has_group "suspicious_login"; then
  write_ar_script lock_user_linux.sh <<'AR_SCRIPT_EOF'
#!/usr/bin/bash

LOG_FILE="/var/ossec/logs/active-responses.log"

IFS= read -r wrapper_json

if [[ -z "$wrapper_json" ]]; then
  exit 0
fi

action=$(jq -r '.command' <<<"$wrapper_json")
user=$(jq -r '.parameters.extra_args[0]' <<<"$wrapper_json")

if [[ "$action" == "add" ]]; then
  usermod -L "$user"
  echo "$(date) [lock_user_linux] Locked $user" >> "$LOG_FILE"
else
  usermod -U "$user"
  echo "$(date) [lock_user_linux] Unlocked $user" >> "$LOG_FILE"
fi

exit 0
AR_SCRIPT_EOF
fi

if has_group "log_volume"; then
  write_ar_script terminate_service.sh <<'AR_SCRIPT_EOF'
#!/bin/bash

LOG_FILE="/var/ossec/logs/active-responses.log"

IFS= read -r wrapper_json
echo "$(date) [terminate_c2] $wrapper_json" >> "$LOG_FILE"

if [[ -z "$wrapper_json" ]]; then
    exit 0
fi

if command -v jq >/dev/null 2>&1; then
    C2_IP=$(echo "$wrapper_json" | jq -r '.parameters.extra_args[0]')
else
    C2_IP=$(echo "$wrapper_json" | grep -oP '"extra_args":\["\K[^"]+')
fi

if [[ -z "$C2_IP" ]]; then
    echo "$(date) [terminate_c2] No destination IP/service provided in extra_args." >> "$LOG_FILE"
    exit 1
fi

is_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r a b c d <<<"$ip"
    [[ "$a" -le 255 && "$b" -le 255 && "$c" -le 255 && "$d" -le 255 ]]
}

if ! is_ipv4 "$C2_IP"; then
    echo "$(date) [terminate_c2] Treating target as service '$C2_IP'" >> "$LOG_FILE"

    SVC_NAME="${C2_IP%.service}"
    if command -v systemctl >/dev/null 2>&1; then
        UNIT="$C2_IP"
        [[ "$UNIT" != *.service ]] && UNIT="${SVC_NAME}.service"
        echo "$(date) [terminate_c2] systemctl stop $UNIT" >> "$LOG_FILE"
        systemctl stop "$UNIT" >> "$LOG_FILE" 2>&1
        exit $?
    fi
    if command -v service >/dev/null 2>&1; then
        echo "$(date) [terminate_c2] service $SVC_NAME stop" >> "$LOG_FILE"
        service "$SVC_NAME" stop >> "$LOG_FILE" 2>&1
        exit $?
    fi
    if [[ -x "/etc/init.d/$SVC_NAME" ]]; then
        echo "$(date) [terminate_c2] /etc/init.d/$SVC_NAME stop" >> "$LOG_FILE"
        "/etc/init.d/$SVC_NAME" stop >> "$LOG_FILE" 2>&1
        exit $?
    fi
    echo "$(date) [terminate_c2] No supported service manager found for '$C2_IP'" >> "$LOG_FILE"
    exit 1
else
    echo "$(date) [terminate_c2] Terminating connections to $C2_IP" >> "$LOG_FILE"
    PIDS=$(ss -ntp | grep "$C2_IP" | awk -F',' '{print $2}' | awk '{print $1}' | sort -u)

    if [[ -z "$PIDS" ]]; then
        echo "$(date) [terminate_c2] No processes found for $C2_IP" >> "$LOG_FILE"
        exit 0
    fi

    for PID in $PIDS; do
        if [[ "$PID" =~ ^[0-9]+$ ]]; then
            kill -9 "$PID"
            echo "$(date) [terminate_c2] Terminated PID $PID for connection to $C2_IP" >> "$LOG_FILE"
        fi
    done
    exit 0
fi
AR_SCRIPT_EOF
fi

if ! has_group "suspicious_login" && ! has_group "log_volume"; then
  echo "OK - no active response script needed for these groups"
fi

REAL_ID=$(awk '{print $1; exit}' /var/ossec/etc/client.keys 2>/dev/null || true)
REAL_NAME=$(awk '{print $2; exit}' /var/ossec/etc/client.keys 2>/dev/null || true)
REAL_NAME="${REAL_NAME:-$AGENT_NAME}"

if systemctl is-active --quiet wazuh-agent; then
  echo "=== SUCCESS ==="
else
  fail "service did not reach the active state" "check: journalctl -u wazuh-agent -n 50"
fi