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
# --allow-service  (log_volume only) systemd service terminate_service.sh
#                may stop. Repeatable or comma-separated. Anything not listed
#                is refused; with none listed, no service can be stopped.
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
ALLOWED_SERVICES=()

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -23
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
    --allow-service)
      IFS=',' read -ra _services_split <<< "$2"
      ALLOWED_SERVICES+=("${_services_split[@]}")
      shift 2
      ;;
    --help|-h)     usage ;;
    *) echo "Unknown option: $1"; usage 2 ;;
  esac
done

[[ -n "$MANAGER" ]] || { echo "ERROR: --manager is required"; usage 2; }
[[ -n "$TOKEN" ]] || { echo "ERROR: --token is required"; usage 2; }
for _svc in "${ALLOWED_SERVICES[@]}"; do
  [[ "$_svc" =~ ^[A-Za-z0-9][A-Za-z0-9@._:-]*$ ]] \
    || { echo "ERROR: invalid --allow-service name: $_svc"; usage 2; }
done

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
elif grep -q "<server>" "$OSSEC_CONF"; then
  perl -0777 -i -pe "s|<server>\s*</server>|<server>\n      <address>${MANAGER}</address>\n      <port>1514</port>\n      <protocol>tcp</protocol>\n    </server>|" "$OSSEC_CONF"
  grep -q "<address>${MANAGER}</address>" "$OSSEC_CONF" \
    || fail "found an empty <server></server> block but could not insert an <address> into it" "check the <server> block manually"
else
  fail "no <server> block found in $OSSEC_CONF" "check the <client> block manually"
fi

echo ">>> Registering with manager $MANAGER..."
GROUPS_CSV=$(IFS=','; echo "${TARGET_GROUPS[*]}")
CLIENT_KEYS=/var/ossec/etc/client.keys
if ! /var/ossec/bin/agent-auth -m "$MANAGER" -P "$TOKEN" -A "$AGENT_NAME" -G "$GROUPS_CSV" 2>/tmp/agent-auth.err; then
  if grep -q "Duplicate agent name" /tmp/agent-auth.err; then
    if [[ -s "$CLIENT_KEYS" ]]; then
      echo "OK - agent name already registered, and $CLIENT_KEYS already has a key"
    else
      cat /tmp/agent-auth.err
      fail "manager has an entry for '$AGENT_NAME' but $CLIENT_KEYS is empty: this agent never actually received a key (likely interrupted by a manager restart mid-enrollment)" \
           "on the manager, deregister the agent and mint a fresh token and re-run this script"
    fi
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

if has_group "suspicious_login" || has_group "log_volume"; then
  if ! command -v jq >/dev/null 2>&1; then
    echo ">>> Installing jq (needed by the active response scripts)..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y -qq jq >/dev/null || true
    elif JQ_PKG_MGR=$(command -v dnf || command -v yum); then
      "$JQ_PKG_MGR" install -y jq >/dev/null || true
    fi
    command -v jq >/dev/null 2>&1 \
      || warn "jq is not installed; the active response scripts will refuse to act until it is"
  fi
fi

if has_group "suspicious_login"; then
  write_ar_script lock_user_linux.sh <<'AR_SCRIPT_EOF'
#!/usr/bin/env bash
# RADAR active response: lock (add) / unlock (delete) a local user account.
# The username comes from alert data, which is attacker-influenced (anyone
# who can produce failed logins picks the name), so it is validated here
# regardless of what the manager already filtered.

set -uo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
# Accounts below this UID (root, system and service accounts) are never touched.
MIN_UID=1000
# Optional extra accounts that must never be locked, one name per line.
PROTECTED_USERS_FILE="/var/ossec/etc/radar-protected-users"

log() { echo "$(date) [lock_user_linux] $*" >> "$LOG_FILE"; }

IFS= read -r wrapper_json || true
[[ -n "${wrapper_json:-}" ]] || exit 0

if ! command -v jq >/dev/null 2>&1; then
  log "jq not installed; refusing to act"
  exit 1
fi

action=$(jq -r '.command // empty' <<<"$wrapper_json" 2>/dev/null) || action=""
user=$(jq -r '.parameters.extra_args[0] | strings' <<<"$wrapper_json" 2>/dev/null) || user=""

case "$action" in
  add)    op="-L"; verb="Locked" ;;
  delete) op="-U"; verb="Unlocked" ;;
  *)
    log "refusing: unexpected command $(printf '%q' "$action")"
    exit 1
    ;;
esac

if [[ ! "$user" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,31}$ ]]; then
  log "refusing: invalid username $(printf '%q' "$user")"
  exit 1
fi

if ! entry=$(getent passwd "$user"); then
  log "refusing: no account named '$user'"
  exit 1
fi
uid=$(cut -d: -f3 <<<"$entry")
if [[ ! "$uid" =~ ^[0-9]+$ ]] || (( uid < MIN_UID || uid == 65534 )); then
  log "refusing: '$user' is a system account (uid $uid)"
  exit 1
fi

if [[ -f "$PROTECTED_USERS_FILE" ]] && grep -qxF -- "$user" "$PROTECTED_USERS_FILE"; then
  log "refusing: '$user' is listed in $PROTECTED_USERS_FILE"
  exit 1
fi

if usermod "$op" -- "$user" >> "$LOG_FILE" 2>&1; then
  log "$verb $user"
else
  log "usermod $op failed for $user"
  exit 1
fi

exit 0
AR_SCRIPT_EOF
fi

if has_group "log_volume"; then
  SERVICES_FILE=/var/ossec/etc/radar-terminable-services
  if [[ ${#ALLOWED_SERVICES[@]} -gt 0 ]]; then
    {
      echo "# Services terminate_service.sh may stop, one per line (written by bootstrap-agent.sh)."
      printf '%s\n' "${ALLOWED_SERVICES[@]}"
    } > "$SERVICES_FILE"
  elif [[ ! -f "$SERVICES_FILE" ]]; then
    echo "# Services terminate_service.sh may stop, one per line. Empty = none." > "$SERVICES_FILE"
  fi
  chown root:wazuh "$SERVICES_FILE"
  chmod 0640 "$SERVICES_FILE"
  if ! grep -qv '^[[:space:]]*\(#\|$\)' "$SERVICES_FILE"; then
    warn "no services listed in $SERVICES_FILE; terminate_service.sh can only kill connections to an IP (use --allow-service to allow stopping a service)"
  fi

  write_ar_script terminate_service.sh <<'AR_SCRIPT_EOF'
#!/usr/bin/env bash
# RADAR active response: stop an allowlisted service, or kill the processes
# holding TCP connections to a given IPv4 address. The target comes from
# alert data (e.g. a syslog program name any local user can forge), so it is
# validated here regardless of what the manager already filtered.

set -uo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
# Services this script may stop, one unit name per line ('#' comments ok).
# A missing or empty file means no service can be stopped.
ALLOWED_SERVICES_FILE="/var/ossec/etc/radar-terminable-services"
# Never stopped, even if listed in the allowlist.
NEVER_STOP_RE='^(wazuh-.*|ssh|sshd|systemd-.*|dbus|dbus-broker|auditd|rsyslog|syslog-ng|firewalld|ufw|nftables|iptables|netfilter-persistent|NetworkManager|networking|polkit)$'

log() { echo "$(date) [terminate_service] $*" >> "$LOG_FILE"; }

IFS= read -r wrapper_json || true
[[ -n "${wrapper_json:-}" ]] || exit 0

if ! command -v jq >/dev/null 2>&1; then
  log "jq not installed; refusing to act"
  exit 1
fi

action=$(jq -r '.command // empty' <<<"$wrapper_json" 2>/dev/null) || action=""
target=$(jq -r '.parameters.extra_args[0] | strings' <<<"$wrapper_json" 2>/dev/null) || target=""

# Stopping a service or killing processes is one-shot: the timeout 'delete'
# must not repeat it.
[[ "$action" == "delete" ]] && exit 0
if [[ "$action" != "add" ]]; then
  log "refusing: unexpected command $(printf '%q' "$action")"
  exit 1
fi
if [[ -z "$target" ]]; then
  log "refusing: no target in extra_args"
  exit 1
fi

is_ipv4() {
  local ip="$1" o octets
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -ra octets <<<"$ip"
  for o in "${octets[@]}"; do
    (( 10#$o <= 255 )) || return 1
  done
}

stop_service() {
  local name="${1%.service}"
  if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9@._:-]*$ ]]; then
    log "refusing: invalid service name $(printf '%q' "$1")"
    return 1
  fi
  if [[ "$name" =~ $NEVER_STOP_RE ]]; then
    log "refusing: '$name' is a protected service"
    return 1
  fi
  if [[ ! -f "$ALLOWED_SERVICES_FILE" ]] \
     || ! sed 's/#.*//; s/[[:space:]]//g; s/\.service$//' "$ALLOWED_SERVICES_FILE" | grep -qxF -- "$name"; then
    log "refusing: '$name' is not listed in $ALLOWED_SERVICES_FILE"
    return 1
  fi

  log "stopping service $name"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop -- "${name}.service" >> "$LOG_FILE" 2>&1
  elif command -v service >/dev/null 2>&1; then
    service "$name" stop >> "$LOG_FILE" 2>&1
  else
    log "no supported service manager found"
    return 1
  fi
}

kill_connections() {
  local ip="$1" pid comm pids killed=0
  case "$ip" in
    0.*|127.*|255.255.255.255)
      log "refusing: $ip is not a remote address"
      return 1
      ;;
  esac
  if ! command -v ss >/dev/null 2>&1; then
    log "ss not installed; cannot find connections to $ip"
    return 1
  fi

  # 'dst' matches the exact remote address, unlike grepping the ss output.
  pids=$(ss -Htnp dst "$ip" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -un)
  for pid in $pids; do
    (( pid > 1 && pid != $$ && pid != PPID )) || continue
    comm=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
    if [[ "$comm" == wazuh-* ]]; then
      log "skipping $comm (pid $pid): never kill the agent"
      continue
    fi
    if kill -9 "$pid" 2>/dev/null; then
      log "killed pid $pid ($comm) connected to $ip"
      killed=$((killed + 1))
    fi
  done
  (( killed > 0 )) || log "no processes to kill for $ip"
  return 0
}

if is_ipv4 "$target"; then
  kill_connections "$target"
else
  stop_service "$target"
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