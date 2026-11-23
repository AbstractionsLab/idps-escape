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
