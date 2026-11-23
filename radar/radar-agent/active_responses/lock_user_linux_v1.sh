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
