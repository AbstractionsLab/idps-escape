#!/usr/bin/env bash
# RADAR active response dispatcher.
#
# bootstrap-agent.sh installs one copy of this file per active response name
# (e.g. /var/ossec/active-response/bin/lock_user_linux.sh). When Wazuh runs
# it, it looks its own name up in /var/ossec/radar-agent/ar-scripts.yaml and
# execs the mapped script with the same stdin and arguments. Editing that
# mapping, or a script it points to, therefore takes effect on the next
# alert without re-running bootstrap-agent.sh.
#
# Nothing is executed unless the mapping, the library and the target script
# are owned by root and not writable by group or others.

set -uo pipefail

RADAR_AGENT_HOME="/var/ossec/radar-agent"
LOG_FILE="/var/ossec/logs/active-responses.log"
TRUSTED_UID=0

name="${0##*/}"
log() { echo "$(date) [ar-dispatch:${name}] $*" >> "$LOG_FILE"; }

# Checked here, before sourcing, because the library is what does the checks.
trusted() {
  local st
  st=$(stat -c '%u %a' -- "$1" 2>/dev/null) || return 1
  [[ "${st%% *}" == "$TRUSTED_UID" ]] && (( (8#${st##* } & 8#022) == 0 ))
}

lib="$RADAR_AGENT_HOME/helpers/ar-mapping.sh"
for p in "$RADAR_AGENT_HOME" "$RADAR_AGENT_HOME/helpers" "$lib"; do
  if [[ -L "$p" ]] || ! trusted "$p"; then
    log "refusing: $p is missing, a symlink, or writable by someone other than uid $TRUSTED_UID"
    exit 1
  fi
done

# shellcheck source-path=SCRIPTDIR source=ar-mapping.sh
source "$lib"

if ! target=$(ar_resolve_script "$RADAR_AGENT_HOME" "$name" "$TRUSTED_UID" 2>>"$LOG_FILE"); then
  log "refusing: no trusted script resolved for '$name'"
  exit 1
fi

log "dispatching to ${target#"$RADAR_AGENT_HOME"/}"
exec "$target" "$@"
