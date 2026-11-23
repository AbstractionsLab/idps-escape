#!/usr/bin/env bash
# RADAR agent: local metric collectors (collectors/<group>/).
#
# Sourced by bootstrap-agent.sh and uninstall-agent.sh. A collector is a
# folder named after the scenario (Wazuh group) that needs it. Each file in it
# is installed under its own name, and its extension says where:
#
#   radar-<name>.sh         -> /usr/local/bin/              root:root 0750
#   radar-<name>.service    -> /etc/systemd/system/         root:root 0644
#   radar-<name>.timer      -> /etc/systemd/system/         root:root 0644 (enabled and started)
#   radar-<name>.logrotate  -> /etc/logrotate.d/radar-<name> root:root 0644
#
# Every file name must start with "radar-", so a collector can never replace
# a system unit or binary. Functions print errors on stderr and return
# non-zero on failure; they never exit the calling shell.

COLLECTORS_DIR_NAME="collectors"
COLLECTOR_BIN_DIR="/usr/local/bin"
COLLECTOR_UNIT_DIR="/etc/systemd/system"
COLLECTOR_LOGROTATE_DIR="/etc/logrotate.d"
COLLECTOR_LOG_DIR="/var/log/radar"

_collector_err() { echo "collectors: $*" >&2; }

# collector_dest <file name>
# Prints the installed path for a collector file, or fails for a name or
# extension that is not allowed.
collector_dest() {
  local f="$1"
  [[ "$f" =~ ^radar-[a-z0-9][a-z0-9-]*\.(sh|service|timer|logrotate)$ ]] || return 1
  case "$f" in
    *.sh)                printf '%s\n' "$COLLECTOR_BIN_DIR/$f" ;;
    *.service|*.timer)   printf '%s\n' "$COLLECTOR_UNIT_DIR/$f" ;;
    *.logrotate)         printf '%s\n' "$COLLECTOR_LOGROTATE_DIR/${f%.logrotate}" ;;
  esac
}

# collector_dir <agent dir> <group>
# Prints the collector folder for a group, or nothing if the group has none.
collector_dir() {
  local d="$1/$COLLECTORS_DIR_NAME/$2"
  [[ "$2" =~ ^[A-Za-z0-9_-]+$ && -d "$d" ]] && printf '%s\n' "$d"
  return 0
}

# collector_validate <collector dir>
# A collector must contain only allowed files (no subfolders, no symlinks)
# and at least one timer, so it actually runs.
collector_validate() {
  local dir="$1" path f timers=0 any=0
  for path in "$dir"/* "$dir"/.[!.]*; do
    [[ -e "$path" || -L "$path" ]] || continue
    f="${path##*/}"
    any=1
    if [[ -L "$path" || ! -f "$path" ]]; then
      _collector_err "$dir: '$f' must be a regular file"
      return 1
    fi
    if ! collector_dest "$f" >/dev/null; then
      _collector_err "$dir: '$f' is not allowed (expected radar-<name>.sh|.service|.timer|.logrotate)"
      return 1
    fi
    [[ "$f" == *.timer ]] && timers=$((timers + 1))
  done
  (( any )) || { _collector_err "$dir is empty"; return 1; }
  (( timers > 0 )) || { _collector_err "$dir has no .timer, so it would never run"; return 1; }
}

# collector_install <collector dir>
# Copies every file to its destination with fixed ownership and modes, then
# reloads systemd and enables and starts every timer. Re-running is safe.
collector_install() {
  local dir="$1" path f dest
  local -a timers=()
  collector_validate "$dir" || return 1
  mkdir -p "$COLLECTOR_LOG_DIR"
  chmod 0755 "$COLLECTOR_LOG_DIR"
  for path in "$dir"/*; do
    f="${path##*/}"
    dest=$(collector_dest "$f") || return 1
    case "$f" in
      *.sh)    install -o root -g root -m 0750 "$path" "$dest" ;;
      *.timer) install -o root -g root -m 0644 "$path" "$dest"; timers+=("$f") ;;
      *)       install -o root -g root -m 0644 "$path" "$dest" ;;
    esac || { _collector_err "could not install $f to $dest"; return 1; }
  done
  systemctl daemon-reload || { _collector_err "systemctl daemon-reload failed"; return 1; }
  for f in "${timers[@]}"; do
    systemctl enable --now "$f" || { _collector_err "could not enable and start $f"; return 1; }
  done
  printf '%s\n' "${timers[@]}"
}

# collector_uninstall <collector dir>
# Stops and disables the collector's timers and removes every installed file
# the folder names, printing how many were removed (0 = not installed).
# Collected logs in /var/log/radar are left alone; the caller decides whether
# to purge them.
collector_uninstall() {
  local dir="$1" path f dest removed=0
  for path in "$dir"/*.timer; do
    [[ -e "$path" ]] || continue
    f="${path##*/}"
    systemctl stop "$f" >/dev/null 2>&1 || true
    systemctl disable "$f" >/dev/null 2>&1 || true
  done
  for path in "$dir"/*; do
    [[ -e "$path" ]] || continue
    f="${path##*/}"
    dest=$(collector_dest "$f") || continue
    if [[ -e "$dest" || -L "$dest" ]]; then
      rm -f "$dest"
      removed=$((removed + 1))
    fi
  done
  (( removed == 0 )) || systemctl daemon-reload >/dev/null 2>&1 || true
  printf '%s\n' "$removed"
}
