#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="/run/radar"
TIMER_PID_FILE="$STATE_DIR/enrollment-window.pid"
RULE_COMMENT="radar-enrollment-window"

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -20
  exit "${1:-0}"
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: this needs root (iptables). Re-run with sudo." >&2
    exit 1
  fi
}

rule_present() {
  iptables -C DOCKER-USER -p tcp --dport 1515 -m comment --comment "$RULE_COMMENT" -j DROP 2>/dev/null
}

add_block_rule() {
  # Idempotent: only inserts if not already present.
  rule_present || iptables -I DOCKER-USER -p tcp --dport 1515 -m comment --comment "$RULE_COMMENT" -j DROP
}

remove_block_rule() {
  # Idempotent: only removes if present. May match more than once if
  # something else inserted a duplicate; strip every occurrence.
  while rule_present; do
    iptables -D DOCKER-USER -p tcp --dport 1515 -m comment --comment "$RULE_COMMENT" -j DROP
  done
}

cancel_pending_timer() {
  if [[ -f "$TIMER_PID_FILE" ]]; then
    local old_pid
    old_pid="$(cat "$TIMER_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      kill "$old_pid" 2>/dev/null || true
    fi
    rm -f "$TIMER_PID_FILE"
  fi
}

cmd_open() {
  require_root
  mkdir -p "$STATE_DIR"

  local minutes="${1:-30}"
  if ! [[ "$minutes" =~ ^[0-9]+$ ]] || [[ "$minutes" -eq 0 ]]; then
    echo "ERROR: --minutes must be a positive integer" >&2
    exit 2
  fi

  cancel_pending_timer

  if rule_present; then
    remove_block_rule
    echo "OK - enrollment window opened (port 1515 now reachable)"
  else
    echo "OK - enrollment window already open"
  fi

  local seconds_total=$((minutes * 60))
  nohup bash -c "
    sleep '$seconds_total'
    while iptables -C DOCKER-USER -p tcp --dport 1515 -m comment --comment '$RULE_COMMENT' -j DROP 2>/dev/null; do :; done
    iptables -I DOCKER-USER -p tcp --dport 1515 -m comment --comment '$RULE_COMMENT' -j DROP
    rm -f '$TIMER_PID_FILE'
  " >/tmp/radar-enrollment-window.log 2>&1 &
  disown
  echo $! > "$TIMER_PID_FILE"
  echo "OK - window will close automatically in ${minutes} minute(s) unless closed manually first"
}

cmd_close() {
  require_root
  cancel_pending_timer
  if rule_present; then
    echo "OK - enrollment window already closed"
  else
    add_block_rule
    echo "OK - enrollment window closed (port 1515 blocked)"
  fi
}

cmd_status() {
  if rule_present; then
    echo "CLOSED - port 1515 is blocked"
  else
    echo "OPEN - port 1515 is reachable"
    if [[ -f "$TIMER_PID_FILE" ]]; then
      local pid
      pid="$(cat "$TIMER_PID_FILE" 2>/dev/null || true)"
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "  (auto-close timer running, pid $pid)"
      fi
    fi
  fi
}

case "${1:-}" in
  open)
    shift
    MINUTES=30
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --minutes) MINUTES="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage 2 ;;
      esac
    done
    cmd_open "$MINUTES"
    ;;
  close)
    cmd_close
    ;;
  status)
    cmd_status
    ;;
  -h|--help|"")
    usage
    ;;
  *)
    echo "Unknown subcommand: $1" >&2
    usage 2
    ;;
esac