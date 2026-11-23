#!/usr/bin/env bash
# radar.sh
# Usage:
#   ./radar.sh gui                                   Start the Web GUI
#   ./radar.sh gui-url                               Print the login URL of the running Web GUI
#   ./radar.sh build <scenario>                       = sudo ./build-radar.sh <scenario>
#   ./radar.sh run <scenario> [--ingest true]         = ./run-radar.sh
#   ./radar.sh health [--scenario ...] [--agent-name ...]  = ./health-radar.sh
#   ./radar.sh stop [--purge]                         = ./stop-radar.sh
#   ./radar.sh mint-token <group>[,<group>...] [minutes]   = ./radar_deploy/manager-mint-token.sh (needs sudo to auto-open port 1515)
#   ./radar.sh enrollment open [--minutes N] | close | status   = ./radar_deploy/manager-enrollment-window.sh (needs sudo)

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"
REQ_FILE="$SCRIPT_DIR/gui/requirements.txt"
REQ_HASH_FILE="$VENV_DIR/.requirements.sha256"

GUI_STATE_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/radar-gui/gui-${RADAR_GUI_PORT:-5000}.env"

running_gui_url() {
  [[ -f "$GUI_STATE_FILE" ]] || return 1
  local pid url
  pid="$(sed -n 's/^PID=//p' "$GUI_STATE_FILE")"
  url="$(sed -n 's/^URL=//p' "$GUI_STATE_FILE")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null &&
     { [[ ! -d /proc ]] || tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q 'app\.py'; }; then
    echo "$url"
    return 0
  fi
  rm -f "$GUI_STATE_FILE"
  return 1
}

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -20
  exit "${1:-0}"
}

ensure_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    echo ">>> Creating virtual environment (first run only)..."
    python3 -m venv "$VENV_DIR"
  fi

  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"

  local current_hash
  current_hash="$(sha256sum "$REQ_FILE" | awk '{print $1}')"
  local stored_hash=""
  [[ -f "$REQ_HASH_FILE" ]] && stored_hash="$(cat "$REQ_HASH_FILE")"

  if [[ "$current_hash" != "$stored_hash" ]]; then
    echo ">>> Installing/updating dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -r "$REQ_FILE"
    echo "$current_hash" > "$REQ_HASH_FILE"
  fi
}

CMD="${1:-}"
shift || true

case "$CMD" in
  gui)
    if url="$(running_gui_url)"; then
      echo ">>> RADAR GUI is already running. Login URL (keep it private):"
      echo "    $url"
      echo "    To restart it, use Log out in the GUI (or stop the running process) and run ./radar.sh gui again."
      exit 0
    fi
    ensure_venv
    echo ">>> Starting RADAR GUI..."
    cd gui
    exec python3 app.py
    ;;

  gui-url)
    if url="$(running_gui_url)"; then
      echo "$url"
    else
      echo "The RADAR GUI is not running on port ${RADAR_GUI_PORT:-5000}. Start it with: ./radar.sh gui" >&2
      exit 1
    fi
    ;;

  build)
    exec bash "$SCRIPT_DIR/build-radar.sh" "$@"
    ;;

  run)
    exec bash "$SCRIPT_DIR/run-radar.sh" "$@"
    ;;

  health)
    exec bash "$SCRIPT_DIR/health-radar.sh" "$@"
    ;;

  stop)
    exec bash "$SCRIPT_DIR/stop-radar.sh" "$@"
    ;;

  mint-token)
    exec bash "$SCRIPT_DIR/radar_deploy/manager-mint-token.sh" "$@"
    ;;

  enrollment)
    exec bash "$SCRIPT_DIR/radar_deploy/manager-enrollment-window.sh" "$@"
    ;;

  rotate-credentials)
    exec bash "$SCRIPT_DIR/radar_deploy/manager-rotate-credentials.sh" "$@"
    ;;

  repair-permissions)
    exec bash "$SCRIPT_DIR/radar_deploy/manager-repair-permissions.sh" "$@"
    ;;

  -h|--help|"")
    usage
    ;;

  *)
    echo "Unknown command: $CMD" >&2
    usage 1
    ;;
esac