#!/usr/bin/env bash

set -Eeuo pipefail

AGENT_NAME=""
AGENT_IP=""
NO_PURGE=""

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -12
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent-name)  AGENT_NAME="$2";  shift 2 ;;
    --agent-ip)    AGENT_IP="$2";    shift 2 ;;
    --no-purge)    NO_PURGE="--no-purge"; shift ;;
    --help|-h)     usage ;;
    *) echo "Unknown option: $1" >&2; usage 2 ;;
  esac
done

[[ -n "$AGENT_NAME" ]] || { echo "ERROR: --agent-name is required"; usage 2; }

RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
radar_load_env "$RADAR_ROOT"

PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli deregister-agent \
  --name "$AGENT_NAME" --ip "$AGENT_IP" $NO_PURGE

echo ""
echo "=== SUCCESS: deregistration for '${AGENT_NAME}' completed ==="
echo "Note: this only removes the agent from the manager. If the endpoint"
echo "itself is still running the Wazuh agent service, it will try to"
echo "re-enroll automatically -- stop/uninstall the agent on the endpoint"
echo "first if you don't want that."