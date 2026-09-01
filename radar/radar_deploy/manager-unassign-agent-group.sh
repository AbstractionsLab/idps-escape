#!/usr/bin/env bash
set -Eeuo pipefail

SCENARIO=""
AGENT_NAME=""
AGENT_IP=""

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -10
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario)    SCENARIO="$2";    shift 2 ;;
    --agent-name)  AGENT_NAME="$2";  shift 2 ;;
    --agent-ip)    AGENT_IP="$2";    shift 2 ;;
    --help|-h)     usage ;;
    *) echo "Unknown option: $1" >&2; usage 2 ;;
  esac
done

[[ -n "$SCENARIO" ]] || { echo "ERROR: --scenario is required"; usage 2; }
[[ -n "$AGENT_NAME" || -n "$AGENT_IP" ]] || { echo "ERROR: at least one of --agent-name or --agent-ip is required"; usage 2; }

RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
radar_load_env "$RADAR_ROOT"

HOSTS_ARG="${AGENT_NAME}:${AGENT_IP}"

PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli unassign-hosts-from-groups \
  --hosts "$HOSTS_ARG" --scenario "$SCENARIO"

echo ""
echo "=== SUCCESS: group unassignment for '${SCENARIO}' completed ==="