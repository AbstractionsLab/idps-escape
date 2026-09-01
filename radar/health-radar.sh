#!/usr/bin/env bash
# Usage: health-radar.sh [--scenario <name|all>] [--agent-name name1,name2]

set -Eeuo pipefail

SCENARIO_FILTER="all"
AGENT_NAMES=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -20
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario)    SCENARIO_FILTER="$2"; shift 2 ;;
    --agent-name)  AGENT_NAMES="$2";     shift 2 ;;
    --help|-h)     usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

cd "$SCRIPT_DIR"
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi
export PYTHONPATH="$(pwd)${PYTHONPATH:+:$PYTHONPATH}"

echo "=== MANAGER (filesystem/container) ==="
bash "radar_deploy/manager-health.sh" "$SCENARIO_FILTER"

echo ""
echo "=== MANAGER (Wazuh API / OpenSearch / webhook) ==="
python3 -m wazuh_api.cli manager-health-api --scenario "$SCENARIO_FILTER"

if [[ -n "$AGENT_NAMES" ]]; then
  echo ""
  echo "=== AGENTS ==="
  python3 -m wazuh_api.cli agent-health --agent-name "$AGENT_NAMES" --scenario "$SCENARIO_FILTER"
fi