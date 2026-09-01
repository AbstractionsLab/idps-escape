#!/usr/bin/env bash

set -Eeuo pipefail

SCENARIO="${1:?Usage: manager-undo-scenario.sh <scenario>}"
RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
radar_load_env "$RADAR_ROOT"

echo ">>> Resetting '${SCENARIO}' group agent.conf to empty..."
PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli undo-scenario-config --scenario "$SCENARIO" --radar-root "$RADAR_ROOT"

echo ">>> Removing '${SCENARIO}' ossec.conf block and any decoder/rule/list files no longer"
echo "    needed by another currently-deployed scenario (restarts the manager only if"
echo "    something actually changed)..."
PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli undo-manager-config \
  --scenario "$SCENARIO" --scenarios-dir "$RADAR_ROOT/scenarios"

echo ""
echo "=== SUCCESS: undo for '${SCENARIO}' completed ==="
echo "Note: this is a partial, conservative undo. It does not remove"
echo "enrichment or active-response scripts on the manager filesystem,"
echo "the filebeat pipeline patch, or shared ossec.conf blocks (default,"
echo "shared auth_log_enrichment, decoder_exclude/whitelist) -- those"
echo "aren't safely reversible without per-scenario dependency tracking."
echo "Decoder/rule/list files ARE removed once no other currently-deployed"
echo "scenario still shares them. Run this scenario's"
echo "'./build-radar.sh ${SCENARIO}' again any time to redeploy."