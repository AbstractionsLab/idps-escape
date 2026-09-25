#!/usr/bin/env bash
set -Eeuo pipefail

SCENARIO="${1:?Usage: manager-apply-scenario-all.sh <scenario>}"
RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"

mapfile -t CONTAINERS < <(radar_manager_containers "$RADAR_ROOT")
if [[ ${#CONTAINERS[@]} -eq 0 ]]; then
  echo "[ERROR] no manager nodes registered in infra.yaml" >&2
  exit 1
fi

PRIMARY="${CONTAINERS[0]}"
FAILED=()

echo ">>> Applying scenario '$SCENARIO' to primary manager: $PRIMARY"
bash "$RADAR_ROOT/radar_deploy/manager-apply-scenario.sh" "$SCENARIO" "$PRIMARY"

if [[ ${#CONTAINERS[@]} -gt 1 ]]; then
  for c in "${CONTAINERS[@]:1}"; do
    echo ""
    echo ">>> Applying scenario '$SCENARIO' to additional manager node: $c"
    if bash "$RADAR_ROOT/radar_deploy/manager-apply-scenario.sh" "$SCENARIO" "$c"; then
      echo "OK - $c done"
    else
      echo "[WARN] scenario apply failed on $c -- agents connected to this node won't get active" >&2
      echo "       responses/enrichment until this is fixed. Continuing with the other nodes." >&2
      FAILED+=("$c")
    fi
  done
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo ""
  echo "[WARN] primary manager ($PRIMARY) is fully configured, but ${#FAILED[@]} additional node(s)" >&2
  echo "       failed: ${FAILED[*]}" >&2
fi