#!/usr/bin/env bash
set -Eeuo pipefail

# Usage:
#   ./stop-radar.sh [--agents|--ssh|--all] [--purge]
# Defaults:
#   mode  = --all       (stop core + container agents + ssh agents)
#   purge = disabled    (do not remove volumes)

DOCKER_BIN="${DOCKER_BIN:-docker}"
ANSIBLE_BIN="${ANSIBLE_BIN:-ansible-playbook}"

PROJECT="${PROJECT:-soar-radar}"
CORE_COMPOSE="${CORE_COMPOSE:-docker-compose.core.yml}"
WEBHOOK_COMPOSE="${CORE_COMPOSE:-docker-compose.webhook.yml}"
AGENTS_COMPOSE="${AGENTS_COMPOSE:-docker-compose.agents.yml}"
INVENTORY="${INVENTORY:-inventory.yaml}"

MODE="--all"
PURGE_FLAGS=()
for arg in "$@"; do
  case "$arg" in
    --agents|--ssh|--all) MODE="$arg" ;;
    --purge) PURGE_FLAGS+=("-v");;
    *) echo "Unknown arg: $arg" >&2; exit 2;;
  esac
done

echo ">>> Stopping RADAR | mode: ${MODE} | purge volumes: ${#PURGE_FLAGS[@]}>0 ? yes : no"

if [[ "$MODE" == "--agents" || "$MODE" == "--all" ]]; then
  if [[ -f "$AGENTS_COMPOSE" ]]; then
    echo ">>> Stopping container agents..."
    "$DOCKER_BIN" compose -p "$PROJECT" -f "$AGENTS_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"
  else
    echo ">>> Skip agents compose: $AGENTS_COMPOSE not found"
  fi
fi


echo ">>> Stopping core stack..."
"$DOCKER_BIN" compose -p "$PROJECT" -f "$CORE_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"
"$DOCKER_BIN" compose -p "$PROJECT" -f "$WEBHOOK_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"

echo ">>> Done."
