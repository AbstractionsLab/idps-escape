#!/usr/bin/env bash
set -Eeuo pipefail

# Usage:
#   ./stop-radar.sh [--purge]
# Examples:
#   ./stop-radar.sh
#   ./stop-radar.sh --purge

DOCKER_BIN="${DOCKER_BIN:-docker}"
CORE_COMPOSE="${CORE_COMPOSE:-docker-compose.core.yml}"
WEBHOOK_COMPOSE="${WEBHOOK_COMPOSE:-docker-compose.webhook.yml}"

PURGE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)
      PURGE=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--purge]" >&2
      exit 2
      ;;
  esac
done

echo "========================================="
echo "RADAR Stop Plan"
echo "========================================="
echo "Purge volumes: $PURGE"
echo "========================================="

PURGE_FLAGS=()
[[ "$PURGE" == true ]] && PURGE_FLAGS+=("-v")

if [[ -f "$WEBHOOK_COMPOSE" ]]; then
  echo ""
  echo ">>> Stopping webhook..."
  "$DOCKER_BIN" compose -f "$WEBHOOK_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"
else
  echo ">>> Skip webhook: $WEBHOOK_COMPOSE not found"
fi

if [[ -f "$CORE_COMPOSE" ]]; then
  echo ""
  echo ">>> Stopping core stack (manager/indexer/dashboard)..."
  "$DOCKER_BIN" compose -f "$CORE_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"
else
  echo ">>> Skip core: $CORE_COMPOSE not found"
fi

echo ""
echo ">>> Manager stopped successfully"