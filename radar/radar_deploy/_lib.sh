#!/usr/bin/env bash

dexec() {
  docker exec "$CONTAINER" bash -lc "$1"
}

dexec_quiet() {
  docker exec "$CONTAINER" bash -lc "$1" 2>/dev/null
}

radar_load_env() {
  local radar_root="${1:?radar_load_env: RADAR_ROOT is required}"
  if [[ -f "$radar_root/.env" ]]; then
    set -a
    # shellcheck disable=SC1091,SC1090
    source "$radar_root/.env"
    set +a
  fi
}