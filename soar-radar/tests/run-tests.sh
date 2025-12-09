#!/usr/bin/env bash
set -Eeuo pipefail

have() { command -v "$1" >/dev/null 2>&1; }
run() { echo "+ $*"; "$@"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
echo "Repo root: $ROOT_DIR"

if have shellcheck; then
  run shellcheck build-radar.sh run-radar.sh
else
  echo "shellcheck not found, skipping shell lint"
fi

run python3 -m py_compile detector.py monitor.py webhook.py

export PYTHONPATH=.
echo "Running pytest..."
run pytest -q

if ! have bats; then
  echo "ERROR: bats not found in PATH"
  exit 1
fi
echo "Running bats..."
run bats tests/bash/build-radar.bats
run bats tests/bash/run-radar.bats

echo "All tests passed"
