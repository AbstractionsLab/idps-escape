#!/usr/bin/env bash
set -Eeuo pipefail

export TERM=xterm-256color
have() { command -v "$1" >/dev/null 2>&1; }
run() { echo "+ $*"; "$@"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
echo "Repo root: $ROOT_DIR"

FAILED_SUITES=()

if have shellcheck; then
  run shellcheck build-radar.sh run-radar.sh bootstrap-agent.sh \
    || FAILED_SUITES+=("shellcheck")
else
  echo "shellcheck not found, skipping shell lint"
fi

run python3 -m py_compile anomaly_detector/detector.py anomaly_detector/monitor.py anomaly_detector/webhook.py \
  || FAILED_SUITES+=("py_compile")

export PYTHONPATH="$ROOT_DIR/anomaly_detector:$ROOT_DIR"
echo "Running pytest..."
run pytest -q || FAILED_SUITES+=("pytest")

if ! have bats; then
  echo "ERROR: bats not found in PATH"
  FAILED_SUITES+=("bats (not found)")
else
  echo "Running bats..."
  for suite in build-radar run-radar bootstrap-agent; do
    run bats -p "tests/bash/${suite}.bats" || FAILED_SUITES+=("bats:${suite}")
  done
fi

echo "=================="
if [[ "${#FAILED_SUITES[@]}" -eq 0 ]]; then
  echo "All tests passed"
  exit 0
else
  echo "FAILED suites: ${FAILED_SUITES[*]}"
  exit 1
fi