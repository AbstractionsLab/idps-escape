#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<EOF
Usage:
  $0 <scenario> [--ingest true|false]

Scenarios: suspicious_login | geoip_detection | log_volume | scanning_detection |
           linux_resource_utilization

--ingest true seeds history for scenarios that ship
scenarios/ingest_scripts/<scenario>/wazuh_ingest.py (log_volume, suspicious_login, linux_resource_utilization).
EOF
  exit 2
}

[[ $# -ge 1 ]] || usage
SCENARIO_NAME="$1"
INGEST="false"
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ingest) INGEST="$2"; shift 2 ;;
    *) usage ;;
  esac
done

if [[ "$INGEST" == "true" && ! -f "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scenarios/ingest_scripts/${SCENARIO_NAME}/wazuh_ingest.py" ]]; then
  echo "[ERROR] --ingest true: scenario '${SCENARIO_NAME}' has no ingest script" >&2
  echo "        (scenarios/ingest_scripts/${SCENARIO_NAME}/wazuh_ingest.py). Re-run with --ingest false;" >&2
  echo "        the detector then builds its baseline from live data." >&2
  exit 2
fi

if [[ -f Dockerfile.radar-cli ]]; then
  echo ">>> Building radar-cli image..."
  docker build -f Dockerfile.radar-cli -t radar-cli:latest .
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

# shellcheck source=radar_deploy/_lib.sh disable=SC1091
source "$SCRIPT_DIR/radar_deploy/_lib.sh"
radar_load_env "$PWD"
CLI_ENV_KEYS=(OS_URL OS_USER OS_PASS OS_VERIFY_SSL OS_TIMEOUT DASHBOARD_VERIFY_SSL
              WEBHOOK_NAME WEBHOOK_URL WEBHOOK_SHARED_SECRET)
cli_env() {
  local k
  CLI_ENV=()
  for k in "${CLI_ENV_KEYS[@]}"; do
    if [[ -n "${!k+x}" ]]; then CLI_ENV+=(-e "$k"); fi
  done
}

OS_URL_RESOLVED="$(python3 -m wazuh_api.infra resolve host indexer 2>/dev/null)" || true
if [[ -n "$OS_URL_RESOLVED" ]]; then export OS_URL="$OS_URL_RESOLVED"; fi
WEBHOOK_URL_DECLARED="${WEBHOOK_URL:-}"
WEBHOOK_URL_RESOLVED=""
if [[ -n "$WEBHOOK_URL_DECLARED" ]]; then
  WEBHOOK_URL_RESOLVED="$(python3 -m wazuh_api.infra resolve-webhook indexer "$WEBHOOK_URL_DECLARED" 2>/dev/null)" || true
fi

cli_env
off_hours() {
  docker run --rm \
    -v "$PWD/config.yaml:/app/config.yaml:ro" \
    "${CLI_ENV[@]}" \
  radar-cli:latest python off_hours.py "$@"
}
# The pipeline must exist before the synthetic ingest names it.
if [[ "$SCENARIO_NAME" == "suspicious_login" ]]; then
  off_hours deploy
fi

if [[ "$INGEST" == "true" ]]; then
  docker run --rm \
    -v "$PWD/${SCENARIO_NAME}/dataset:/app/${SCENARIO_NAME}/dataset" \
    -v "$PWD/config/wazuh_indexer_ssl_certs/root-ca.pem:/app/config/wazuh_indexer_ssl_certs/root-ca.pem" \
    "${CLI_ENV[@]}" \
  radar-cli:latest python "${SCENARIO_NAME}"/wazuh_ingest.py
fi

# Flag archive events indexed before the pipeline existed (model mode trains on them).
if [[ "$SCENARIO_NAME" == "suspicious_login" ]]; then
  off_hours backfill
fi

if [[ -n "$WEBHOOK_URL_RESOLVED" ]]; then export WEBHOOK_URL="$WEBHOOK_URL_RESOLVED"; fi

# suspicious_login has no generic detector: off_hours.py runs its off-hours
# consumers (rule-mode monitor, model-mode detector and monitor) and stops the
# detectors they replace. It runs after the backfill, so model mode trains on flagged history.
if [[ "$SCENARIO_NAME" == "suspicious_login" ]]; then
  cli_env
  off_hours monitors
  exit 0
fi

DET_ID="$(docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  "${CLI_ENV[@]}" \
  radar-cli:latest python detector.py "${SCENARIO_NAME}")"

cli_env
MON_ID="$(docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  "${CLI_ENV[@]}" \
  radar-cli:latest python monitor.py "${SCENARIO_NAME}" "$DET_ID")"
