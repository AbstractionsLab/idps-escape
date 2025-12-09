#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<EOF
Usage:
  $0 <scenario>

Scenarios: suspicious_login | insider_threat | ddos_detection | malware_communication | log_volume
EOF
  exit 2
}

[[ $# -ge 1 ]] || usage
SCENARIO_NAME="$1"

if [[ "$SCENARIO_NAME" != "log_volume" ]]; then
  docker run --rm \
  -v "$PWD/${SCENARIO_NAME}/dataset:/app/${SCENARIO_NAME}/dataset" \
  -v "$PWD/config/wazuh_indexer_ssl_certs/root-ca.pem:/app/config/wazuh_indexer_ssl_certs/root-ca.pem" \
  -v "$PWD/.env:/app/.env:ro" \
  radar-cli:latest python "${SCENARIO_NAME}"/wazuh_ingest.py
fi



DET_ID="$(docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -v "$PWD/.env:/app/.env:ro" \
  radar-cli:latest python detector.py "${SCENARIO_NAME}")"

MON_ID="$(docker run --rm \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -v "$PWD/.env:/app/.env:ro" \
  radar-cli:latest python monitor.py "${SCENARIO_NAME}" "$DET_ID")"