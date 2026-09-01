#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<EOF
Usage:
  $0 <scenario> [--ingest true|false]

Scenarios: suspicious_login | geoip_detection | log_volume | scanning_detection
Dataset ingest to speed up the training:    true (default) | false
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

if [[ -f Dockerfile.radar-cli ]]; then
  echo ">>> Building radar-cli image..."
  docker build -f Dockerfile.radar-cli -t radar-cli:latest .
fi

if [[ "$INGEST" == "true" ]]; then
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