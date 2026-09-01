#!/usr/bin/env bash
set -Eeuo pipefail

RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$RADAR_ROOT/config"
CERTS_DIR="$CONFIG_DIR/wazuh_indexer_ssl_certs"
CERTS_YML="$CONFIG_DIR/certs.yml"

if [[ ! -f "$CERTS_YML" ]]; then
  echo "[!] $CERTS_YML not found -- cannot generate certs." >&2
  exit 1
fi

mkdir -p "$CERTS_DIR"

if compgen -G "$CERTS_DIR/*.pem" > /dev/null; then
  echo "OK - certs already present in $CERTS_DIR, skipping generation."
  exit 0
fi

echo ">>> No certs found in $CERTS_DIR -- generating with wazuh-certs-generator..."
docker run --rm \
  -v "$CERTS_YML:/config/certs.yml:ro" \
  -v "$CERTS_DIR:/certificates" \
  wazuh/wazuh-certs-generator:0.0.2
echo "OK - certs generated in $CERTS_DIR."