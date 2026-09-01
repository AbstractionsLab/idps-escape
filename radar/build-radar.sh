#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  build-radar.sh <scenario>
  build-radar.sh --core-only

Scenarios:
  suspicious_login | geoip_detection | log_volume | scanning_detection

Flags:
  --core-only           Bring up the Wazuh manager/indexer/dashboard stack
                        only.

Examples:
  ./build-radar.sh suspicious_login
  ./build-radar.sh --core-only
EOF
  exit 2
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage
[[ $# -ge 1 ]] || usage

CORE_ONLY=false
SCENARIO_NAME=""
if [[ "$1" == "--core-only" ]]; then
  CORE_ONLY=true
  shift
else
  SCENARIO_NAME="$1"; shift
fi

if [[ $# -gt 0 ]]; then
  echo "Unknown option: $1"; usage
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
export PYTHONPATH="$(pwd)${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$CORE_ONLY" != true ]]; then
  SCENARIO_INFO="$(python3 -m wazuh_api.cli scenario-info "$SCENARIO_NAME")" || exit 1
fi

echo "=== RADAR plan ==="
if [[ "$CORE_ONLY" == true ]]; then
  echo "Mode         : core-only (plain Wazuh, no RADAR scenario)"
else
  echo "Scenario     : $SCENARIO_NAME"
fi
echo "=================="

if [[ ! -f .env ]]; then
  echo "[!] .env not found. Copy env.example to .env and fill in the required values." >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a

# --- manager: bring up local core stack if not already running ---
if ! docker ps --format '{{.Names}}' | grep -qx wazuh.manager; then
  echo ">>> Ensuring indexer/manager/dashboard TLS certs exist..."
  bash "radar_deploy/manager-ensure-certs.sh"

  PIPELINE_CONTAINER_PATH='/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json'
  PIPELINE_HOST_PATH=$(grep -E ":${PIPELINE_CONTAINER_PATH//\//\\/}\$" volumes.yml | head -1 | sed -E 's/^ *- *//; s/:[^:]*$//')
  if [[ -z "$PIPELINE_HOST_PATH" ]]; then
    echo "[!] volumes.yml has no bind mount for $PIPELINE_CONTAINER_PATH on service wazuh.manager" >&2
    echo "    Add that mapping (see radar-getting-started.md's \"Configure volume mappings\" section) and re-run." >&2
    exit 1
  fi
  if [[ ! -e "$PIPELINE_HOST_PATH" || -d "$PIPELINE_HOST_PATH" || ! -s "$PIPELINE_HOST_PATH" ]]; then
    echo ">>> Seeding ${PIPELINE_HOST_PATH} with default content before first container creation..."
    mkdir -p "$(dirname "$PIPELINE_HOST_PATH")"
    [[ -d "$PIPELINE_HOST_PATH" ]] && (rmdir "$PIPELINE_HOST_PATH" 2>/dev/null || rm -rf "$PIPELINE_HOST_PATH")
    cp config/wazuh_cluster/pipeline-archives.json "$PIPELINE_HOST_PATH"
    chmod 644 "$PIPELINE_HOST_PATH"
  fi

  echo ">>> Bringing up local core stack (docker-compose.core.yml)..."
  docker compose -f docker-compose.core.yml -f volumes.yml up -d
else
  echo ">>> Manager already running."
fi

# --- webhook (RADAR's AD-alerts integration; not part of plain Wazuh) ---
if [[ "$CORE_ONLY" != true && -f docker-compose.webhook.yml ]]; then
  echo ">>> Building webhook locally..."
  WAZUH_REGISTRATION_TOKEN=""
  if docker compose -f docker-compose.webhook.yml run --rm --no-deps --entrypoint sh webhook \
       -c 'test -s /var/ossec/etc/client.keys' >/dev/null 2>&1; then
    echo "OK - webhook already enrolled; no new token needed"
  else
    echo ">>> Webhook not yet enrolled; minting a short-lived token..."
    MINT_OUTPUT=$(bash radar_deploy/manager-mint-token.sh default 60 2>&1) || {
      echo "$MINT_OUTPUT"
      echo "[ERROR] Could not mint an enrollment token for the webhook." >&2
      exit 1
    }
    echo "$MINT_OUTPUT"
    WAZUH_REGISTRATION_TOKEN=$(echo "$MINT_OUTPUT" | grep '^TOKEN_VALUE=' | cut -d= -f2)
    if [[ -z "$WAZUH_REGISTRATION_TOKEN" ]]; then
      echo "[ERROR] Could not extract the enrollment token from manager-mint-token.sh output." >&2
      exit 1
    fi
  fi
  export WAZUH_REGISTRATION_TOKEN

  docker compose -f docker-compose.webhook.yml up -d --build
fi

if [[ -z "${WAZUH_API_URL:-}" || -z "${WAZUH_AUTH_USER:-}" || -z "${WAZUH_AUTH_PASS:-}" ]]; then
  echo "[!] WAZUH_API_URL / WAZUH_AUTH_USER / WAZUH_AUTH_PASS are not fully set in .env." >&2
  exit 1
fi

export WAZUH_API_URL WAZUH_AUTH_USER WAZUH_AUTH_PASS OS_URL OS_USER OS_PASS

echo ">>> Waiting for the Wazuh API to become reachable..."
python3 -m wazuh_api.cli wait-for-api --timeout 120

echo ">>> Hardening agent enrollment (require credential, disable auto-purge)..."
bash "radar_deploy/manager-harden-enrollment.sh"

if [[ "$CORE_ONLY" == true ]]; then
  echo ""
  echo "=== SUCCESS: plain Wazuh manager/indexer/dashboard is up (no RADAR scenario applied) ==="
  echo "To layer a RADAR scenario on top later, run: ./build-radar.sh <scenario>"
  exit 0
fi

if [[ "$SCENARIO_NAME" == "suspicious_login" && -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "[!] MAXMIND_LICENSE_KEY is not set in .env. Only needed the first time the manager"
  echo "    fetches GeoLite2-City.mmdb / GeoLite2-ASN.mmdb (see radar_deploy/manager-apply-scenario.sh)."
fi

echo ">>> Waiting for OpenSearch to become reachable..."
python3 -m wazuh_api.cli wait-for-opensearch --timeout 120

echo ">>> Applying manager-side scenario config (active responses, enrichment, filebeat)..."
bash "radar_deploy/manager-apply-scenario.sh" "$SCENARIO_NAME"

echo ">>> Deploying '${SCENARIO_NAME}' group/agent.conf via Wazuh API..."
python3 -m wazuh_api.cli deploy-scenario-config \
  --scenario "$SCENARIO_NAME" --agent-config-dir scenarios/agent_configs

echo ">>> Deploying decoders/rules/lists and ossec.conf via Wazuh API..."
python3 -m wazuh_api.cli deploy-manager-config \
  --scenario "$SCENARIO_NAME" --scenarios-dir scenarios