#!/usr/bin/env bash
set -Eeuo pipefail

MANAGER_MODE="local"
AGENT_MODE="local"
SCENARIO_FILTER="all"
SSH_KEY="${HOME}/.ssh/id_ed25519"
ENV_FILE=".env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//' | head -20
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager)   MANAGER_MODE="$2"; shift 2 ;;
    --agent)     AGENT_MODE="$2";   shift 2 ;;
    --scenario)  SCENARIO_FILTER="$2"; shift 2 ;;
    --ssh-key)   SSH_KEY="$2";      shift 2 ;;
    --help|-h)   usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ "$MANAGER_MODE" != "local" && "$MANAGER_MODE" != "remote" ]]; then
  echo "ERROR: --manager must be 'local' or 'remote'" >&2; exit 1
fi
if [[ "$AGENT_MODE" != "local" && "$AGENT_MODE" != "remote" ]]; then
  echo "ERROR: --agent must be 'local' or 'remote'" >&2; exit 1
fi

[[ "$MANAGER_MODE" == "local" ]] && MGR_GROUP="wazuh_manager_local"      || MGR_GROUP="wazuh_manager_ssh"
[[ "$AGENT_MODE"   == "local" ]] && AGENT_GROUP="wazuh_agents_container"  || AGENT_GROUP="wazuh_agents_ssh"
[[ "$MANAGER_MODE" == "local" ]] && MGR_MODE_FULL="docker_local"          || MGR_MODE_FULL="docker_remote"

VAULT_FLAG=""
if [[ "$MANAGER_MODE" == "remote" || "$AGENT_MODE" == "remote" ]]; then
    [[ -f "$SSH_KEY" ]] || { echo "ERROR: SSH key not found: $SSH_KEY"; exit 1; }
    if [ -z "${SSH_AUTH_SOCK:-}" ] || ! ssh-add -l >/dev/null 2>&1; then
        eval "$(ssh-agent -s)"
        ssh-add "$SSH_KEY"
    else
        ssh-add -l | grep -q "$(ssh-keygen -lf "$SSH_KEY" | awk '{print $2}')" || ssh-add "$SSH_KEY"
    fi
    if [[ "${RADAR_NONINTERACTIVE:-}" == "1" ]]; then VAULT_FLAG=""; else VAULT_FLAG="--ask-vault-pass"; fi
fi

[[ -f "$ENV_FILE" ]] && set -a && source "$ENV_FILE" && set +a || true

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY_FILE="/tmp/radar_health_${TIMESTAMP}.txt"
rm -f /tmp/radar_health_*_agent_*.txt 2>/dev/null

ansible-playbook "${SCRIPT_DIR}/roles/health_check/health-check.yml" \
    -i "${SCRIPT_DIR}/inventory.yaml" \
    --limit "${MGR_GROUP}:${AGENT_GROUP}" \
    -e "manager_mode=${MGR_MODE_FULL}" \
    -e "scenario_filter=${SCENARIO_FILTER}" \
    -e "ar_yaml_path=${SCRIPT_DIR}/scenarios/active_responses/ar.yaml" \
    -e "scenarios_root=${SCRIPT_DIR}/scenarios" \
    -e "os_url=${OS_URL:-}" \
    -e "os_user=${OS_USER:-}" \
    -e "os_pass=${OS_PASS:-}" \
    -e "wazuh_api_url=${WAZUH_API_URL:-}" \
    -e "wazuh_auth_user=${WAZUH_AUTH_USER:-}" \
    -e "wazuh_auth_pass=${WAZUH_AUTH_PASS:-}" \
    -e "dashboard_url=${DASHBOARD_URL:-}" \
    -e "webhook_url=${WEBHOOK_URL:-}" \
    -e "summary_file=${SUMMARY_FILE}" \
    ${VAULT_FLAG}

cat "${SUMMARY_FILE}" 2>/dev/null
for agent_file in /tmp/radar_health_*_agent_*.txt; do
    [ -f "$agent_file" ] && cat "$agent_file"
done
echo ""