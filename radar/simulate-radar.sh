#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./simulate-radar.sh <suspicious_login|geoip_detection|log_volume> --agent <local|remote> [--ssh-key <path>]

Description:
  - suspicious_login, geoip_detection:
      --agent local  : run inside local agent container (docker exec)
      --agent remote : run on remote SSH agent via Ansible (copies + runs script)
  - log_volume:
      always runs locally (no Ansible), regardless of --agent
EOF
}


SCENARIO="${1:-}"
shift || true
AGENT_MODE=""
SSH_KEY=""
DEFAULT_KEY="$HOME/.ssh/id_ed25519"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)
      AGENT_MODE="${2:-}"
      shift 2
      ;;
    --ssh-key)
      SSH_KEY="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${SCENARIO}" ]]; then
  echo "Missing scenario argument" >&2
  usage
  exit 1
fi

case "${SCENARIO}" in
  suspicious_login|geoip_detection|log_volume) ;;
  *)
    echo "Invalid scenario: ${SCENARIO}" >&2
    echo "Allowed: suspicious_login, geoip_detection, log_volume" >&2
    exit 1
    ;;
esac

if [[ -z "${AGENT_MODE}" ]]; then
  echo "Missing --agent <local|remote>" >&2
  usage
  exit 1
fi
case "${AGENT_MODE}" in
  local|remote) ;;
  *)
    echo "Invalid --agent value: ${AGENT_MODE} (use local or remote)" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"

RATF_SCENARIO_DIR="${REPO_ROOT}/radar-test-framework/simulate/scenarios"
PLAYBOOK="${REPO_ROOT}/roles/wazuh_agent/playbooks/simulate.yml"
INVENTORY="${REPO_ROOT}/inventory.yaml"
CFG_YAML="${REPO_ROOT}/config.yaml"

# if [[ "${SCENARIO}" == "log_volume" ]]; then
#   echo "Running log_volume locally"
#   python3 "${RATF_SCENARIO_DIR}/log_volume.py"
#   exit 0
# fi

if [[ ! -d "${RATF_SCENARIO_DIR}" ]]; then
  echo "Scenario dir not found: ${RATF_SCENARIO_DIR}" >&2
  exit 1
fi

if [[ ! -f "${INVENTORY}" ]]; then
  echo "Inventory not found: ${INVENTORY}" >&2
  exit 1
fi


# when agent is local
if [[ "${AGENT_MODE}" == "local" ]]; then
  if [[ ! -f "${CFG_YAML}" ]]; then
    echo "Config not found: ${CFG_YAML}" >&2
    exit 1
  fi

  CONTAINER_NAME="$(
    python3 -c "import yaml; c=yaml.safe_load(open('${CFG_YAML}')) or {}; print(((c.get('scenarios') or {}).get('${SCENARIO}') or c.get('${SCENARIO}') or {} or {}).get('container_name',''))"
  )"

  if [[ -z "${CONTAINER_NAME}" ]]; then
    echo "Missing '${SCENARIO}.container_name' in ${CFG_YAML}" >&2
    exit 1
  fi

  echo "Scenario: ${SCENARIO}"
  echo "Agent: local"
  echo "Container: ${CONTAINER_NAME}"

  TMP_DIR="/tmp/ratf-simulate/scenarios"

  docker exec -i "${CONTAINER_NAME}" sh -lc "mkdir -p ${TMP_DIR}"
  docker cp "${RATF_SCENARIO_DIR}/." "${CONTAINER_NAME}:${TMP_DIR}/"
  docker exec -i "${CONTAINER_NAME}" sh -lc "python3 ${TMP_DIR}/${SCENARIO}.py"

  exit 0
fi


# when agent is remote
if [[ ! -f "${PLAYBOOK}" ]]; then
  echo "Playbook not found: ${PLAYBOOK}" >&2
  echo "Next step: create roles/wazuh_agent/playbooks/simulate.yml" >&2
  exit 1
fi

ANSIBLE_VAULT_FLAG=""

KEY="${SSH_KEY:-$DEFAULT_KEY}"
if [[ ! -f "$KEY" ]]; then
  echo "SSH key not found at: $KEY" >&2
  echo "Provide a valid key via --ssh-key or ensure $DEFAULT_KEY exists." >&2
  exit 1
fi

if [ -z "${SSH_AUTH_SOCK:-}" ] || ! ssh-add -l >/dev/null 2>&1; then
  echo "Starting ssh-agent and adding key: $KEY"
  eval "$(ssh-agent -s)"
  ssh-add "$KEY"
else
  echo "Reusing existing ssh-agent session; adding key: $KEY (if not already loaded)"
  ssh-add -l | grep -q "$(ssh-keygen -lf "$KEY" | awk '{print $2}')" || ssh-add "$KEY"
fi

ANSIBLE_VAULT_FLAG="--ask-vault-pass"

CMD=(
  ansible-playbook
  -i "${INVENTORY}"
  --limit "wazuh_agents_ssh"
  ${ANSIBLE_VAULT_FLAG}
  "${PLAYBOOK}"
  -e "radar_simulate_scenario=${SCENARIO}"
  -e "ratf_scenarios_dir=${RATF_SCENARIO_DIR}"
  -e "radar_config_path=${CFG_YAML}"
)

echo "Scenario: ${SCENARIO}"
echo "Agent: remote"
echo "Playbook: ${PLAYBOOK}"

${CMD[@]}
