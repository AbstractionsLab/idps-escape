#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  build-radar.sh <scenario> --agent <local|remote> --manager <local|remote> --manager_exists <true|false> [--ssh-key </path/to/private_key>]

Scenarios:
  suspicious_login | insider_threat | ddos_detection | malware_communication | geoip_detection | log_volume

Flags:
  --agent           Where agents live:      local (docker-compose.agents.yml) | remote (SSH endpoints)
  --manager         Where manager lives:    local (docker-compose.core.yml)   | remote (SSH host)
  --manager_exists  Whether the manager already exists at that location:
                      - true  : do not bootstrap a manager
                      - false : bootstrap (local: docker compose up; remote: let Ansible bootstrap)
  --ssh-key         Optional: path to the SSH private key used for remote manager/agent access.
                    If not provided, defaults to: $HOME/.ssh/id_ed25519

Examples:
  # Lab: local manager + local agent containers; create manager if missing
  ./build-radar.sh insider_threat --agent local --manager local --manager_exists false

  # Customer: remote manager already exists (cluster or single), remote SSH agents
  ./build-radar.sh suspicious_login --agent remote --manager remote --manager_exists true

  # Customer: remote manager DOES NOT exist yet; bootstrap it via Ansible, remote SSH agents
  ./build-radar.sh ddos_detection --agent remote --manager remote --manager_exists false --ssh-key "$HOME/.ssh/mykeys/id_ed25519"
EOF
  exit 2
}


[[ $# -ge 1 ]] || usage
SCENARIO_NAME="$1"; shift

AGENT_MODE=""
MANAGER_MODE=""
MANAGER_EXISTS=""
SSH_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)
      [[ $# -ge 2 ]] || usage
      AGENT_MODE="$2"; shift 2;;
    --manager)
      [[ $# -ge 2 ]] || usage
      MANAGER_MODE="$2"; shift 2;;
    --manager_exists)
      [[ $# -ge 2 ]] || usage
      MANAGER_EXISTS="$2"; shift 2;;
    --ssh-key)
      [[ $# -ge 2 ]] || usage
      SSH_KEY="$2"; shift 2;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done


case "$SCENARIO_NAME" in
  suspicious_login|insider_threat|ddos_detection|malware_communication|geoip_detection|log_volume) ;;
  *) echo "Invalid scenario: $SCENARIO_NAME"; usage ;;
esac

case "$AGENT_MODE"   in local|remote) ;; *) echo "--agent must be local or remote"; usage ;; esac
case "$MANAGER_MODE" in local|remote) ;; *) echo "--manager must be local or remote"; usage ;; esac
case "$MANAGER_EXISTS" in true|false) ;; *) echo "--manager_exists must be true or false"; usage ;; esac


case "$SCENARIO_NAME" in
  suspicious_login)       AGENT_SERVICE="agent.suspicious" ;;
  insider_threat)         AGENT_SERVICE="agent.insider"    ;;
  ddos_detection)         AGENT_SERVICE="agent.ddos"       ;;
  malware_communication)  AGENT_SERVICE="agent.malcom"     ;;
  geoip_detection)        AGENT_SERVICE="agent.geoip"     ;;
  log_volume)             AGENT_SERVICE="agent.logvolume"     ;;
esac


if [[ "$MANAGER_MODE" == "local" ]]; then
  LIMIT_MGR_GROUP="wazuh_manager_local"
else
  LIMIT_MGR_GROUP="wazuh_manager_ssh"
fi

if [[ "$AGENT_MODE" == "local" ]]; then
  LIMIT_AGENT_GROUP="wazuh_agents_container"
else
  LIMIT_AGENT_GROUP="wazuh_agents_ssh"
fi


DEFAULT_KEY="$HOME/.ssh/id_ed25519"
KEY="${SSH_KEY:-$DEFAULT_KEY}"

ANSIBLE_VAULT_FLAG=""
if [[ "$MANAGER_MODE" == "remote" || "$AGENT_MODE" == "remote" ]]; then
  if [[ ! -f "$KEY" ]]; then
    echo "[!] SSH key not found at: $KEY" >&2
    echo "Provide a valid key via --ssh-key or ensure $DEFAULT_KEY exists." >&2
    exit 1
  fi

  if [ -z "${SSH_AUTH_SOCK:-}" ] || ! ssh-add -l >/dev/null 2>&1; then
    echo "[*] Starting ssh-agent and adding key: $KEY"
    eval "$(ssh-agent -s)"
    ssh-add "$KEY"
  else
    echo "[*] Reusing existing ssh-agent session; adding key: $KEY (if not already loaded)"
    ssh-add -l | grep -q "$(ssh-keygen -lf "$KEY" | awk '{print $2}')" || ssh-add "$KEY"
  fi

  ANSIBLE_VAULT_FLAG="--ask-vault-pass"
fi


EXTRA_VARS=(
  "-e" "scenario_name=${SCENARIO_NAME}"
  "-e" "agent_scope=${AGENT_MODE}"
  "-e" "manager_scope=${MANAGER_MODE}"
  "-e" "manager_bootstrap=$([[ "$MANAGER_MODE" == "remote" && "$MANAGER_EXISTS" == "false" ]] && echo true || echo false)"
)


echo "=== RADAR plan ==="
echo "Scenario         : $SCENARIO_NAME"
echo "Manager location : $MANAGER_MODE   (exists: $MANAGER_EXISTS)"
echo "Agents location  : $AGENT_MODE"
echo "Ansible limits   : ${LIMIT_MGR_GROUP}, ${LIMIT_AGENT_GROUP}"
echo "Vault prompt     : $([[ -n "$ANSIBLE_VAULT_FLAG" ]] && echo yes || echo no)"
echo "=================="


if [[ "$MANAGER_MODE" == "local" && "$MANAGER_EXISTS" == "false" ]]; then
  echo ">>> Bringing up local core stack (docker-compose.core.yml)..."
  docker compose -f docker-compose.core.yml up -d
  docker compose -f docker-compose.webhook.yml up -d
else
  echo ">>> Not touching local manager."
fi


if [[ "$AGENT_MODE" == "local" ]]; then
  echo ">>> Starting local agent container for scenario: $SCENARIO_NAME ($AGENT_SERVICE)"
  docker compose -f docker-compose.agents.yml up -d "$AGENT_SERVICE"
else
  echo ">>> Agents are remote; will not start local agent containers."
fi


if [[ -f Dockerfile.radar-cli ]]; then
  echo ">>> Building radar-cli image..."
  docker build -f Dockerfile.radar-cli -t radar-cli:latest .
fi

export $(grep -v '^#' .env | xargs)

echo ">>> Running Ansible (limit: ${LIMIT_MGR_GROUP}, ${LIMIT_AGENT_GROUP})..."
ansible-playbook -i inventory.yaml site.yaml \
  --limit "${LIMIT_MGR_GROUP}:${LIMIT_AGENT_GROUP}" \
  "${EXTRA_VARS[@]}" \
  ${ANSIBLE_VAULT_FLAG}
