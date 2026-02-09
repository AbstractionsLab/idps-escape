#!/usr/bin/env bash
set -Eeuo pipefail

# Usage:
#   ./stop-radar.sh --manager <local|remote> --agent <local|remote> [--purge] [--disable-wazuh-agent]
# Examples:
#   ./stop-radar.sh --manager local --agent remote --purge
#   ./stop-radar.sh --manager remote --agent remote --disable-wazuh-agent
#   ./stop-radar.sh --manager remote --agent remote

DOCKER_BIN="${DOCKER_BIN:-docker}"
ANSIBLE_BIN="${ANSIBLE_BIN:-ansible-playbook}"
PROJECT="${PROJECT:-soar-radar}"
CORE_COMPOSE="${CORE_COMPOSE:-docker-compose.core.yml}"
WEBHOOK_COMPOSE="${WEBHOOK_COMPOSE:-docker-compose.webhook.yml}"
AGENTS_COMPOSE="${AGENTS_COMPOSE:-docker-compose.agents.yml}"
INVENTORY="${INVENTORY:-inventory.yaml}"
STOP_MANAGER_PLAYBOOK="${STOP_MANAGER_PLAYBOOK:-roles/wazuh_manager/playbooks/stop_manager.yml}"
STOP_AGENTS_PLAYBOOK="${STOP_AGENTS_PLAYBOOK:-roles/wazuh_agent/playbooks/stop_agents.yml}"

MANAGER_MODE=""
AGENTS_MODE=""
PURGE=false
DISABLE_WAZUH_AGENT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager)
      if [[ -z "${2:-}" || "$2" == --* ]]; then
        echo "ERROR: --manager requires argument: local or remote" >&2
        exit 1
      fi
      if [[ "$2" != "local" && "$2" != "remote" ]]; then
        echo "ERROR: --manager must be 'local' or 'remote', got: $2" >&2
        exit 1
      fi
      MANAGER_MODE="$2"
      shift 2
      ;;
    --agent)
      if [[ -z "${2:-}" || "$2" == --* ]]; then
        echo "ERROR: --agent requires argument: local or remote" >&2
        exit 1
      fi
      if [[ "$2" != "local" && "$2" != "remote" ]]; then
        echo "ERROR: --agent must be 'local' or 'remote', got: $2" >&2
        exit 1
      fi
      AGENTS_MODE="$2"
      shift 2
      ;;
    --purge)
      PURGE=true
      shift
      ;;
    --disable-wazuh-agent)
      DISABLE_WAZUH_AGENT=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 --manager <local|remote> --agent <local|remote> [--purge] [--disable-wazuh-agent]" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$MANAGER_MODE" ]]; then
  echo "ERROR: --manager <local|remote> is required" >&2
  echo "Usage: $0 --manager <local|remote> --agent <local|remote> [--purge] [--disable-wazuh-agent]" >&2
  exit 1
fi

echo "========================================="
echo "RADAR Stop Plan"
echo "========================================="
echo "Manager mode:   $MANAGER_MODE"
echo "Agents mode:    $AGENTS_MODE"
echo "Purge volumes:  $PURGE"
echo "Disable Wazuh agent: $DISABLE_WAZUH_AGENT"
echo "========================================="


DEFAULT_KEY="$HOME/.ssh/id_ed25519"
KEY="${SSH_KEY:-$DEFAULT_KEY}"

ANSIBLE_VAULT_FLAG=""
if [[ "$MANAGER_MODE" == "remote" || "$AGENTS_MODE" == "remote" ]]; then
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

stop_local_manager() {
  echo ""
  echo ">>> Stopping LOCAL manager..."
  
  PURGE_FLAGS=()
  [[ "$PURGE" == true ]] && PURGE_FLAGS+=("-v")
  
  if [[ -f "$WEBHOOK_COMPOSE" ]]; then
    echo ">>> Stopping webhook..."
    "$DOCKER_BIN" compose -p "$PROJECT" -f "$WEBHOOK_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"
  else
    echo ">>> Skip webhook: $WEBHOOK_COMPOSE not found"
  fi
  
  if [[ -f "$CORE_COMPOSE" ]]; then
    echo ">>> Stopping core stack..."
    "$DOCKER_BIN" compose -p "$PROJECT" -f "$CORE_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"
  else
    echo ">>> Skip core: $CORE_COMPOSE not found"
  fi
  
  echo ">>> Local manager stopped successfully"
}

stop_remote_manager() {
  echo ""
  echo ">>> Stopping REMOTE manager via Ansible..."
  
  if [[ ! -f "$INVENTORY" ]]; then
    echo "ERROR: Inventory file not found: $INVENTORY" >&2
    exit 1
  fi
  
  if [[ ! -f "$STOP_MANAGER_PLAYBOOK" ]]; then
    echo "ERROR: Stop manager playbook not found: $STOP_MANAGER_PLAYBOOK" >&2
    exit 1
  fi
  
  "$ANSIBLE_BIN" -i "$INVENTORY" "$STOP_MANAGER_PLAYBOOK" \
    -e "purge_volumes=$PURGE" \
    -e "ansible_python_interpreter=auto" \
    ${ANSIBLE_VAULT_FLAG}
  
  if [[ $? -eq 0 ]]; then
    echo ">>> Remote manager stopped successfully"
  else
    echo "ERROR: Failed to stop remote manager" >&2
    exit 1
  fi
}

stop_local_agents() {
  echo ""
  echo ">>> Stopping LOCAL container agents..."
  
  if [[ ! -f "$AGENTS_COMPOSE" ]]; then
    echo ">>> Skip agents: $AGENTS_COMPOSE not found"
    return 0
  fi
  
  PURGE_FLAGS=()
  [[ "$PURGE" == true ]] && PURGE_FLAGS+=("-v")
  
  "$DOCKER_BIN" compose -p "$PROJECT" -f "$AGENTS_COMPOSE" down --remove-orphans "${PURGE_FLAGS[@]}"
  if [[ "$DISABLE_WAZUH_AGENT" == true ]]; then
    echo ">>> NOTE: --disable-wazuh-agent only applies to remote SSH agents, not container agents"
  fi
  echo ">>> Local agents stopped successfully"
}

stop_remote_agents() {
  echo ""
  echo ">>> Stopping REMOTE agents via Ansible..."
  
  if [[ ! -f "$INVENTORY" ]]; then
    echo "ERROR: Inventory file not found: $INVENTORY" >&2
    exit 1
  fi
  
  if [[ ! -f "$STOP_AGENTS_PLAYBOOK" ]]; then
    echo "ERROR: Stop agents playbook not found: $STOP_AGENTS_PLAYBOOK" >&2
    exit 1
  fi

  "$ANSIBLE_BIN" -i "$INVENTORY" "$STOP_AGENTS_PLAYBOOK" \
    -e "ansible_python_interpreter=auto" \
    -e "disable_wazuh_agent=$DISABLE_WAZUH_AGENT" \
    ${ANSIBLE_VAULT_FLAG}

  if [[ $? -eq 0 ]]; then
    echo ">>> Remote agents stopped successfully"
  else
    echo "ERROR: Failed to stop remote agents" >&2
    exit 1
  fi
}

case "$MANAGER_MODE" in
  local)
    stop_local_manager
    ;;
  remote)
    stop_remote_manager
    ;;
esac

if [[ -n "$AGENTS_MODE" ]]; then
  case "$AGENTS_MODE" in
    local)
      stop_local_agents
      ;;
    remote)
      stop_remote_agents
      ;;
  esac
fi
