#!/usr/bin/env bats

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"

  TMPDIR="$(mktemp -d)"
  BIN_DIR="${TMPDIR}/bin"
  mkdir -p "${BIN_DIR}"

  export PATH="${BIN_DIR}:${PATH}"

  DOCKER_LOG="${TMPDIR}/docker.log"
  ANSIBLE_LOG="${TMPDIR}/ansible.log"

  cat > "${BIN_DIR}/docker" <<EOF
#!/usr/bin/env bash
echo "docker \$*" >> "${DOCKER_LOG}"
exit 0
EOF
  chmod +x "${BIN_DIR}/docker"

  cat > "${BIN_DIR}/ansible-playbook" <<EOF
#!/usr/bin/env bash
echo "ansible-playbook \$*" >> "${ANSIBLE_LOG}"
exit 0
EOF
  chmod +x "${BIN_DIR}/ansible-playbook"

  cat > "${BIN_DIR}/ssh-agent" <<'EOF'
#!/usr/bin/env bash
echo "SSH_AUTH_SOCK=/tmp/fake; export SSH_AUTH_SOCK;"
EOF
  chmod +x "${BIN_DIR}/ssh-agent"

  cat > "${BIN_DIR}/ssh-add" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${BIN_DIR}/ssh-add"

  cat > "${BIN_DIR}/ssh-keygen" <<'EOF'
#!/usr/bin/env bash
echo "256 SHA256:dummy key"
EOF
  chmod +x "${BIN_DIR}/ssh-keygen"

  mkdir -p "${REPO_ROOT}/roles/wazuh_agent/playbooks"
  [[ -f "${REPO_ROOT}/roles/wazuh_agent/playbooks/simulate.yml" ]] || echo "- hosts: all
  tasks: []" > "${REPO_ROOT}/roles/wazuh_agent/playbooks/simulate.yml"

  [[ -f "${REPO_ROOT}/inventory.yaml" ]] || echo "all:
  hosts: {}" > "${REPO_ROOT}/inventory.yaml"

  mkdir -p "${REPO_ROOT}/radar-test-framework/simulate/scenarios"
  [[ -d "${REPO_ROOT}/radar-test-framework/simulate/scenarios" ]] || true

  # root config.yaml used by simulate-radar.sh create only if missing
  CONFIG_YAML_CREATED=false
  if [[ ! -f "${REPO_ROOT}/config.yaml" ]]; then
    printf 'geoip_detection:\n  container_name: agent.geoip\n' > "${REPO_ROOT}/config.yaml"
    CONFIG_YAML_CREATED=true
  fi

  SSH_KEY="${TMPDIR}/id_ed25519"
  echo "dummy" > "${SSH_KEY}"
}

teardown() {
  [[ "${CONFIG_YAML_CREATED}" == "true" ]] && rm -f "${REPO_ROOT}/config.yaml"
  rm -rf "${TMPDIR}"
}

@test "missing scenario fails" {
  run bash "${REPO_ROOT}/simulate-radar.sh"
  [ "$status" -ne 0 ]
}

@test "invalid scenario fails" {
  run bash "${REPO_ROOT}/simulate-radar.sh" nope --agent local
  [ "$status" -ne 0 ]
}

@test "missing --agent fails" {
  run bash "${REPO_ROOT}/simulate-radar.sh" geoip_detection
  [ "$status" -ne 0 ]
}

@test "local agent uses docker with container from config.yaml" {
  run bash "${REPO_ROOT}/simulate-radar.sh" geoip_detection --agent local
  [ "$status" -eq 0 ]

  # ensure docker was invoked and container name used
  run bash -c "cat '${DOCKER_LOG}'"
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker exec -i agent.geoip"* ]]
  [[ "$output" == *"docker cp"* ]]
}

@test "remote agent uses ansible-playbook with limit and extra vars" {
  run bash "${REPO_ROOT}/simulate-radar.sh" suspicious_login --agent remote --ssh-key "${SSH_KEY}"
  [ "$status" -eq 0 ]

  run bash -c "cat '${ANSIBLE_LOG}'"
  [ "$status" -eq 0 ]
  [[ "$output" == *"--limit wazuh_agents_ssh"* ]]
  [[ "$output" == *"radar_simulate_scenario=suspicious_login"* ]]
}