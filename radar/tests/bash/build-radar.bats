#!/usr/bin/env bats

# Helper: print the captured log when an assertion fails
print_log() {
  echo
  echo "---- calls.log ----"
  if [[ -f "$LOG_DIR/calls.log" ]]; then
    cat "$LOG_DIR/calls.log"
  else
    echo "(no calls.log found)"
  fi
  echo "-------------------"
}

# Helper: assert a substring exists in calls.log
assert_in_log() {
  local needle="$1"
  if ! grep -Fq -- "$needle" "$LOG_DIR/calls.log"; then
    echo "Expected to find: $needle"
    print_log
    return 1
  fi
}

setup() {
  TEST_TMP="$(mktemp -d)"
  export LOG_DIR="$TEST_TMP"
  mkdir -p "$TEST_TMP"

  # fixtures so relative paths exist
  cp -r "${BATS_TEST_DIRNAME}/fixtures/." "$TEST_TMP/"

  # prepend our stubs
  export PATH="${BATS_TEST_DIRNAME}/stubs:${PATH}"

  # ensure script is executable
  SCRIPT="${BATS_TEST_DIRNAME}/../../build-radar.sh"
  chmod +x "$SCRIPT"

  # ensure a dummy ssh key exists for remote-mode tests (script checks file exists)
  export HOME="${TEST_TMP}/home"
  mkdir -p "$HOME/.ssh"
  : > "$HOME/.ssh/id_ed25519"

  # run from temp dir so relative paths resolve to fixtures
  pushd "$TEST_TMP" >/dev/null
  : > "$LOG_DIR/calls.log"
}

teardown() {
  popd >/dev/null
  rm -rf "$TEST_TMP"
}

@test "default: agents mode + suspicious_login" {
  run "${BATS_TEST_DIRNAME}/../../build-radar.sh" suspicious_login \
    --agent local \
    --manager local \
    --manager_exists false
  [ "$status" -eq 0 ] || { echo "status=$status"; echo "$output"; print_log; false; }

  # docker compose core up
  assert_in_log "docker compose -f docker-compose.core.yml -f volumes.yml up -d"

  # docker compose webhook up
  assert_in_log "docker compose -f docker-compose.webhook.yml up -d"

  # docker compose agents up
  assert_in_log "docker compose -f docker-compose.agents.yml up -d agent.suspicious"

  # ansible base invocation
  assert_in_log "ansible-playbook -i inventory.yaml site.yaml"

  # scenario var
  grep -Fq -- '-e scenario_name=suspicious_login' "$LOG_DIR/calls.log" \
    || { echo 'Missing -e scenario_name for suspicious_login'; print_log; false; }

  # limit group for local manager + container agents
  grep -Fq -- '--limit wazuh_manager_local:wazuh_agents_container' "$LOG_DIR/calls.log" \
    || grep -Fq -- '--limit "wazuh_manager_local:wazuh_agents_container"' "$LOG_DIR/calls.log" \
    || { echo 'Missing --limit for local manager + container agents'; print_log; false; }

}

@test "ssh mode switches limit and adds --ask-vault-pass" {
  run "${BATS_TEST_DIRNAME}/../../build-radar.sh" suspicious_login \
    --agent remote \
    --manager remote \
    --manager_exists true \
    --ssh-key "$HOME/.ssh/id_ed25519"
  [ "$status" -eq 0 ] || { echo "status=$status"; echo "$output"; print_log; false; }

  # should NOT start container agents
  if grep -Fq 'docker compose -f docker-compose.agents.yml up -d' "$LOG_DIR/calls.log"; then
    echo "agents.yml should not be started when --agent remote"
    print_log
    false
  fi

  # should NOT bring up local core/webhook stack when manager is remote
  if grep -Fq 'docker compose -f docker-compose.core.yml' "$LOG_DIR/calls.log"; then
    echo "core stack should not be started when --manager remote"
    print_log
    false
  fi
  if grep -Fq 'docker compose -f docker-compose.webhook.yml' "$LOG_DIR/calls.log"; then
    echo "webhook stack should not be started when --manager remote"
    print_log
    false
  fi

  # ansible base + scenario -e
  assert_in_log "ansible-playbook -i inventory.yaml site.yaml"
  grep -Fq -- 'scenario_name=suspicious_login' "$LOG_DIR/calls.log" \
    || { echo 'Missing -e scenario_name in remote mode'; print_log; false; }

  # correct limit group and vault prompt
  grep -Fq -- 'wazuh_manager_ssh:wazuh_agents_ssh' "$LOG_DIR/calls.log" \
    || { echo 'Missing remote ssh limit group'; print_log; false; }
  grep -Fq -- '--ask-vault-pass' "$LOG_DIR/calls.log" \
    || { echo 'Missing --ask-vault-pass in remote mode'; print_log; false; }
}

@test "custom scenario propagates" {
  run "${BATS_TEST_DIRNAME}/../../build-radar.sh" insider_threat \
    --agent local \
    --manager local \
    --manager_exists false
  [ "$status" -eq 0 ] || { echo "status=$status"; echo "$output"; print_log; false; }

  assert_in_log "ansible-playbook -i inventory.yaml site.yaml"
  grep -Fq -- 'scenario_name=insider_threat' "$LOG_DIR/calls.log" \
    || { echo 'Missing scenario_name for insider_threat'; print_log; false; }

  grep -Fq -- 'wazuh_manager_local:wazuh_agents_container' "$LOG_DIR/calls.log" \
    || { echo 'Missing local/container limit group'; print_log; false; }
}

@test "shellcheck (informational)" {
  shellcheck "${BATS_TEST_DIRNAME}/../../build-radar.sh" || true
}
