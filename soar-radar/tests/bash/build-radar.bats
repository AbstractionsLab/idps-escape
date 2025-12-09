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

  # run from temp dir so relative paths resolve to fixtures
  pushd "$TEST_TMP" >/dev/null
  : > "$LOG_DIR/calls.log"
}

teardown() {
  popd >/dev/null
  rm -rf "$TEST_TMP"
}

@test "default: agents mode + suspicious_login" {
  run "${BATS_TEST_DIRNAME}/../../build-radar.sh"
  [ "$status" -eq 0 ]

  # docker compose core up
  assert_in_log "docker compose -f docker-compose.core.yml up -d"

  # docker compose agents up
  assert_in_log "docker compose -f docker-compose.agents.yml up -d"

  # ansible base invocation
  assert_in_log "ansible-playbook -i inventory.yaml site.yaml"

  # scenario -e is present (quotes may be collapsed by shell, so test both)
  grep -Fq -- '-e scenario_name="suspicious_login"' "$LOG_DIR/calls.log" \
    || grep -Fq -- "-e scenario_name=suspicious_login" "$LOG_DIR/calls.log" \
    || { echo 'Missing -e scenario_name for suspicious_login'; print_log; false; }

  # limit group (quotes may or may not be present)
  grep -Fq -- '--limit wazuh_manager:wazuh_agents_container' "$LOG_DIR/calls.log" \
    || grep -Fq -- '--limit "wazuh_manager:wazuh_agents_container"' "$LOG_DIR/calls.log" \
    || { echo 'Missing --limit for container agents'; print_log; false; }

  # final docker build
  assert_in_log "docker build -f Dockerfile.radar-cli -t radar-cli:latest ."
}

@test "ssh mode switches limit and adds --ask-vault-pass" {
  run "${BATS_TEST_DIRNAME}/../../build-radar.sh" suspicious_login --ssh
  [ "$status" -eq 0 ]

  # should NOT start container agents
  if grep -Fq 'docker compose -f docker-compose.agents.yml up -d' "$LOG_DIR/calls.log"; then
    echo "agents.yml should not be started in --ssh mode"
    print_log
    false
  fi

  # ansible base + scenario -e
  assert_in_log "ansible-playbook -i inventory.yaml site.yaml"
  grep -Fq -- 'scenario_name="suspicious_login"' "$LOG_DIR/calls.log" \
    || grep -Fq -- "scenario_name=suspicious_login" "$LOG_DIR/calls.log" \
    || { echo 'Missing -e scenario_name in ssh mode'; print_log; false; }

  # correct limit group and vault prompt
  grep -Fq -- 'wazuh_manager:wazuh_agents_ssh' "$LOG_DIR/calls.log" \
    || { echo 'Missing ssh limit group'; print_log; false; }
  grep -Fq -- '--ask-vault-pass' "$LOG_DIR/calls.log" \
    || { echo 'Missing --ask-vault-pass in ssh mode'; print_log; false; }
}

@test "custom scenario propagates" {
  run "${BATS_TEST_DIRNAME}/../../build-radar.sh" insider_threat
  [ "$status" -eq 0 ]

  assert_in_log "ansible-playbook -i inventory.yaml site.yaml"
  grep -Fq -- 'scenario_name="insider_threat"' "$LOG_DIR/calls.log" \
    || grep -Fq -- "scenario_name=insider_threat" "$LOG_DIR/calls.log" \
    || { echo 'Missing scenario_name for insider_threat'; print_log; false; }
  grep -Fq -- 'wazuh_manager:wazuh_agents_container' "$LOG_DIR/calls.log" \
    || { echo 'Missing container limit group'; print_log; false; }
}

@test "shellcheck (informational)" {
  shellcheck "${BATS_TEST_DIRNAME}/../../build-radar.sh" || true
}
