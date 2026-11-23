#!/usr/bin/env bats
# Unit tests for radar-agent/helpers/ar-dispatch.sh, run against a sandboxed
# copy of /var/ossec/radar-agent (no root needed).

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  AGENT_DIR="${REPO_ROOT}/radar-agent"
  TMP="$(mktemp -d)"
  ME="$(id -u)"
  AGENT_HOME="$TMP/radar-agent"
  LOG="$TMP/active-responses.log"
  BIN="$TMP/bin"

  mkdir -p "$AGENT_HOME/helpers" "$AGENT_HOME/active_responses" "$BIN"
  cp "$AGENT_DIR/helpers/ar-mapping.sh" "$AGENT_DIR/helpers/ar-dispatch.sh" "$AGENT_HOME/helpers/"
  cat > "$AGENT_HOME/ar-scripts.yaml" <<'EOF'
scripts:
  echo_ar.sh: active_responses/echo_ar_v1.sh
EOF
  add_script echo_ar_v1.sh 'echo "v1 args=[$*] stdin=[$(cat)]"; exit 7'
  add_script echo_ar_v2.sh 'echo "v2 args=[$*] stdin=[$(cat)]"; exit 0'
  chmod 0750 "$AGENT_HOME" "$AGENT_HOME/helpers" "$AGENT_HOME/active_responses"
  chmod 0640 "$AGENT_HOME/ar-scripts.yaml" "$AGENT_HOME"/helpers/*.sh
}

teardown() {
  rm -rf "$TMP"
}

add_script() {
  printf '#!/usr/bin/env bash\n%s\n' "$2" > "$AGENT_HOME/active_responses/$1"
  chmod 0750 "$AGENT_HOME/active_responses/$1"
}

# Installs the dispatcher under <name>, pointed at the sandbox, as
# bootstrap-agent.sh does under /var/ossec/active-response/bin.
install_dispatcher() {
  sed -e "s#^RADAR_AGENT_HOME=.*#RADAR_AGENT_HOME=\"$AGENT_HOME\"#" \
      -e "s#^LOG_FILE=.*#LOG_FILE=\"$LOG\"#" \
      -e "s#^TRUSTED_UID=.*#TRUSTED_UID=$ME#" \
      "$AGENT_DIR/helpers/ar-dispatch.sh" > "$BIN/$1"
  chmod 0750 "$BIN/$1"
}

@test "execs the mapped script with the same stdin and arguments, and returns its exit code" {
  install_dispatcher echo_ar.sh
  run bash -c "echo '{\"command\":\"add\"}' | '$BIN/echo_ar.sh' a b"
  [ "$status" -eq 7 ]
  [ "$output" = 'v1 args=[a b] stdin=[{"command":"add"}]' ]
  grep -q "\[ar-dispatch:echo_ar.sh\] dispatching to active_responses/echo_ar_v1.sh" "$LOG"
}

@test "a catalog change takes effect on the next run without reinstalling" {
  install_dispatcher echo_ar.sh
  run bash -c "echo x | '$BIN/echo_ar.sh'"
  [[ "$output" == v1* ]]
  sed -i 's/echo_ar_v1/echo_ar_v2/' "$AGENT_HOME/ar-scripts.yaml"
  run bash -c "echo x | '$BIN/echo_ar.sh'"
  [ "$status" -eq 0 ]
  [[ "$output" == v2* ]]
}

@test "an edited script takes effect on the next run without reinstalling" {
  install_dispatcher echo_ar.sh
  add_script echo_ar_v1.sh 'echo patched'
  run bash -c "'$BIN/echo_ar.sh' </dev/null"
  [ "$output" = "patched" ]
}

@test "an unmapped name is refused and logged" {
  install_dispatcher other_ar.sh
  run bash -c "echo x | '$BIN/other_ar.sh'"
  [ "$status" -eq 1 ]
  [ -z "$output" ]
  grep -q "no script mapped for active response 'other_ar.sh'" "$LOG"
  grep -q "refusing: no trusted script resolved for 'other_ar.sh'" "$LOG"
}

@test "a missing radar-agent home is refused and logged" {
  install_dispatcher echo_ar.sh
  rm -rf "$AGENT_HOME"
  run bash -c "echo x | '$BIN/echo_ar.sh'"
  [ "$status" -eq 1 ]
  grep -q "refusing: $AGENT_HOME is missing" "$LOG"
}

@test "a writable library is refused before it is sourced" {
  install_dispatcher echo_ar.sh
  echo 'echo SOURCED > "'"$TMP"'/sourced"' >> "$AGENT_HOME/helpers/ar-mapping.sh"
  chmod g+w "$AGENT_HOME/helpers/ar-mapping.sh"
  run bash -c "echo x | '$BIN/echo_ar.sh'"
  [ "$status" -eq 1 ]
  [ ! -e "$TMP/sourced" ]
  grep -q "refusing: $AGENT_HOME/helpers/ar-mapping.sh" "$LOG"
}

@test "a broken catalog is refused and logged, nothing runs" {
  install_dispatcher echo_ar.sh
  printf 'scripts:\n  echo_ar.sh: /tmp/elsewhere.sh\n' > "$AGENT_HOME/ar-scripts.yaml"
  run bash -c "echo x | '$BIN/echo_ar.sh'"
  [ "$status" -eq 1 ]
  [[ "$output" != v1* ]]
  grep -q "invalid script path" "$LOG"
}

@test "each installed copy dispatches by its own file name" {
  install_dispatcher echo_ar.sh
  add_script other_v1.sh 'echo other'
  printf 'scripts:\n  echo_ar.sh: active_responses/echo_ar_v1.sh\n  other.sh: active_responses/other_v1.sh\n' > "$AGENT_HOME/ar-scripts.yaml"
  cp "$BIN/echo_ar.sh" "$BIN/other.sh"
  run bash -c "'$BIN/other.sh' </dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "other" ]
}

@test "a writable target script is refused and not run" {
  install_dispatcher echo_ar.sh
  chmod o+w "$AGENT_HOME/active_responses/echo_ar_v1.sh"
  run bash -c "echo x | '$BIN/echo_ar.sh'"
  [ "$status" -eq 1 ]
  [[ "$output" != v1* ]]
  grep -q "not group/world-writable" "$LOG"
}

@test "end to end: the shipped lock_user_linux_v1.sh runs through the dispatcher" {
  command -v jq >/dev/null 2>&1 || skip "jq not installed"
  cp "$AGENT_DIR/ar-scripts.yaml" "$AGENT_HOME/ar-scripts.yaml"
  install -m 0750 "$AGENT_DIR/active_responses/lock_user_linux_v1.sh" "$AGENT_HOME/active_responses/"
  sed -i "s#^LOG_FILE=.*#LOG_FILE=\"$LOG\"#" "$AGENT_HOME/active_responses/lock_user_linux_v1.sh"
  install_dispatcher lock_user_linux.sh

  # uid 0 is always refused by the script itself, so nothing is locked.
  run bash -c "echo '{\"command\":\"add\",\"parameters\":{\"extra_args\":[\"root\"]}}' | '$BIN/lock_user_linux.sh'"
  [ "$status" -eq 1 ]
  grep -q "dispatching to active_responses/lock_user_linux_v1.sh" "$LOG"
  grep -q "\[lock_user_linux\] refusing: 'root' is a system account" "$LOG"
}

@test "shellcheck (informational)" {
  shellcheck -x "${AGENT_DIR}/helpers/ar-dispatch.sh" || true
}
