#!/usr/bin/env bats
setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/bootstrap-agent.sh"
}

# --- argument validation (no root needed, no filesystem writes) -----------

@test "no arguments prints usage and exits 2" {
  run bash "$SCRIPT"
  [ "$status" -eq 2 ]
  [[ "$output" == *"Usage:"* ]]
}

@test "--help exits 0 and prints usage" {
  run bash "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage:"* ]]
}

@test "missing --manager is rejected" {
  run bash "$SCRIPT" --token abc --group default
  [ "$status" -eq 2 ]
  [[ "$output" == *"--manager is required"* ]]
}

@test "missing --token is rejected" {
  run bash "$SCRIPT" --manager 10.0.0.5 --group default
  [ "$status" -eq 2 ]
  [[ "$output" == *"--token is required"* ]]
}

@test "unknown flag is rejected with usage" {
  run bash "$SCRIPT" --manager 10.0.0.5 --token abc --group default --bogus
  [ "$status" -eq 2 ]
  [[ "$output" == *"Unknown option"* ]]
}

@test "non-root invocation is rejected, even with all required args present" {
  if ! command -v runuser >/dev/null 2>&1 || ! id nobody >/dev/null 2>&1; then
    skip "no unprivileged user / runuser available to exercise this as non-root"
  fi
  run runuser -u nobody -- bash "$SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"run this as root"* ]]
}

_require_root_for_fake_root_tests() {
  if [[ "$(id -u)" -ne 0 ]]; then
    skip "these tests write to a fake /var/ossec and need root to chown root:wazuh"
  fi
  if ! getent group wazuh >/dev/null 2>&1; then
    skip "no 'wazuh' group on this host -- create one to run these tests (groupadd wazuh)"
  fi
}

_setup_fake_root() {
  FAKE_ROOT="$(mktemp -d)"
  mkdir -p "$FAKE_ROOT/var/ossec/etc" "$FAKE_ROOT/var/ossec/bin" "$FAKE_ROOT/var/ossec/logs"

  SANDBOXED_SCRIPT="$FAKE_ROOT/bootstrap-agent.sh"
  sed "s#/var/ossec#${FAKE_ROOT}/var/ossec#g" "$SCRIPT" > "$SANDBOXED_SCRIPT"
  chmod +x "$SANDBOXED_SCRIPT"

  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  cat > "$FAKE_ROOT/var/ossec/etc/ossec.conf" <<'EOF'
<ossec_config>
  <client>
    <server>
      <address>OLD_MANAGER</address>
    </server>
  </client>
</ossec_config>
EOF

  BIN_DIR="$FAKE_ROOT/bin"
  mkdir -p "$BIN_DIR"
  cat > "${BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${BIN_DIR}/systemctl"

  cat > "${BIN_DIR}/apt-mark" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "${FAKE_ROOT}/apt-mark.calls"
exit 0
EOF
  chmod +x "${BIN_DIR}/apt-mark"

  export PATH="${BIN_DIR}:${PATH}"
}

teardown() {
  if [[ -n "${FAKE_ROOT:-}" ]]; then
    rm -rf "$FAKE_ROOT"
  fi
}

@test "comma-separated --group and repeated --group both contribute, with no duplicates lost" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group default,suspicious_login --group log_volume --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"Groups   : default suspicious_login log_volume"* ]]
}

@test "writes terminate_service.sh for log_volume; suspicious_login needs no custom script" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group suspicious_login,log_volume --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK - installed terminate_service.sh"* ]]
  [ -x "$FAKE_ROOT/var/ossec/active-response/bin/terminate_service.sh" ]
  [ ! -e "$FAKE_ROOT/var/ossec/active-response/bin/lock_user_linux.sh" ]
}

@test "writes no active response script for a group that needs none" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"no active response script needed"* ]]
  [ ! -e "$FAKE_ROOT/var/ossec/active-response/bin/lock_user_linux.sh" ]
}

@test "updates the <address> tag in ossec.conf to the given manager" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 203.0.113.9 --token abc --group default
  [ "$status" -eq 0 ]
  run cat "$FAKE_ROOT/var/ossec/etc/ossec.conf"
  [[ "$output" == *"<address>203.0.113.9</address>"* ]]
  [[ "$output" != *"OLD_MANAGER"* ]]
}

@test "fails clearly when ossec.conf has no <address> tag to patch" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  echo "<ossec_config></ossec_config>" > "$FAKE_ROOT/var/ossec/etc/ossec.conf"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"no <address> tag found"* ]]
}

@test "already-enrolled agent (non-empty client.keys) skips agent-auth" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  echo "001 edge.vm NULL deadbeef" > "$FAKE_ROOT/var/ossec/etc/client.keys"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"already enrolled, skipping agent-auth"* ]]
}

@test "a fresh enrollment prints per-group agent_groups confirmation commands" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  # Simulate agent-auth writing client.keys on a real successful enrollment.
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<EOF
#!/usr/bin/env bash
echo "001 edge.vm NULL deadbeef" > "${FAKE_ROOT}/var/ossec/etc/client.keys"
exit 0
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group default --group suspicious_login,log_volume --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"=== SUCCESS ==="* ]]
  [[ "$output" == *"agent_groups -a -q -i 001 -g default"* ]]
  [[ "$output" == *"agent_groups -a -q -i 001 -g suspicious_login"* ]]
  [[ "$output" == *"agent_groups -a -q -i 001 -g log_volume"* ]]
}

@test "'Duplicate agent name' from agent-auth is treated as success, not failure" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<'EOF'
#!/usr/bin/env bash
echo "ERROR: Duplicate agent name" >&2
exit 1
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK - agent name already registered"* ]]
}

@test "'Invalid password' from agent-auth fails with a token/reachability hint" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<'EOF'
#!/usr/bin/env bash
echo "ERROR: Invalid password" >&2
exit 1
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token wrong --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"enrollment rejected by manager"* ]]
  [[ "$output" == *"10.0.0.5:1515 is reachable"* ]]
}

@test "an unrecognized agent-auth failure surfaces the raw stderr and fails" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<'EOF'
#!/usr/bin/env bash
echo "some unexpected low-level error" >&2
exit 1
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"some unexpected low-level error"* ]]
  [[ "$output" == *"agent-auth failed"* ]]
}

@test "pins wazuh-agent via apt-mark hold, and reports success" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"Pinning wazuh-agent"* ]]
  [[ "$output" == *"OK - wazuh-agent held"* ]]
  [ -f "$FAKE_ROOT/apt-mark.calls" ]
  grep -q "^hold wazuh-agent$" "$FAKE_ROOT/apt-mark.calls"
}

@test "an already-installed agent still gets pinned (pin step is unconditional)" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  # agent-auth already present in the fake root -- install step is skipped.

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"Wazuh agent already installed, skipping package install"* ]]
  [[ "$output" == *"OK - wazuh-agent held"* ]]
}

@test "apt-mark hold failure warns clearly but does not fail the whole run" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  cat > "${BIN_DIR}/apt-mark" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod +x "${BIN_DIR}/apt-mark"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING: 'apt-mark hold wazuh-agent' failed"* ]]
  [[ "$output" == *"=== SUCCESS ==="* ]]
}

@test "shellcheck (informational)" {
  shellcheck "$SCRIPT" || true
}
