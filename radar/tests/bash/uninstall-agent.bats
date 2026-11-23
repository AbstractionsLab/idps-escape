#!/usr/bin/env bats
# Tests for radar-agent/uninstall-agent.sh against a sandboxed endpoint: the
# real bootstrap-agent.sh installs into a fake root first, then the
# uninstaller removes it. Package managers and systemctl are stubbed.

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  AGENT_DIR="${REPO_ROOT}/radar-agent"
}

teardown() {
  if [[ -n "${FAKE_ROOT:-}" ]]; then
    rm -rf "$FAKE_ROOT"
  fi
}

_require_root() {
  [[ "$(id -u)" -eq 0 ]] || skip "needs root to chown root:wazuh in the sandbox"
  getent group wazuh >/dev/null 2>&1 || skip "no 'wazuh' group on this host (groupadd wazuh)"
}

_sandbox() {
  FAKE_ROOT="$(mktemp -d)"
  SANDBOX_AGENT_DIR="$FAKE_ROOT/radar-agent"
  cp -r "$AGENT_DIR" "$SANDBOX_AGENT_DIR"
  AR_BIN="$FAKE_ROOT/var/ossec/active-response/bin"
  mkdir -p "$FAKE_ROOT/var/ossec/etc" "$FAKE_ROOT/var/ossec/bin" "$FAKE_ROOT/var/ossec/logs" \
           "$FAKE_ROOT/usr/local/bin" "$FAKE_ROOT/etc/systemd/system" "$FAKE_ROOT/etc/logrotate.d" \
           "$FAKE_ROOT/var/log" "$FAKE_ROOT/etc/apt/sources.list.d" "$FAKE_ROOT/usr/share/keyrings" \
           "$FAKE_ROOT/etc/yum.repos.d"
  local f
  while IFS= read -r -d '' f; do
    sed -i -e "s#/var/ossec#${FAKE_ROOT}/var/ossec#g" \
           -e "s#/usr/local/bin/radar-#${FAKE_ROOT}/usr/local/bin/radar-#g" \
           -e "s#/etc/systemd/system/radar-#${FAKE_ROOT}/etc/systemd/system/radar-#g" \
           -e "s#/etc/logrotate.d/radar-#${FAKE_ROOT}/etc/logrotate.d/radar-#g" \
           -e "s#/var/log/radar#${FAKE_ROOT}/var/log/radar#g" \
           -e "s#/var/lib/radar-agent#${FAKE_ROOT}/var/lib/radar-agent#g" \
           -e "s#\"/usr/local/bin\"#\"${FAKE_ROOT}/usr/local/bin\"#g" \
           -e "s#\"/etc/systemd/system\"#\"${FAKE_ROOT}/etc/systemd/system\"#g" \
           -e "s#\"/etc/logrotate.d\"#\"${FAKE_ROOT}/etc/logrotate.d\"#g" \
           -e "s#/etc/apt/sources.list.d#${FAKE_ROOT}/etc/apt/sources.list.d#g" \
           -e "s#/usr/share/keyrings#${FAKE_ROOT}/usr/share/keyrings#g" \
           -e "s#/etc/yum.repos.d#${FAKE_ROOT}/etc/yum.repos.d#g" \
           "$f"
  done < <(find "$SANDBOX_AGENT_DIR" -name '*.sh' -type f -print0)

  printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE_ROOT/var/ossec/bin/agent-auth"
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"
  printf '<ossec_config><client><server><address>OLD</address></server></client></ossec_config>\n' \
    > "$FAKE_ROOT/var/ossec/etc/ossec.conf"

  BIN_DIR="$FAKE_ROOT/stub"
  mkdir -p "$BIN_DIR"
  local c
  for c in systemctl apt-mark apt-get; do
    cat > "$BIN_DIR/$c" <<EOF
#!/usr/bin/env bash
echo "$c \$*" >> "${FAKE_ROOT}/calls"
exit 0
EOF
    chmod +x "$BIN_DIR/$c"
  done
  # The package reports itself as removed once apt-get has run.
  cat > "$BIN_DIR/dpkg-query" <<'EOF'
#!/usr/bin/env bash
echo -n "not-installed"
EOF
  chmod +x "$BIN_DIR/dpkg-query"
  export PATH="$BIN_DIR:$PATH"
}

_bootstrap() {
  run bash "$SANDBOX_AGENT_DIR/bootstrap-agent.sh" --manager 10.0.0.5 --token abc "$@"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "--help prints usage" {
  run bash "$AGENT_DIR/uninstall-agent.sh" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage:"* ]]
  [[ "$output" == *"--purge-data"* ]]
}

@test "removes installed collectors, keeps unrelated units and binaries" {
  _require_root
  _sandbox
  _bootstrap --group log_volume,linux_resource_utilization
  [ -f "$FAKE_ROOT/etc/systemd/system/radar-log-volume.timer" ]
  touch "$FAKE_ROOT/etc/systemd/system/sshd.service" "$FAKE_ROOT/usr/local/bin/other-tool"

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK - removed the log_volume metric collector (4 files)"* ]]
  [[ "$output" == *"OK - removed the linux_resource_utilization metric collector (4 files)"* ]]
  [ -z "$(ls -A "$FAKE_ROOT/etc/logrotate.d")" ]
  [ "$(ls "$FAKE_ROOT/etc/systemd/system")" = "sshd.service" ]
  [ "$(ls "$FAKE_ROOT/usr/local/bin")" = "other-tool" ]
  grep -qx "systemctl stop radar-log-volume.timer" "$FAKE_ROOT/calls"
  grep -qx "systemctl disable radar-linux-resource-utilization.timer" "$FAKE_ROOT/calls"
}

@test "collected metrics are kept unless --purge-data" {
  _require_root
  _sandbox
  _bootstrap --group log_volume
  echo x > "$FAKE_ROOT/var/log/radar/log_volume_metric.log"

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 0 ]
  [ -f "$FAKE_ROOT/var/log/radar/log_volume_metric.log" ]

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh" --purge-data
  [ "$status" -eq 0 ]
  [ ! -e "$FAKE_ROOT/var/log/radar" ]
  [ ! -e "$FAKE_ROOT/var/ossec" ]
}

@test "removes RADAR dispatchers, the radar-agent home and the allowlist, nothing else in bin" {
  _require_root
  _sandbox
  _bootstrap --group suspicious_login --allow-service nginx
  [ -x "$AR_BIN/lock_user_linux.sh" ]
  printf '#!/bin/sh\nexit 0\n' > "$AR_BIN/firewall-drop"

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK - removed lock_user_linux.sh"* ]]
  [[ "$output" == *"OK - removed terminate_service.sh"* ]]
  [ ! -e "$AR_BIN/lock_user_linux.sh" ]
  [ ! -e "$AR_BIN/terminate_service.sh" ]
  [ -f "$AR_BIN/firewall-drop" ]
  [ ! -e "$FAKE_ROOT/var/ossec/radar-agent" ]
  [ ! -e "$FAKE_ROOT/var/ossec/etc/radar-terminable-services" ]
}

@test "an endpoint with nothing RADAR-specific installed uninstalls cleanly" {
  _require_root
  _sandbox
  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 0 ]
  [[ "$output" != *"metric collector"* ]]
  [[ "$output" == *"=== Uninstall complete ==="* ]]
  [[ "$output" == *"tick 'Replace the existing agent'"* ]]
}

@test "refuses to run from an incomplete folder, before removing anything" {
  _require_root
  _sandbox
  _bootstrap --group log_volume
  rm "$SANDBOX_AGENT_DIR/helpers/collectors.sh"

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 1 ]
  [[ "$output" == *"run uninstall-agent.sh from inside the full radar-agent folder"* ]]
  [ -f "$FAKE_ROOT/etc/systemd/system/radar-log-volume.timer" ]
  [ -d "$FAKE_ROOT/var/ossec/radar-agent" ]
  [ ! -e "$FAKE_ROOT/calls" ] || ! grep -q "apt-get" "$FAKE_ROOT/calls"
}

@test "bootstrap then uninstall then bootstrap again works" {
  _require_root
  _sandbox
  _bootstrap --group log_volume,suspicious_login
  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 0 ]
  mkdir -p "$FAKE_ROOT/var/ossec/etc"
  _bootstrap --group log_volume,suspicious_login
  [ -f "$FAKE_ROOT/etc/systemd/system/radar-log-volume.timer" ]
  [ -x "$AR_BIN/lock_user_linux.sh" ]
}

@test "keeps the agent key, root-only, with the manager it belongs to" {
  _require_root
  _sandbox
  _bootstrap --group default --agent-name edge.vm
  echo "001 edge.vm any deadbeef" > "$FAKE_ROOT/var/ossec/etc/client.keys"

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"kept this endpoint's agent key"* ]]
  [[ "$output" == *"reconnects this endpoint as the same agent"* ]]
  [ "$(cat "$FAKE_ROOT/var/lib/radar-agent/client.keys")" = "001 edge.vm any deadbeef" ]
  [ "$(cat "$FAKE_ROOT/var/lib/radar-agent/manager")" = "10.0.0.5" ]
  [ "$(stat -c '%U:%G %a' "$FAKE_ROOT/var/lib/radar-agent")" = "root:root 700" ]
  [ "$(stat -c '%U:%G %a' "$FAKE_ROOT/var/lib/radar-agent/client.keys")" = "root:root 600" ]
}

@test "--purge-data keeps no agent key" {
  _require_root
  _sandbox
  _bootstrap --group default --agent-name edge.vm
  echo "001 edge.vm any deadbeef" > "$FAKE_ROOT/var/ossec/etc/client.keys"
  mkdir -p "$FAKE_ROOT/var/lib/radar-agent" && echo stale > "$FAKE_ROOT/var/lib/radar-agent/client.keys"

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh" --purge-data
  [ "$status" -eq 0 ]
  [ ! -e "$FAKE_ROOT/var/lib/radar-agent" ]
  [[ "$output" == *"tick 'Replace the existing agent'"* ]]
}

@test "full cycle: bootstrap, uninstall, package purge, bootstrap again succeeds as the same agent" {
  _require_root
  _sandbox
  echo "001 edge.vm any deadbeef" > "$FAKE_ROOT/var/ossec/etc/client.keys"
  _bootstrap --group default,suspicious_login --agent-name edge.vm

  run bash "$SANDBOX_AGENT_DIR/uninstall-agent.sh"
  [ "$status" -eq 0 ]
  # what the real package purge does to the key
  rm -f "$FAKE_ROOT/var/ossec/etc/client.keys"
  # the manager still knows the agent, so it refuses a new enrollment
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<'EOF'
#!/usr/bin/env bash
echo "ERROR: Duplicate agent name" >&2
exit 1
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  _bootstrap --group default,suspicious_login --agent-name edge.vm
  [[ "$output" == *"reconnecting as the existing agent 'edge.vm'"* ]]
  [ "$(cat "$FAKE_ROOT/var/ossec/etc/client.keys")" = "001 edge.vm any deadbeef" ]
  [ ! -e "$FAKE_ROOT/var/lib/radar-agent" ]
}

@test "shellcheck (informational)" {
  shellcheck -x "${AGENT_DIR}/uninstall-agent.sh" || true
}
