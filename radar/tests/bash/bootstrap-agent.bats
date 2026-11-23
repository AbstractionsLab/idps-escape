#!/usr/bin/env bats
setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  AGENT_DIR="${REPO_ROOT}/radar-agent"
  SCRIPT="${AGENT_DIR}/bootstrap-agent.sh"
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

  # The whole radar-agent folder is deployed, as on a real endpoint.
  SANDBOX_AGENT_DIR="$FAKE_ROOT/radar-agent"
  cp -r "$AGENT_DIR" "$SANDBOX_AGENT_DIR"
  SANDBOXED_SCRIPT="$SANDBOX_AGENT_DIR/bootstrap-agent.sh"
  AGENT_HOME="$FAKE_ROOT/var/ossec/radar-agent"
  AR_BIN="$FAKE_ROOT/var/ossec/active-response/bin"
  mkdir -p "$FAKE_ROOT/usr/local/bin" "$FAKE_ROOT/etc/systemd/system" \
           "$FAKE_ROOT/etc/logrotate.d" "$FAKE_ROOT/var/log"
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
           "$f"
  done < <(find "$SANDBOX_AGENT_DIR" -name '*.sh' -type f -print0)
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
  cat > "${BIN_DIR}/systemctl" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "${FAKE_ROOT}/systemctl.calls"
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

@test "every catalog script gets a dispatcher in active-response/bin" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group suspicious_login,log_volume --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK - installed lock_user_linux.sh -> active_responses/lock_user_linux_v1.sh"* ]]
  [[ "$output" == *"OK - installed terminate_service.sh -> active_responses/terminate_service_v1.sh"* ]]
  [ -x "$AR_BIN/lock_user_linux.sh" ]
  [ -x "$AR_BIN/terminate_service.sh" ]
  # What lands in active-response/bin is the dispatcher, not the payload.
  cmp -s "$AR_BIN/lock_user_linux.sh" "$SANDBOX_AGENT_DIR/helpers/ar-dispatch.sh"
  cmp -s "$AR_BIN/terminate_service.sh" "$SANDBOX_AGENT_DIR/helpers/ar-dispatch.sh"
}

@test "the folder's catalog, library and all scripts are copied to a root-owned radar-agent home" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  # A second version shipped alongside v1 must be available on the endpoint.
  cp "$SANDBOX_AGENT_DIR/active_responses/lock_user_linux_v1.sh" \
     "$SANDBOX_AGENT_DIR/active_responses/lock_user_linux_v2.sh"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group suspicious_login --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"copied active response catalog and scripts to $AGENT_HOME"* ]]
  cmp -s "$AGENT_HOME/ar-scripts.yaml" "$SANDBOX_AGENT_DIR/ar-scripts.yaml"
  cmp -s "$AGENT_HOME/helpers/ar-mapping.sh" "$SANDBOX_AGENT_DIR/helpers/ar-mapping.sh"
  cmp -s "$AGENT_HOME/active_responses/lock_user_linux_v1.sh" "$SANDBOX_AGENT_DIR/active_responses/lock_user_linux_v1.sh"
  [ -x "$AGENT_HOME/active_responses/lock_user_linux_v2.sh" ]
  [ -x "$AGENT_HOME/active_responses/terminate_service_v1.sh" ]
  [ "$(stat -c '%U:%G %a' "$AGENT_HOME")" = "root:wazuh 750" ]
  [ "$(stat -c '%U:%G %a' "$AGENT_HOME/ar-scripts.yaml")" = "root:wazuh 640" ]
  [ "$(stat -c '%U:%G %a' "$AGENT_HOME/active_responses/lock_user_linux_v1.sh")" = "root:wazuh 750" ]
  [ "$(stat -c '%U:%G %a' "$AR_BIN/lock_user_linux.sh")" = "root:wazuh 750" ]
}

@test "re-running replaces the radar-agent home with the folder's current content" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]
  touch "$AGENT_HOME/active_responses/stale.sh"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]
  [ ! -e "$AGENT_HOME/active_responses/stale.sh" ]
  [ ! -e "${AGENT_HOME}.new" ]
}

@test "installed lock_user_linux.sh runs the mapped script end to end" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  command -v jq >/dev/null 2>&1 || skip "jq not installed"
  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]

  # uid 0 is always refused by the script itself, so nothing is locked.
  run bash -c "echo '{\"command\":\"add\",\"parameters\":{\"extra_args\":[\"root\"]}}' | '$AR_BIN/lock_user_linux.sh'"
  [ "$status" -eq 1 ]
  grep -q "dispatching to active_responses/lock_user_linux_v1.sh" "$FAKE_ROOT/var/ossec/logs/active-responses.log"
  grep -q "\[lock_user_linux\] refusing: 'root' is a system account" "$FAKE_ROOT/var/ossec/logs/active-responses.log"
}

@test "switching the installed catalog to another script version needs no bootstrap re-run" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  printf '#!/usr/bin/env bash\necho "lock v2 ran"\n' > "$SANDBOX_AGENT_DIR/active_responses/lock_user_linux_v2.sh"
  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]

  sed -i 's/lock_user_linux_v1.sh/lock_user_linux_v2.sh/' "$AGENT_HOME/ar-scripts.yaml"
  run bash -c "echo '{}' | '$AR_BIN/lock_user_linux.sh'"
  [ "$status" -eq 0 ]
  [ "$output" = "lock v2 ran" ]
}

@test "fails before changing anything when a listed script is missing from the folder" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  rm "$SANDBOX_AGENT_DIR/active_responses/lock_user_linux_v1.sh"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 1 ]
  [[ "$output" == *"maps lock_user_linux.sh to active_responses/lock_user_linux_v1.sh, which is not in"* ]]
  [[ "$output" == *"deploy the full radar-agent folder"* ]]
  [[ "$output" != *"=== bootstrap-agent.sh ==="* ]]
  grep -q "OLD_MANAGER" "$FAKE_ROOT/var/ossec/etc/ossec.conf"
}

@test "fails before changing anything when the catalog is invalid" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  printf 'scripts: lock_user_linux_v1.sh\n' > "$SANDBOX_AGENT_DIR/ar-scripts.yaml"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"must map active response names to scripts"* ]]
  [[ "$output" == *"could not read the active response catalog"* ]]
  grep -q "OLD_MANAGER" "$FAKE_ROOT/var/ossec/etc/ossec.conf"
}

@test "fails before changing anything when run outside a complete radar-agent folder" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  rm -rf "$SANDBOX_AGENT_DIR/helpers"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"helpers is incomplete"* ]]
  [[ "$output" == *"collectors.sh"* ]]
  [[ "$output" == *"deploy the full radar-agent folder"* ]]
  grep -q "OLD_MANAGER" "$FAKE_ROOT/var/ossec/etc/ossec.conf"
}

@test "linux_resource_utilization installs the collector timer and terminate_service.sh" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group linux_resource_utilization --agent-name edge.vm --allow-service nginx
  [ "$status" -eq 0 ]
  [[ "$output" == *"installed and started radar-linux-resource-utilization.timer"* ]]
  [[ "$output" == *"OK - installed terminate_service.sh"* ]]
  [ -x "$FAKE_ROOT/usr/local/bin/radar-linux-resource-utilization-metric.sh" ]
  [ -f "$FAKE_ROOT/etc/systemd/system/radar-linux-resource-utilization.timer" ]
  [ -f "$FAKE_ROOT/etc/logrotate.d/radar-linux-resource-utilization" ]
  [ -x "$FAKE_ROOT/var/ossec/active-response/bin/terminate_service.sh" ]
  grep -qx "nginx" "$FAKE_ROOT/var/ossec/etc/radar-terminable-services"
}

@test "collectors are installed from the folder unchanged, and their timers started" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group log_volume,linux_resource_utilization --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"Installing the log_volume metric collector"* ]]
  [[ "$output" == *"OK - installed and started radar-log-volume.timer"* ]]
  local c f
  for c in log_volume linux_resource_utilization; do
    for f in "$SANDBOX_AGENT_DIR/collectors/$c"/*; do
      case "$f" in
        *.sh)        cmp "$f" "$FAKE_ROOT/usr/local/bin/${f##*/}" ;;
        *.logrotate) local n="${f##*/}"; cmp "$f" "$FAKE_ROOT/etc/logrotate.d/${n%.logrotate}" ;;
        *)           cmp "$f" "$FAKE_ROOT/etc/systemd/system/${f##*/}" ;;
      esac
    done
  done
  grep -qx "enable --now radar-log-volume.timer" "$FAKE_ROOT/systemctl.calls"
  grep -qx "enable --now radar-linux-resource-utilization.timer" "$FAKE_ROOT/systemctl.calls"
}

@test "groups without a collector install none" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default,suspicious_login
  [ "$status" -eq 0 ]
  [[ "$output" != *"metric collector"* ]]
  [ -z "$(ls -A "$FAKE_ROOT/usr/local/bin")" ]
  [ -z "$(ls -A "$FAKE_ROOT/etc/systemd/system")" ]
  [ -z "$(ls -A "$FAKE_ROOT/etc/logrotate.d")" ]
}

@test "a new collector folder is picked up with no bootstrapper change" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  local c="$SANDBOX_AGENT_DIR/collectors/suspicious_login"
  mkdir -p "$c"
  printf '#!/usr/bin/env bash\necho x\n' > "$c/radar-sl-metric.sh"
  printf '[Service]\nExecStart=/usr/local/bin/radar-sl-metric.sh\n' > "$c/radar-sl.service"
  printf '[Timer]\nUnit=radar-sl.service\n' > "$c/radar-sl.timer"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK - installed and started radar-sl.timer"* ]]
  [ -x "$FAKE_ROOT/usr/local/bin/radar-sl-metric.sh" ]
}

@test "fails before changing anything when a joined group's collector is invalid" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  touch "$SANDBOX_AGENT_DIR/collectors/log_volume/sshd.service"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group log_volume
  [ "$status" -eq 1 ]
  [[ "$output" == *"'sshd.service' is not allowed"* ]]
  [[ "$output" == *"invalid collector for group 'log_volume'"* ]]
  [[ "$output" != *"=== bootstrap-agent.sh ==="* ]]
  grep -q "OLD_MANAGER" "$FAKE_ROOT/var/ossec/etc/ossec.conf"
  [ -z "$(ls -A "$FAKE_ROOT/etc/systemd/system")" ]
}

@test "an invalid collector of a group not joined does not block bootstrap" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  touch "$SANDBOX_AGENT_DIR/collectors/log_volume/sshd.service"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]
}

@test "fails before changing anything when packaging/wazuh.repo is missing" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  rm "$SANDBOX_AGENT_DIR/packaging/wazuh.repo"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"packaging/wazuh.repo not found"* ]]
  grep -q "OLD_MANAGER" "$FAKE_ROOT/var/ossec/etc/ossec.conf"
}

@test "linux_resource_utilization collector emits a line the decoder regex accepts" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  [[ -r /proc/stat && -r /proc/meminfo ]] || skip "needs /proc/stat and /proc/meminfo"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group linux_resource_utilization --agent-name edge.vm
  [ "$status" -eq 0 ]

  run bash "$FAKE_ROOT/usr/local/bin/radar-linux-resource-utilization-metric.sh"
  [ "$status" -eq 0 ]
  line="$(tail -n 1 "$FAKE_ROOT/var/log/radar/resource_usage_metric.log")"
  [[ "$line" =~ \ resource_usage_metric:\ cpu=[0-9]+\.[0-9]{2}\ mem=[0-9]+\.[0-9]{2}$ ]]
}

@test "the whole catalog is installed whatever the groups, so later GUI bindings work" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [ -x "$AR_BIN/lock_user_linux.sh" ]
  [ -x "$AR_BIN/terminate_service.sh" ]
  [ -f "$AGENT_HOME/ar-scripts.yaml" ]
}

@test "terminate_service.sh always gets an allowlist file, empty by default" {
  _require_root_for_fake_root_tests
  _setup_fake_root

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]
  [ -f "$FAKE_ROOT/var/ossec/etc/radar-terminable-services" ]
  ! grep -qv '^[[:space:]]*\(#\|$\)' "$FAKE_ROOT/var/ossec/etc/radar-terminable-services"
  [ "$(stat -c '%U:%G %a' "$FAKE_ROOT/var/ossec/etc/radar-terminable-services")" = "root:wazuh 640" ]
  [[ "$output" == *"no services listed in"* ]]
}

@test "an existing allowlist is kept when no --allow-service is given" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  printf 'nginx\n' > "$FAKE_ROOT/var/ossec/etc/radar-terminable-services"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  grep -qx "nginx" "$FAKE_ROOT/var/ossec/etc/radar-terminable-services"
}

@test "an empty catalog installs nothing and says so" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  printf 'scripts: {}\n' > "$SANDBOX_AGENT_DIR/ar-scripts.yaml"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"the active response catalog is empty, no script installed"* ]]
  [ ! -e "$AR_BIN/lock_user_linux.sh" ]
  [ ! -e "$AGENT_HOME" ]
}

@test "re-running removes dispatchers dropped from the catalog, and only those" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [ -x "$AR_BIN/terminate_service.sh" ]
  # A file Wazuh or an operator put there must survive.
  printf '#!/bin/sh\nexit 0\n' > "$AR_BIN/firewall-drop"

  printf 'scripts:\n  lock_user_linux.sh: active_responses/lock_user_linux_v1.sh\n' > "$SANDBOX_AGENT_DIR/ar-scripts.yaml"
  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK - removed terminate_service.sh (no longer in the catalog)"* ]]
  [ ! -e "$AR_BIN/terminate_service.sh" ]
  [ -x "$AR_BIN/lock_user_linux.sh" ]
  [ -f "$AR_BIN/firewall-drop" ]
}

@test "an old embedded-payload script in bin is replaced by the dispatcher" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  mkdir -p "$AR_BIN"
  printf '#!/usr/bin/env bash\necho legacy payload\n' > "$AR_BIN/lock_user_linux.sh"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group suspicious_login
  [ "$status" -eq 0 ]
  cmp -s "$AR_BIN/lock_user_linux.sh" "$SANDBOX_AGENT_DIR/helpers/ar-dispatch.sh"
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

@test "fills in the manager address when <server> is empty" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  printf '<ossec_config><client><server>\n</server></client></ossec_config>\n' \
    > "$FAKE_ROOT/var/ossec/etc/ossec.conf"

  run bash "$SANDBOXED_SCRIPT" --manager 203.0.113.9 --token abc --group default
  [ "$status" -eq 0 ]
  grep -q "<address>203.0.113.9</address>" "$FAKE_ROOT/var/ossec/etc/ossec.conf"
  grep -q "<port>1514</port>" "$FAKE_ROOT/var/ossec/etc/ossec.conf"
}

@test "fails clearly when ossec.conf has no <server> block to patch" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  echo "<ossec_config></ossec_config>" > "$FAKE_ROOT/var/ossec/etc/ossec.conf"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"no <server> block found"* ]]
}

@test "enrollment passes manager, token, name and every group to agent-auth in one call" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<EOF
#!/usr/bin/env bash
echo "\$*" > "${FAKE_ROOT}/agent-auth.args"
exit 0
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc \
    --group default --group suspicious_login,log_volume --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"=== SUCCESS ==="* ]]
  [ "$(cat "$FAKE_ROOT/agent-auth.args")" = "-m 10.0.0.5 -P abc -A edge.vm -G default,suspicious_login,log_volume" ]
}

@test "re-running on an enrolled endpoint: 'Duplicate agent name' with a key is success" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  echo "001 edge.vm any deadbeef" > "$FAKE_ROOT/var/ossec/etc/client.keys"
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

@test "'Duplicate agent name' without a local key fails with a deregister hint" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  : > "$FAKE_ROOT/var/ossec/etc/client.keys"
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<'EOF'
#!/usr/bin/env bash
echo "ERROR: Duplicate agent name" >&2
exit 1
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default
  [ "$status" -eq 1 ]
  [[ "$output" == *"already has an agent named"* ]]
  [[ "$output" == *"this endpoint has no key for it"* ]]
  [[ "$output" == *"Agent Management > Onboard agent"* ]]
  [[ "$output" == *"tick 'Replace the existing agent'"* ]]
  [[ "$output" == *"keeps the agent's groups"* ]]
}

_kept_key() {
  # <name> <manager>: what uninstall-agent.sh leaves in /var/lib/radar-agent
  mkdir -p "$FAKE_ROOT/var/lib/radar-agent"
  echo "001 $1 any deadbeef" > "$FAKE_ROOT/var/lib/radar-agent/client.keys"
  echo "$2" > "$FAKE_ROOT/var/lib/radar-agent/manager"
}

_duplicate_name_manager() {
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<'EOF'
#!/usr/bin/env bash
echo "ERROR: Duplicate agent name" >&2
exit 1
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"
}

@test "after uninstall, a kept key is restored and the endpoint reconnects as the same agent" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  : > "$FAKE_ROOT/var/ossec/etc/client.keys"
  _kept_key edge.vm 10.0.0.5
  _duplicate_name_manager

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" == *"restored this endpoint's previous agent key for 'edge.vm'"* ]]
  [[ "$output" == *"reconnecting as the existing agent 'edge.vm': it keeps its ID and groups"* ]]
  [ "$(cat "$FAKE_ROOT/var/ossec/etc/client.keys")" = "001 edge.vm any deadbeef" ]
  [ "$(stat -c '%U:%G %a' "$FAKE_ROOT/var/ossec/etc/client.keys")" = "root:wazuh 640" ]
  [ ! -e "$FAKE_ROOT/var/lib/radar-agent" ]
}

@test "a kept key for another agent name is not restored" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  : > "$FAKE_ROOT/var/ossec/etc/client.keys"
  _kept_key other.vm 10.0.0.5
  _duplicate_name_manager

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default --agent-name edge.vm
  [ "$status" -eq 1 ]
  [[ "$output" == *"kept agent key is for 'other.vm' on manager '10.0.0.5', not 'edge.vm'"* ]]
  [[ "$output" == *"Agent Management > Onboard agent"* ]]
  [ ! -s "$FAKE_ROOT/var/ossec/etc/client.keys" ]
  [ -s "$FAKE_ROOT/var/lib/radar-agent/client.keys" ]
}

@test "a kept key from another manager is not restored" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  : > "$FAKE_ROOT/var/ossec/etc/client.keys"
  _kept_key edge.vm 192.168.9.9
  _duplicate_name_manager

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default --agent-name edge.vm
  [ "$status" -eq 1 ]
  [[ "$output" == *"on manager '192.168.9.9', not 'edge.vm' on '10.0.0.5'"* ]]
  [ ! -s "$FAKE_ROOT/var/ossec/etc/client.keys" ]
}

@test "an existing key always wins over a kept one, and the kept copy is cleaned up" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  echo "002 edge.vm any current" > "$FAKE_ROOT/var/ossec/etc/client.keys"
  _kept_key edge.vm 10.0.0.5
  _duplicate_name_manager

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default --agent-name edge.vm
  [ "$status" -eq 0 ]
  [[ "$output" != *"restored"* ]]
  [ "$(cat "$FAKE_ROOT/var/ossec/etc/client.keys")" = "002 edge.vm any current" ]
  [ ! -e "$FAKE_ROOT/var/lib/radar-agent" ]
}

@test "if the manager no longer knows the agent, a fresh enrollment replaces the restored key" {
  _require_root_for_fake_root_tests
  _setup_fake_root
  : > "$FAKE_ROOT/var/ossec/etc/client.keys"
  _kept_key edge.vm 10.0.0.5
  cat > "$FAKE_ROOT/var/ossec/bin/agent-auth" <<EOF
#!/usr/bin/env bash
echo "007 edge.vm any newkey" > "${FAKE_ROOT}/var/ossec/etc/client.keys"
exit 0
EOF
  chmod +x "$FAKE_ROOT/var/ossec/bin/agent-auth"

  run bash "$SANDBOXED_SCRIPT" --manager 10.0.0.5 --token abc --group default --agent-name edge.vm
  [ "$status" -eq 0 ]
  [ "$(cat "$FAKE_ROOT/var/ossec/etc/client.keys")" = "007 edge.vm any newkey" ]
  [ ! -e "$FAKE_ROOT/var/lib/radar-agent" ]
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
  shellcheck -x "$SCRIPT" || true
}
