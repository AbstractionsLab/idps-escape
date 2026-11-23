#!/usr/bin/env bats
# Unit tests for radar-agent/helpers/collectors.sh. Install/uninstall tests use
# temporary destination folders and a stub systemctl; they need root only for
# "install -o root".

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  AGENT_DIR="${REPO_ROOT}/radar-agent"
  # shellcheck source=../../radar-agent/helpers/collectors.sh
  source "${AGENT_DIR}/helpers/collectors.sh"
  TMP="$(mktemp -d)"

  # Redirect every destination into the sandbox.
  COLLECTOR_BIN_DIR="$TMP/usr/local/bin"
  COLLECTOR_UNIT_DIR="$TMP/etc/systemd/system"
  COLLECTOR_LOGROTATE_DIR="$TMP/etc/logrotate.d"
  COLLECTOR_LOG_DIR="$TMP/var/log/radar"
  mkdir -p "$COLLECTOR_BIN_DIR" "$COLLECTOR_UNIT_DIR" "$COLLECTOR_LOGROTATE_DIR"

  mkdir -p "$TMP/stub"
  cat > "$TMP/stub/systemctl" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "$TMP/systemctl.calls"
[[ "\$*" == "enable --now radar-fail.timer" ]] && exit 1
exit 0
EOF
  chmod +x "$TMP/stub/systemctl"
  PATH="$TMP/stub:$PATH"
}

teardown() {
  rm -rf "$TMP"
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || skip "install -o root needs root"
}

# A collector folder with the usual four files.
make_collector() {
  C="$TMP/collectors/demo"
  mkdir -p "$C"
  printf '#!/usr/bin/env bash\necho metric\n' > "$C/radar-demo-metric.sh"
  printf '[Service]\nType=oneshot\nExecStart=/usr/local/bin/radar-demo-metric.sh\n' > "$C/radar-demo.service"
  printf '[Timer]\nUnit=radar-demo.service\n[Install]\nWantedBy=timers.target\n' > "$C/radar-demo.timer"
  printf '/var/log/radar/demo.log {\n  daily\n}\n' > "$C/radar-demo.logrotate"
}

# --- destinations -------------------------------------------------------------

@test "dest: each extension goes to its system folder" {
  [ "$(collector_dest radar-x-metric.sh)" = "$COLLECTOR_BIN_DIR/radar-x-metric.sh" ]
  [ "$(collector_dest radar-x.service)" = "$COLLECTOR_UNIT_DIR/radar-x.service" ]
  [ "$(collector_dest radar-x.timer)" = "$COLLECTOR_UNIT_DIR/radar-x.timer" ]
  [ "$(collector_dest radar-x.logrotate)" = "$COLLECTOR_LOGROTATE_DIR/radar-x" ]
}

@test "dest: names that could replace system files are refused" {
  local bad
  for bad in sshd.service radar-x.conf radar-x radar-.timer radar-X.timer \
             '../radar-x.timer' 'radar-x/y.timer' radar-x.sh.bak .radar-x.timer \
             'radar-x .timer' radar_x.timer; do
    run collector_dest "$bad"
    [ "$status" -ne 0 ] || { echo "accepted: $bad"; return 1; }
  done
}

@test "the shipped default destinations are the real system folders" {
  run bash -c "source '$AGENT_DIR/helpers/collectors.sh'; echo \"\$COLLECTOR_BIN_DIR \$COLLECTOR_UNIT_DIR \$COLLECTOR_LOGROTATE_DIR \$COLLECTOR_LOG_DIR\""
  [ "$output" = "/usr/local/bin /etc/systemd/system /etc/logrotate.d /var/log/radar" ]
}

# --- lookup -------------------------------------------------------------------

@test "collector_dir: finds shipped collectors, nothing for other groups" {
  [ "$(collector_dir "$AGENT_DIR" log_volume)" = "$AGENT_DIR/collectors/log_volume" ]
  [ "$(collector_dir "$AGENT_DIR" linux_resource_utilization)" = "$AGENT_DIR/collectors/linux_resource_utilization" ]
  [ -z "$(collector_dir "$AGENT_DIR" suspicious_login)" ]
  [ -z "$(collector_dir "$AGENT_DIR" default)" ]
}

@test "collector_dir: a group name cannot point outside collectors/" {
  [ -z "$(collector_dir "$AGENT_DIR" ..)" ]
  [ -z "$(collector_dir "$AGENT_DIR" ../helpers)" ]
  [ -z "$(collector_dir "$AGENT_DIR" '')" ]
}

# --- validation -----------------------------------------------------------------

@test "validate: the shipped collectors are valid" {
  local d
  for d in "$AGENT_DIR"/collectors/*/; do
    run collector_validate "${d%/}"
    [ "$status" -eq 0 ] || { echo "$d: $output"; return 1; }
  done
}

@test "validate: an empty folder is refused" {
  mkdir -p "$TMP/collectors/empty"
  run collector_validate "$TMP/collectors/empty"
  [ "$status" -ne 0 ]
  [[ "$output" == *"is empty"* ]]
}

@test "validate: a collector without a timer is refused" {
  make_collector
  rm "$C/radar-demo.timer"
  run collector_validate "$C"
  [ "$status" -ne 0 ]
  [[ "$output" == *"has no .timer"* ]]
}

@test "validate: an unexpected file (including a hidden one) is refused" {
  make_collector
  touch "$C/README.md"
  run collector_validate "$C"
  [ "$status" -ne 0 ]
  [[ "$output" == *"'README.md' is not allowed"* ]]

  rm "$C/README.md"
  touch "$C/.radar-demo.timer.swp"
  run collector_validate "$C"
  [ "$status" -ne 0 ]
}

@test "validate: subfolders and symlinks are refused" {
  make_collector
  mkdir "$C/radar-sub.timer"
  run collector_validate "$C"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must be a regular file"* ]]

  rmdir "$C/radar-sub.timer"
  ln -s /etc/passwd "$C/radar-link.logrotate"
  run collector_validate "$C"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must be a regular file"* ]]
}

# --- install --------------------------------------------------------------------

@test "install: copies every file unchanged with fixed modes, starts the timer" {
  require_root
  make_collector
  run collector_install "$C"
  [ "$status" -eq 0 ]
  [ "$output" = "radar-demo.timer" ]

  cmp "$C/radar-demo-metric.sh" "$COLLECTOR_BIN_DIR/radar-demo-metric.sh"
  cmp "$C/radar-demo.service" "$COLLECTOR_UNIT_DIR/radar-demo.service"
  cmp "$C/radar-demo.timer" "$COLLECTOR_UNIT_DIR/radar-demo.timer"
  cmp "$C/radar-demo.logrotate" "$COLLECTOR_LOGROTATE_DIR/radar-demo"
  [ "$(stat -c '%U:%G %a' "$COLLECTOR_BIN_DIR/radar-demo-metric.sh")" = "root:root 750" ]
  [ "$(stat -c '%U:%G %a' "$COLLECTOR_UNIT_DIR/radar-demo.service")" = "root:root 644" ]
  [ "$(stat -c '%U:%G %a' "$COLLECTOR_UNIT_DIR/radar-demo.timer")" = "root:root 644" ]
  [ "$(stat -c '%U:%G %a' "$COLLECTOR_LOGROTATE_DIR/radar-demo")" = "root:root 644" ]
  [ "$(stat -c '%a' "$COLLECTOR_LOG_DIR")" = "755" ]

  # daemon-reload comes before the timer is enabled.
  [ "$(sed -n 1p "$TMP/systemctl.calls")" = "daemon-reload" ]
  [ "$(sed -n 2p "$TMP/systemctl.calls")" = "enable --now radar-demo.timer" ]
}

@test "install: source modes do not leak (a world-writable source is installed 0644)" {
  require_root
  make_collector
  chmod 0666 "$C/radar-demo.service"
  chmod 0777 "$C/radar-demo-metric.sh"
  run collector_install "$C"
  [ "$status" -eq 0 ]
  [ "$(stat -c '%a' "$COLLECTOR_UNIT_DIR/radar-demo.service")" = "644" ]
  [ "$(stat -c '%a' "$COLLECTOR_BIN_DIR/radar-demo-metric.sh")" = "750" ]
}

@test "install: re-running is idempotent" {
  require_root
  make_collector
  run collector_install "$C"
  [ "$status" -eq 0 ]
  run collector_install "$C"
  [ "$status" -eq 0 ]
  cmp "$C/radar-demo.timer" "$COLLECTOR_UNIT_DIR/radar-demo.timer"
}

@test "install: an invalid collector installs nothing" {
  require_root
  make_collector
  touch "$C/evil.service"
  run collector_install "$C"
  [ "$status" -ne 0 ]
  [ -z "$(ls -A "$COLLECTOR_UNIT_DIR")" ]
  [ ! -e "$TMP/systemctl.calls" ]
}

@test "install: a timer that cannot be started is reported" {
  require_root
  make_collector
  mv "$C/radar-demo.timer" "$C/radar-fail.timer"
  run collector_install "$C"
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not enable and start radar-fail.timer"* ]]
}

# --- uninstall ------------------------------------------------------------------

@test "uninstall: stops the timer and removes exactly the collector's files" {
  require_root
  make_collector
  collector_install "$C" >/dev/null
  touch "$COLLECTOR_UNIT_DIR/sshd.service" "$COLLECTOR_BIN_DIR/radar-other-metric.sh"
  : > "$TMP/systemctl.calls"

  run collector_uninstall "$C"
  [ "$status" -eq 0 ]
  [ "$output" = "4" ]
  [ ! -e "$COLLECTOR_BIN_DIR/radar-demo-metric.sh" ]
  [ ! -e "$COLLECTOR_UNIT_DIR/radar-demo.service" ]
  [ ! -e "$COLLECTOR_UNIT_DIR/radar-demo.timer" ]
  [ ! -e "$COLLECTOR_LOGROTATE_DIR/radar-demo" ]
  [ -e "$COLLECTOR_UNIT_DIR/sshd.service" ]
  [ -e "$COLLECTOR_BIN_DIR/radar-other-metric.sh" ]
  grep -qx "stop radar-demo.timer" "$TMP/systemctl.calls"
  grep -qx "disable radar-demo.timer" "$TMP/systemctl.calls"
  grep -qx "daemon-reload" "$TMP/systemctl.calls"
}

@test "uninstall: nothing installed reports 0 and does not reload systemd" {
  make_collector
  run collector_uninstall "$C"
  [ "$status" -eq 0 ]
  [ "$output" = "0" ]
  ! grep -qx "daemon-reload" "$TMP/systemctl.calls"
}

@test "uninstall: collected logs are left alone" {
  require_root
  make_collector
  collector_install "$C" >/dev/null
  echo data > "$COLLECTOR_LOG_DIR/demo.log"
  collector_uninstall "$C" >/dev/null
  [ -f "$COLLECTOR_LOG_DIR/demo.log" ]
}

@test "uninstall: unexpected files in the folder are ignored, never mapped to a path" {
  make_collector
  touch "$C/sshd.service"
  touch "$COLLECTOR_UNIT_DIR/sshd.service"
  run collector_uninstall "$C"
  [ "$status" -eq 0 ]
  [ -e "$COLLECTOR_UNIT_DIR/sshd.service" ]
}

@test "shellcheck (informational)" {
  shellcheck "${AGENT_DIR}/helpers/collectors.sh" "${AGENT_DIR}"/collectors/*/*.sh || true
}
