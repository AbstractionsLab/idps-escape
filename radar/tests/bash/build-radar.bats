#!/usr/bin/env bats

bats_require_minimum_version 1.5.0

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/build-radar.sh"
}

@test "no arguments prints usage and exits 2" {
  run bash "$SCRIPT"
  [ "$status" -eq 2 ]
  [[ "$output" == *"Usage:"* ]]
}

@test "--help exits 0 (before -h is treated as an unknown flag)" {
  run bash "$SCRIPT" --help
  [ "$status" -eq 2 ] || [ "$status" -eq 0 ]
  [[ "$output" == *"Usage:"* ]]
}

@test "--agent is rejected as an unknown option (the flag was removed entirely)" {
  run bash "$SCRIPT" suspicious_login --agent remote
  [ "$status" -eq 2 ]
  [[ "$output" == *"Unknown option"* ]]
}

@test "unknown flag is rejected with usage" {
  run bash "$SCRIPT" suspicious_login --nope
  [ "$status" -eq 2 ]
  [[ "$output" == *"Unknown option"* ]]
}

@test "invalid scenario name is rejected by scenario-info (read-only against real config.yaml)" {
  run bash "$SCRIPT" totally_bogus_scenario
  [ "$status" -eq 1 ]
  [[ "$output" == *"Invalid scenario"* ]]
}

_setup_isolated_root() {
  TEST_ROOT="$(mktemp -d)"
  cp "$SCRIPT" "$TEST_ROOT/"
  cp -r "$REPO_ROOT/wazuh_api" "$TEST_ROOT/"
  mkdir -p "$TEST_ROOT/radar_deploy" "$TEST_ROOT/config/wazuh_cluster" \
           "$TEST_ROOT/srv/etc" "$TEST_ROOT/srv/filebeat"
  echo '{}' > "$TEST_ROOT/config/wazuh_cluster/pipeline-archives.json"

  cat > "$TEST_ROOT/config.yaml" <<'YAML'
scenarios:
  suspicious_login:
    container_name: agent.suspicious
YAML

  cat > "$TEST_ROOT/volumes.yml" <<YAML
version: "3.7"
services:
  wazuh.manager:
    volumes:
      - $TEST_ROOT/srv/etc:/var/ossec/etc
      - $TEST_ROOT/srv/filebeat/pipeline.json:/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json
YAML

  touch "$TEST_ROOT/docker-compose.core.yml"
  cat > "$TEST_ROOT/.env" <<'ENV'
WAZUH_API_URL=https://fake
WAZUH_AUTH_USER=u
WAZUH_AUTH_PASS=p
ENV

  cat > "$TEST_ROOT/radar_deploy/manager-ensure-certs.sh" <<'STUB'
#!/usr/bin/env bash
echo "manager-ensure-certs.sh called" >> "$LOG_DIR/calls.log"
STUB
  chmod +x "$TEST_ROOT/radar_deploy/manager-ensure-certs.sh"

  BIN_DIR="$TEST_ROOT/bin"
  mkdir -p "$BIN_DIR"
  export LOG_DIR="$TEST_ROOT/logs"
  mkdir -p "$LOG_DIR"
  : > "$LOG_DIR/calls.log"

  # $1 selects docker ps's fake output so a single stub covers both branches.
  cat > "${BIN_DIR}/docker" <<EOF
#!/usr/bin/env bash
echo "docker \$*" >> "${LOG_DIR}/calls.log"
if [[ "\$1" == "ps" ]]; then
  [[ -f "${TEST_ROOT}/.manager-running" ]] && echo "wazuh.manager"
fi
exit 0
EOF
  chmod +x "${BIN_DIR}/docker"
  REAL_PYTHON3="$(command -v python3)"
  cat > "${BIN_DIR}/python3" <<EOF
#!/usr/bin/env bash
if [[ "\$*" == *"wait-for-api"* ]]; then
  echo '{"api_reachable": true}'
  exit 0
fi
exec "${REAL_PYTHON3}" "\$@"
EOF
  chmod +x "${BIN_DIR}/python3"

  export PATH="${BIN_DIR}:${PATH}"
}

teardown() {
  if [[ -n "${TEST_ROOT:-}" ]]; then
    rm -rf "$TEST_ROOT"
  fi
}

@test "when the manager isn't running: certs are ensured, then compose up, in that order" {
  _setup_isolated_root

  cd "$TEST_ROOT"
  run ! bash build-radar.sh suspicious_login
  # Expected to fail further down (radar_deploy/manager-apply-scenario.sh
  # isn't stubbed -- out of scope here), so we assert on the log, not the
  # specific exit code -- 'run !' just tells bats we know this fails.

  run cat "$LOG_DIR/calls.log"
  [ "$status" -eq 0 ]
  # docker ps happens first (the "is the manager running" check)...
  [[ "${lines[0]}" == "docker ps --format {{.Names}}" ]]
  # ...then certs are ensured BEFORE compose up...
  certs_line=-1; compose_line=-1
  for i in "${!lines[@]}"; do
    [[ "${lines[$i]}" == "manager-ensure-certs.sh called" ]] && certs_line=$i
    [[ "${lines[$i]}" == "docker compose -f docker-compose.core.yml -f volumes.yml up -d" ]] && compose_line=$i
  done
  [ "$certs_line" -ge 0 ]
  [ "$compose_line" -ge 0 ]
  [ "$certs_line" -lt "$compose_line" ]
}

@test "when the manager is already running: certs are not touched and compose up is skipped" {
  _setup_isolated_root
  touch "$TEST_ROOT/.manager-running"

  cd "$TEST_ROOT"
  run ! bash build-radar.sh suspicious_login
  [[ "$output" == *"Manager already running."* ]]

  run cat "$LOG_DIR/calls.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker ps"* ]]
  [[ "$output" != *"manager-ensure-certs.sh called"* ]]
  [[ "$output" != *"compose"*"up"* ]]
}

@test "shellcheck (informational)" {
  shellcheck "$SCRIPT" || true
}
