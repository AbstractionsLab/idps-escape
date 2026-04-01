#!/usr/bin/env bats

setup() {
  TEST_TMP="$(mktemp -d)"
  export LOG_DIR="$TEST_TMP"
  mkdir -p "$TEST_TMP/suspicious_login/dataset"
  touch "$TEST_TMP/config.yaml" "$TEST_TMP/.env"
  mkdir -p "$TEST_TMP/config/wazuh_indexer_ssl_certs"
  touch "$TEST_TMP/config/wazuh_indexer_ssl_certs/root-ca.pem"
  export PATH="${BATS_TEST_DIRNAME}/stubs:${PATH}"
  SCRIPT="${BATS_TEST_DIRNAME}/../../run-radar.sh"
  chmod +x "$SCRIPT"
  pushd "$TEST_TMP" >/dev/null
  : > "$LOG_DIR/calls.log"
}

teardown() {
  popd >/dev/null
  rm -rf "$TEST_TMP"
}

@test "default run ingest dataset, cert, and passes DET_ID to monitor" {
  run "${BATS_TEST_DIRNAME}/../../run-radar.sh" suspicious_login --ingest true
  [ "$status" -eq 0 ] || { echo "status=$status"; echo "$output"; echo "---- calls.log ----"; cat "$LOG_DIR/calls.log" 2>/dev/null || true; echo "-------------------"; false; }

  # final docker build
  if [[ -f Dockerfile.radar-cli ]]; then
    assert_in_log "docker build -f Dockerfile.radar-cli -t radar-cli:latest ."
  fi

  # Ingest call (no --network in current script)
  grep -F \
    "docker run --rm -v $TEST_TMP/suspicious_login/dataset:/app/suspicious_login/dataset -v $TEST_TMP/config/wazuh_indexer_ssl_certs/root-ca.pem:/app/config/wazuh_indexer_ssl_certs/root-ca.pem -v $TEST_TMP/.env:/app/.env:ro radar-cli:latest python suspicious_login/wazuh_ingest.py" \
    "$LOG_DIR/calls.log"

  # Detector call -> stub prints det-12345
  grep -F \
    "docker run --rm -v $TEST_TMP/config.yaml:/app/config.yaml:ro -v $TEST_TMP/.env:/app/.env:ro radar-cli:latest python detector.py suspicious_login" \
    "$LOG_DIR/calls.log"

  # Monitor call should include det-12345
  grep -F \
    "docker run --rm -v $TEST_TMP/config.yaml:/app/config.yaml:ro -v $TEST_TMP/.env:/app/.env:ro radar-cli:latest python monitor.py suspicious_login det-12345" \
    "$LOG_DIR/calls.log"
}

@test "default run without ingest" {
  run "${BATS_TEST_DIRNAME}/../../run-radar.sh" suspicious_login
  [ "$status" -eq 0 ] || { echo "status=$status"; echo "$output"; echo "---- calls.log ----"; cat "$LOG_DIR/calls.log" 2>/dev/null || true; echo "-------------------"; false; }

  if grep -Fq "wazuh_ingest.py" "$LOG_DIR/calls.log"; then
    echo "ingest should not run when --ingest is not specified"
    echo "---- calls.log ----"; cat "$LOG_DIR/calls.log"; echo "-------------------"
    false
  fi

  grep -F \
    "docker run --rm -v $TEST_TMP/config.yaml:/app/config.yaml:ro -v $TEST_TMP/.env:/app/.env:ro radar-cli:latest python detector.py suspicious_login" \
    "$LOG_DIR/calls.log"

  grep -F \
    "docker run --rm -v $TEST_TMP/config.yaml:/app/config.yaml:ro -v $TEST_TMP/.env:/app/.env:ro radar-cli:latest python monitor.py suspicious_login det-12345" \
    "$LOG_DIR/calls.log"
}

@test "shellcheck (informational)" {
  shellcheck "${BATS_TEST_DIRNAME}/../../run-radar.sh" || true
}
