#!/usr/bin/env bats

GIB=$((1024 ** 3))
MIB=$((1024 ** 2))

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  SCRIPT_SRC="${REPO_ROOT}/radar-test-framework/simulate/scenarios/linux_resource_utilization.sh"
  TMPDIR="$(mktemp -d)"
  BIN_DIR="${TMPDIR}/bin"
  mkdir -p "${BIN_DIR}"
  STRESS_LOG="${TMPDIR}/stress-ng.log"
  MEMINFO="${TMPDIR}/meminfo"
  SCRIPT="${TMPDIR}/lru.sh"

  cat > "${BIN_DIR}/stress-ng" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "${STRESS_LOG}"
[[ -n "\${FAKE_STRESS_RC:-}" ]] && exit "\${FAKE_STRESS_RC}"
trap 'exit 0' TERM
sleep 30 &
wait
EOF
  chmod +x "${BIN_DIR}/stress-ng"
  export PATH="${BIN_DIR}:${PATH}"

  meminfo $((8 * 1024 * 1024)) $((6 * 1024 * 1024))
  configure MEMINFO_PATH "\"${MEMINFO}\"" DURATION_SECONDS 2 REPORT_INTERVAL_SECONDS 30
}

teardown() {
  pkill -f "${BIN_DIR}/stress-ng" 2>/dev/null || true
  rm -rf "${TMPDIR}"
}

meminfo() {
  printf 'MemTotal:       %s kB\nMemFree:        1 kB\nMemAvailable:   %s kB\n' "$1" "$2" > "${MEMINFO}"
}

configure() {
  [[ -f "${SCRIPT}" ]] || cp "${SCRIPT_SRC}" "${SCRIPT}"
  while (( $# >= 2 )); do
    grep -q "^$1=" "${SCRIPT}"
    sed -i "s|^$1=.*|$1=$2|" "${SCRIPT}"
    shift 2
  done
}

stress_args() {
  cat "${STRESS_LOG}"
}

@test "both mode runs stress-ng with CPU load and the computed memory" {
  configure MODE '"both"' CPU_WORKERS 2
  run bash "${SCRIPT}"
  [ "$status" -eq 0 ]
  [[ "$output" == *"CPU: 2 worker(s) at 95% load"* ]]
  [[ "$output" == *"linux_resource_utilization simulation completed. Load released."* ]]
  local expected=$(( 7301444403 - 2 * GIB ))
  [ "$(stress_args)" = "--cache-size 64K --cpu 2 --cpu-load 95 --vm 1 --vm-bytes ${expected} --vm-keep --vm-populate --vm-hang 0 --timeout 2s" ]
}

@test "cpu mode with CPU_WORKERS=0 uses one worker per CPU and no memory" {
  configure MODE '"cpu"' CPU_LOAD_PCT 70
  run bash "${SCRIPT}"
  [ "$status" -eq 0 ]
  [ "$(stress_args)" = "--cache-size 64K --cpu $(nproc) --cpu-load 70 --timeout 2s" ]
}

@test "mem mode keeps the safety floor of free memory" {
  meminfo $((8 * 1024 * 1024)) $((600 * 1024))
  configure MODE '"mem"' MEM_TARGET_PCT 100
  run bash "${SCRIPT}"
  [ "$status" -eq 0 ]
  [[ "$(stress_args)" == *"--vm-bytes $(( 88 * MIB )) "* ]]
}

@test "mem mode never holds more than MEM_MAX_BYTES" {
  configure MODE '"mem"' MEM_MAX_BYTES "${GIB}"
  run bash "${SCRIPT}"
  [ "$status" -eq 0 ]
  [[ "$(stress_args)" == *"--vm-bytes ${GIB} "* ]]
}

@test "mem mode already above target allocates nothing and does not start stress-ng" {
  meminfo $((8 * 1024 * 1024)) $((1024 * 1024))
  configure MODE '"mem"'
  run bash "${SCRIPT}"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nothing allocated"* ]]
  [ ! -f "${STRESS_LOG}" ]
}

@test "stress-ng is stopped when the script is terminated" {
  configure MODE '"cpu"' DURATION_SECONDS 60
  bash "${SCRIPT}" > "${TMPDIR}/out" 2>&1 &
  local pid=$!
  for _ in $(seq 50); do [[ -f "${STRESS_LOG}" ]] && break; sleep 0.1; done
  pgrep -f "${BIN_DIR}/stress-ng" > /dev/null
  kill -TERM "${pid}"
  local rc=0
  wait "${pid}" || rc=$?
  [ "$rc" -eq 130 ]
  grep -q "Interrupted; load released." "${TMPDIR}/out"
  sleep 0.5
  ! pgrep -f "${BIN_DIR}/stress-ng" > /dev/null
}

@test "a failing stress-ng is reported" {
  configure MODE '"cpu"'
  FAKE_STRESS_RC=3 run bash "${SCRIPT}"
  [ "$status" -eq 1 ]
  [[ "$output" == *"stress-ng stopped with exit code 3"* ]]
}

@test "missing stress-ng gives install instructions" {
  local minbin="${TMPDIR}/minbin"
  mkdir -p "${minbin}"
  for c in bash env date awk dirname uname nproc sleep kill; do
    ln -s "$(command -v "$c")" "${minbin}/$c"
  done
  configure MODE '"cpu"'
  PATH="${minbin}" run bash "${SCRIPT}"
  [ "$status" -eq 1 ]
  [[ "$output" == *"stress-ng is not installed"*"apt-get install -y stress-ng"* ]]
}

@test "inject mode writes decoder-compatible lines until the deadline" {
  mkdir -p "${TMPDIR}/radar"
  configure MODE '"inject"' DURATION_SECONDS 3 INJECT_INTERVAL_SECONDS 1 \
    INJECT_CPU_PCT 99 INJECT_MEM_PCT 88 INJECT_LOG_PATH "\"${TMPDIR}/radar/m.log\""
  run bash "${SCRIPT}"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Injected 4 metric line(s)"* ]]
  [ "$(wc -l < "${TMPDIR}/radar/m.log")" -eq 4 ]
  ! grep -vE '^[A-Z][a-z]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ resource_usage_metric: cpu=99\.00 mem=88\.00$' "${TMPDIR}/radar/m.log"
  [ ! -f "${STRESS_LOG}" ]
}

@test "inject mode without the collector directory explains enrollment" {
  configure MODE '"inject"' INJECT_LOG_PATH "\"${TMPDIR}/missing/m.log\""
  run bash "${SCRIPT}"
  [ "$status" -eq 1 ]
  [[ "$output" == *"linux_resource_utilization group"* ]]
}

@test "an invalid mode is rejected" {
  configure MODE '"gpu"'
  run bash "${SCRIPT}"
  [ "$status" -eq 1 ]
  [[ "$output" == *"MODE must be one of cpu, mem, both, inject"* ]]
}

@test "an out-of-range CPU load is rejected" {
  configure CPU_LOAD_PCT 150
  run bash "${SCRIPT}"
  [ "$status" -eq 1 ]
  [[ "$output" == *"CPU_LOAD_PCT must be a whole number from 1 to 100"* ]]
}

@test "meminfo without MemAvailable is a clear error" {
  printf 'MemTotal: 1000 kB\n' > "${MEMINFO}"
  configure MODE '"mem"'
  run bash "${SCRIPT}"
  [ "$status" -eq 1 ]
  [[ "$output" == *"has no MemTotal/MemAvailable"* ]]
}
