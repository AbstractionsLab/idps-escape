#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit
export LC_ALL=C

MODE="both"
DURATION_SECONDS=300
CPU_WORKERS=0
CPU_LOAD_PCT=90
MEM_TARGET_PCT=85
MEM_MAX_BYTES=$((16 * 1024 ** 3))
MEM_MIN_AVAILABLE_BYTES=$((512 * 1024 ** 2))
INJECT_LOG_PATH="/var/log/radar/resource_usage_metric.log"
INJECT_CPU_PCT=97.5
INJECT_MEM_PCT=95.0
INJECT_INTERVAL_SECONDS=5
REPORT_INTERVAL_SECONDS=30
MEMINFO_PATH="/proc/meminfo"

STRESS_PID=""

[[ -n "${RATF_DEBUG:-}" ]] && set -x

die() {
  echo "ERROR: $*" >&2
  exit 1
}

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
is_num() { [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]; }
uint_in() { is_uint "$1" && (( $1 >= $2 && $1 <= $3 )); }
pct_ok() { is_num "$1" && awk -v p="$1" 'BEGIN { exit !(p > 0 && p <= 100) }'; }

validate_config() {
  case "$MODE" in
    cpu|mem|both|inject) ;;
    *) die "MODE must be one of cpu, mem, both, inject, got '$MODE'" ;;
  esac
  uint_in "$DURATION_SECONDS" 1 999999999 || die "DURATION_SECONDS must be a whole number of seconds >= 1"
  is_uint "$CPU_WORKERS" || die "CPU_WORKERS must be a whole number (0 = one per CPU)"
  uint_in "$CPU_LOAD_PCT" 1 100 || die "CPU_LOAD_PCT must be a whole number from 1 to 100"
  pct_ok "$MEM_TARGET_PCT" || die "MEM_TARGET_PCT must be a number above 0 and up to 100"
  is_uint "$MEM_MAX_BYTES" || die "MEM_MAX_BYTES must be a whole number of bytes"
  is_uint "$MEM_MIN_AVAILABLE_BYTES" || die "MEM_MIN_AVAILABLE_BYTES must be a whole number of bytes"
  is_num "$INJECT_CPU_PCT" || die "INJECT_CPU_PCT must be a number"
  is_num "$INJECT_MEM_PCT" || die "INJECT_MEM_PCT must be a number"
  uint_in "$INJECT_INTERVAL_SECONDS" 1 999999999 || die "INJECT_INTERVAL_SECONDS must be a whole number of seconds >= 1"
  uint_in "$REPORT_INTERVAL_SECONDS" 1 999999999 || die "REPORT_INTERVAL_SECONDS must be a whole number of seconds >= 1"
}

read_meminfo() {
  [[ -r "$MEMINFO_PATH" ]] || die "Cannot read $MEMINFO_PATH"
  local out
  out="$(awk '/^MemTotal:/ { t = $2 * 1024 } /^MemAvailable:/ { a = $2 * 1024; seen = 1 }
              END { if (t > 0 && seen) printf "%.0f %.0f\n", t, a }' "$MEMINFO_PATH")"
  [[ -n "$out" ]] || die "$MEMINFO_PATH has no MemTotal/MemAvailable (not a Linux host?)"
  echo "$out"
}

mem_used_pct() {
  local info total avail
  info="$(read_meminfo)"
  read -r total avail <<< "$info"
  awk -v t="$total" -v a="$avail" 'BEGIN { printf "%.1f\n", (1 - a / t) * 100 }'
}

mem_bytes_to_allocate() {
  local info total avail
  info="$(read_meminfo)"
  read -r total avail <<< "$info"
  awk -v t="$total" -v a="$avail" -v p="$MEM_TARGET_PCT" -v cap="$MEM_MAX_BYTES" -v floor="$MEM_MIN_AVAILABLE_BYTES" 'BEGIN {
    wanted = int(t * p / 100) - (t - a)
    headroom = a - floor
    r = wanted
    if (headroom < r) r = headroom
    if (cap < r) r = cap
    if (r < 0) r = 0
    printf "%.0f\n", r
  }'
}

run_inject() {
  local deadline="$1" dir host written=0
  dir="$(dirname "$INJECT_LOG_PATH")"
  [[ -d "$dir" ]] || die "'$dir' does not exist. Is this agent enrolled in the linux_resource_utilization group (bootstrap-agent.sh creates it)?"
  host="$(uname -n)"
  while :; do
    printf '%s %s resource_usage_metric: cpu=%.2f mem=%.2f\n' \
      "$(date '+%b %d %H:%M:%S')" "$host" "$INJECT_CPU_PCT" "$INJECT_MEM_PCT" >> "$INJECT_LOG_PATH" 2>/dev/null \
      || die "Could not write to '$INJECT_LOG_PATH'"
    written=$((written + 1))
    if (( $(date +%s) + INJECT_INTERVAL_SECONDS > deadline )); then
      break
    fi
    sleep "$INJECT_INTERVAL_SECONDS"
  done
  echo "linux_resource_utilization simulation completed. Injected ${written} metric line(s) into ${INJECT_LOG_PATH}"
}

stop_load() {
  if [[ -n "$STRESS_PID" ]]; then
    kill -TERM "$STRESS_PID" 2>/dev/null || true
    wait "$STRESS_PID" 2>/dev/null || true
    STRESS_PID=""
  fi
}

on_interrupt() {
  stop_load
  echo "Interrupted; load released." >&2
  exit 130
}

hold() {
  local deadline="$1" next now
  next=$(( $(date +%s) + REPORT_INTERVAL_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if [[ -n "$STRESS_PID" ]] && ! kill -0 "$STRESS_PID" 2>/dev/null; then
      return
    fi
    sleep 1
    now=$(date +%s)
    if (( now >= next && now < deadline )); then
      echo "  ... $(( deadline - now ))s left, memory in use $(mem_used_pct)%"
      next=$(( next + REPORT_INTERVAL_SECONDS ))
    fi
  done
}

run_load() {
  local deadline="$1" args=() bytes before workers rc=0
  command -v stress-ng >/dev/null 2>&1 \
    || die "stress-ng is not installed on this agent. Install it with 'sudo apt-get install -y stress-ng' (Debian/Ubuntu) or 'sudo dnf install -y stress-ng' (RHEL/Fedora)."

  if [[ "$MODE" == cpu || "$MODE" == both ]]; then
    workers="$CPU_WORKERS"
    (( workers > 0 )) || workers="$(nproc)"
    args+=(--cpu "$workers" --cpu-load "$CPU_LOAD_PCT")
    echo "CPU: ${workers} worker(s) at ${CPU_LOAD_PCT}% load"
  fi

  if [[ "$MODE" == mem || "$MODE" == both ]]; then
    before="$(mem_used_pct)"
    bytes="$(mem_bytes_to_allocate)"
    if (( bytes > 0 )); then
      args+=(--vm 1 --vm-bytes "$bytes" --vm-keep --vm-populate --vm-hang 0)
      echo "Memory: holding $(( bytes / 1024 / 1024 )) MiB, in use ${before}% before (target ${MEM_TARGET_PCT}%)"
    else
      echo "Memory: in use ${before}% (target ${MEM_TARGET_PCT}%)"
      echo "  (nothing allocated: already at target, or the safety floor was reached)"
    fi
  fi

  trap on_interrupt INT TERM
  trap stop_load EXIT
  if (( ${#args[@]} > 0 )); then
    stress-ng --cache-size 64K "${args[@]}" --timeout "${DURATION_SECONDS}s" &
    STRESS_PID=$!
  fi

  hold "$deadline"

  if [[ -n "$STRESS_PID" ]]; then
    if kill -0 "$STRESS_PID" 2>/dev/null && (( $(date +%s) >= deadline )); then
      stop_load
    else
      wait "$STRESS_PID" || rc=$?
      STRESS_PID=""
      (( rc == 0 )) || die "stress-ng stopped with exit code ${rc}; see its output above."
    fi
  fi

  echo "linux_resource_utilization simulation completed. Load released."
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode=*) MODE="${1#*=}"; shift ;;
      --mode)   [[ $# -ge 2 ]] || die "--mode needs a value"; MODE="$2"; shift 2 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
}

main() {
  parse_args "$@"
  validate_config
  local deadline
  deadline=$(( $(date +%s) + DURATION_SECONDS ))

  echo "Simulating linux_resource_utilization (mode=${MODE}, duration=${DURATION_SECONDS}s) ..."
  echo "Expected detection: rule 100321 (LinuxResourceUtilization-Anomaly-Detected)"

  if [[ "$MODE" == inject ]]; then
    run_inject "$deadline"
  else
    run_load "$deadline"
  fi
}

main "$@"