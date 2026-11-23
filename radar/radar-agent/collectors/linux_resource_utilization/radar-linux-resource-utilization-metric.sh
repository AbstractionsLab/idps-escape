#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/radar/resource_usage_metric.log"

read_cpu_sample() {
  awk '/^cpu / {total=0; for(i=2;i<=NF;i++) total+=$i; print total, $5}' /proc/stat
}

read -r T1_TOTAL T1_IDLE < <(read_cpu_sample)
sleep 1
read -r T2_TOTAL T2_IDLE < <(read_cpu_sample)

D_TOTAL=$((T2_TOTAL - T1_TOTAL))
D_IDLE=$((T2_IDLE - T1_IDLE))
if [[ "$D_TOTAL" -gt 0 ]]; then
  CPU_PCT=$(awk -v dt="$D_TOTAL" -v di="$D_IDLE" 'BEGIN{printf "%.2f", (1-(di/dt))*100}')
else
  CPU_PCT="0.00"
fi

MEM_TOTAL=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
MEM_AVAIL=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
if [[ "${MEM_TOTAL:-0}" -gt 0 ]]; then
  MEM_PCT=$(awk -v t="$MEM_TOTAL" -v a="${MEM_AVAIL:-0}" 'BEGIN{printf "%.2f", (1-(a/t))*100}')
else
  MEM_PCT="0.00"
fi

printf '%s %s resource_usage_metric: cpu=%s mem=%s\n' \
  "$(date '+%b %d %H:%M:%S')" "$(hostname)" "$CPU_PCT" "$MEM_PCT" >> "$LOG_FILE"
