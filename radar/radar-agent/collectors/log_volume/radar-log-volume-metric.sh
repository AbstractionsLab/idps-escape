#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/radar/log_volume_metric.log"
BYTES=$(du -sb /var/log 2>/dev/null | awk '{print $1}')
printf '%s %s log_volume_metric: /var/log %s\n' \
  "$(date '+%b %d %H:%M:%S')" "$(hostname)" "${BYTES:-0}" >> "$LOG_FILE"
