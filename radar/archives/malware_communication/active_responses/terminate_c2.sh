#!/bin/bash

# terminate_c2.sh - Wazuh AR
LOG_FILE="/var/ossec/logs/active-responses.log"

# 1) Read full wrapper JSON from stdin
IFS= read -r wrapper_json
echo "$wrapper_json" >> "$LOG_FILE"

# 2) Make sure we got something
if [[ -z "$wrapper_json" ]]; then
    exit 0
fi

# 3) Extract C2 destination IP from extra_args[0]
if command -v jq >/dev/null 2>&1; then
    C2_IP=$(echo "$wrapper_json" | jq -r '.parameters.extra_args[0]')
else
    C2_IP=$(echo "$wrapper_json" | grep -oP '"extra_args":\["\K[^"]+')
fi

if [[ -z "$C2_IP" ]]; then
    echo "$(date) [terminate_c2] No destination IP provided in extra_args." >> "$LOG_FILE"
    exit 1
fi

echo "$(date) [terminate_c2] Terminating connections to $C2_IP" >> "$LOG_FILE"

# Find PIDs communicating with that destination IP
PIDS=$(ss -ntp | grep "$C2_IP" | awk -F',' '{print $2}' | awk '{print $1}' | sort -u)

if [[ -z "$PIDS" ]]; then
    echo "$(date) [terminate_c2] No processes found for $C2_IP" >> "$LOG_FILE"
    exit 0
fi

for PID in $PIDS; do
    if [[ "$PID" =~ ^[0-9]+$ ]]; then
        kill -9 "$PID"
        echo "$(date) [terminate_c2] Terminated PID $PID for connection to $C2_IP" >> "$LOG_FILE"
    fi
done

exit 0
