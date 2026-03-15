#!/bin/bash

# terminate_c2.sh - Wazuh AR
LOG_FILE="/var/ossec/logs/active-responses.log"

# 1) Read full wrapper JSON from stdin
IFS= read -r wrapper_json
echo "$(date) [terminate_c2] $wrapper_json" >> "$LOG_FILE"

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
    echo "$(date) [terminate_c2] No destination IP/service provided in extra_args." >> "$LOG_FILE"
    exit 1
fi

is_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r a b c d <<<"$ip"
    [[ "$a" -le 255 && "$b" -le 255 && "$c" -le 255 && "$d" -le 255 ]]
}

if ! is_ipv4 "$C2_IP"; then
    echo "$(date) [terminate_c2] Treating target as service '$C2_IP'" >> "$LOG_FILE"

    SVC_NAME="${C2_IP%.service}"
    if command -v systemctl >/dev/null 2>&1; then
        UNIT="$C2_IP"
        [[ "$UNIT" != *.service ]] && UNIT="${SVC_NAME}.service"
        echo "$(date) [terminate_c2] systemctl stop $UNIT" >> "$LOG_FILE"
        systemctl stop "$UNIT" >> "$LOG_FILE" 2>&1
        exit $?
    fi
    if command -v service >/dev/null 2>&1; then
        echo "$(date) [terminate_c2] service $SVC_NAME stop" >> "$LOG_FILE"
        service "$SVC_NAME" stop >> "$LOG_FILE" 2>&1
        exit $?
    fi
    if [[ -x "/etc/init.d/$SVC_NAME" ]]; then
        echo "$(date) [terminate_c2] /etc/init.d/$SVC_NAME stop" >> "$LOG_FILE"
        "/etc/init.d/$SVC_NAME" stop >> "$LOG_FILE" 2>&1
        exit $?
    fi
    echo "$(date) [terminate_c2] No supported service manager found for '$C2_IP'" >> "$LOG_FILE"
    exit 1
else
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
fi
