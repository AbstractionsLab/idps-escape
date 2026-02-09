#!/bin/bash

# Wazuh Active Response - Rate Limiting with fallback to limit
LOG_FILE="/var/ossec/logs/active-responses.log"
RATE_LIMIT="20/minute"
BURST="10"

# Read Wazuh wrapper JSON from stdin
IFS= read -r wrapper_json
if [[ -z "$wrapper_json" ]]; then
  exit 0
fi

# Extract action type
action=$(jq -r '.command' <<<"$wrapper_json")
if [[ "$action" != "add" ]]; then
  echo "$(date '+%Y/%m/%d %H:%M:%S') - rate-limit.sh: Ignoring action=$action" >> "$LOG_FILE"
  exit 0
fi

# Extract Source IP from arguments
SRC_IP=$(jq -r '.parameters.extra_args[0]' <<<"$wrapper_json")
if [[ -z "$SRC_IP" || "$SRC_IP" == "null" ]]; then
  echo "$(date '+%Y/%m/%d %H:%M:%S') - rate-limit.sh: No source IP provided in extra_args" >> "$LOG_FILE"
  exit 1
fi

# Try hashlimit first
iptables -I INPUT 1 -s "$SRC_IP" -p tcp --dport 80 -m hashlimit \
  --hashlimit-name wazuh_limit_$SRC_IP \
  --hashlimit $RATE_LIMIT \
  --hashlimit-burst $BURST \
  --hashlimit-mode srcip \
  --hashlimit-htable-expire 60000 \
  -j ACCEPT

if [[ $? -eq 0 ]]; then
  echo "$(date '+%Y/%m/%d %H:%M:%S') - rate-limit.sh: Applied hashlimit to $SRC_IP" >> "$LOG_FILE"
  exit 0
else
  # Fallback to global limit (not per IP)
  iptables -I INPUT 1 -s "$SRC_IP" -p tcp --dport 80 -m limit \
  --limit $RATE_LIMIT \
  --limit-burst $BURST \
  -j ACCEPT
  if [[ $? -eq 0 ]]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') - rate-limit.sh: hashlimit failed, applied fallback global limit to $SRC_IP" >> "$LOG_FILE"
    exit 0
  else
    echo "$(date '+%Y/%m/%d %H:%M:%S') - rate-limit.sh: FATAL: Failed to apply both hashlimit and fallback limit for $SRC_IP" >> "$LOG_FILE"
    exit 1
  fi
fi