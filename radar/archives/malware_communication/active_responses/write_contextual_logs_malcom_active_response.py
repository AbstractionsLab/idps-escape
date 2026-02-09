#!/usr/bin/bash
#
# write_log.sh
# Reads the full Wazuh wrapper JSON on stdin, extracts user + events
LOG_FILE="/var/ossec/logs/ad_pc_enriched.log"


#read -r -d '' wrapper_json <&0
IFS= read -r wrapper_json
echo "$wrapper_json" >>  "$LOG_FILE"

# 2) Make sure we got something
if [[ -z "$wrapper_json" ]]; then
    exit 0
fi

# 3) Parse the wrapper and confirm action is "add"
command=$(jq -r '.command' <<<"$wrapper_json")
if [[ "$command" != "add" ]]; then
    # nothing to do on "delete" or other actions
    exit 0
fi

# 4) Extract the user and the events JSON blob
ipaddr=$(jq -r '.parameters.alert.data.ip_keyword' <<<"$wrapper_json")
events_json=$(jq -c '.parameters.extra_args[1]' <<<"$wrapper_json")

# 5) Append to the enrichment log
echo "===== $(date -Iseconds) Enrichment for IP address $ipaddr =====" >> "$LOG_FILE"
echo "$events_json" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"