#!/usr/bin/bash

LOG_FILE="/var/ossec/logs/blocked_users.log"

# 1) Read exactly one line (up to the newline) from STDIN
#    If execd hands you the wrapper on STDIN, it will be one JSON blob + "\n"
IFS= read -r wrapper_json

# 2) Bail out if empty
if [[ -z "$wrapper_json" ]]; then
  exit 0
fi

# 3) Parse out the values
action=$(jq -r '.command' <<<"$wrapper_json")
user  =$(jq -r '.parameters.data.user_keyword' <<<"$wrapper_json")

# 4) Send the control message (must end with a newline)
cat <<EOF
{
  "version":1,
  "origin":{"name":"lock_user.sh","module":"active-response"},
  "command":"check_keys",
  "parameters":{"keys":["$user"]}
}
EOF

# 5) Read execd’s response (one line)
IFS= read -r resp_json
resp_cmd=$(jq -r '.command' <<<"$resp_json")
if [[ "$resp_cmd" != "continue" ]]; then
  exit 0
fi

# 6) Do add/delete
ts=$(date -Iseconds)
if [[ "$action" == "add" ]]; then
  usermod -L "$user"
  echo "$ts: Locked $user" >> "$LOG_FILE"
else
  usermod -U "$user"
  echo "$ts: Unlocked $user" >> "$LOG_FILE"
fi

exit 0
