#!/usr/bin/bash

LOG_FILE="/var/ossec/logs/active-responses.log"

# 1) Read exactly one line (up to the newline) from STDIN
#    If execd hands you the wrapper on STDIN, it will be one JSON blob + "\n"
IFS= read -r wrapper_json

# 2) Bail out if empty
if [[ -z "$wrapper_json" ]]; then
  exit 0
fi

# 3) Parse out the values
action=$(jq -r '.command' <<<"$wrapper_json")
user=$(jq -r '.parameters.extra_args[0]' <<<"$wrapper_json")


# 4) Do add/delete
if [[ "$action" == "add" ]]; then
  usermod -L "$user"
  echo "$(date) [lock_user_linux] Locked $user" >> "$LOG_FILE"
else
  usermod -U "$user"
  echo "$(date) [lock_user_linux] Unlocked $user" >> "$LOG_FILE"
fi

exit 0
