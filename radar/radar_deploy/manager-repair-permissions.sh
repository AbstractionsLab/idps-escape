#!/usr/bin/env bash

set -Eeuo pipefail

RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./_lib.sh
source "$RADAR_ROOT/radar_deploy/_lib.sh"
CONTAINER="${1:-$(radar_manager_container "$RADAR_ROOT")}"

if [[ $EUID -ne 0 ]]; then
  echo "[!] manager-repair-permissions.sh needs root; skipping." >&2
  exit 0
fi

docker exec -i -u root "$CONTAINER" bash -s <<'IN_CONTAINER'
set -u
REF=/var/ossec/data_tmp/permanent
fixed=0
for d in /var/ossec/api/configuration /var/ossec/etc /var/ossec/logs /var/ossec/queue \
         /var/ossec/var/multigroups /var/ossec/integrations /var/ossec/active-response/bin /etc/filebeat; do
  [ -d "$d" ] || continue
  while IFS= read -r -d '' p; do
    r="$REF$p"
    if [ -e "$r" ] && [ ! -L "$r" ]; then
      chown --reference="$r" -- "$p" && chmod --reference="$r" -- "$p"
    else
      chmod o-rwx -- "$p"
    fi
    fixed=$((fixed + 1))
  done < <(find "$d" -xdev ! -type l -perm -0002 -print0 2>/dev/null)
done
if [ "$fixed" -gt 0 ]; then
  echo "OK - reset $fixed world-writable path(s) in the manager"
else
  echo "OK - no world-writable paths in the manager"
fi
IN_CONTAINER

OVERLAY_YAML="$(PYTHONPATH="$RADAR_ROOT" python3 -m wazuh_api.cli core-volumes-overlay 2>/dev/null)" || OVERLAY_YAML=""
PARENT="$(python3 - "$OVERLAY_YAML" <<'PY'
import os, re, sys
paths = [m.split(":", 1)[0] for m in re.findall(r"^\s*-\s*(/\S+)", sys.argv[1], re.M)]
if paths:
    parent = os.path.commonpath([os.path.dirname(p) if not os.path.isdir(p) else p for p in paths])
    protected = {"/", "/srv", "/var", "/var/lib", "/opt", "/home", "/root", "/etc", "/usr", "/mnt", "/media", "/tmp", "/data"}
    if parent not in protected and parent.count("/") >= 2:
        print(parent)
PY
)"
if [[ -n "$PARENT" && -d "$PARENT" && "$(stat -c %u "$PARENT")" == 0 ]]; then
  chmod o-rwx "$PARENT"
  echo "OK - $PARENT is closed to other local users"
elif [[ -n "$PARENT" ]]; then
  echo "[!] $PARENT is not a root-owned directory; left unchanged." >&2
fi
