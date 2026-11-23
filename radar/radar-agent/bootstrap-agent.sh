#!/usr/bin/env bash
# Usage:
#   bootstrap-agent.sh --manager <address> --token <secret> --group <group-name> [--agent-name <name>]
#
# Run it from inside the radar-agent folder, copied whole to the endpoint:
# the active response scripts, collectors and libraries are read from there.
#
# --manager      Wazuh manager address (host or IP) the agent should enroll to
# --token        Enrollment password (matches the manager's authd shared
#                password -- mint one with `python3 -m wazuh_api.cli
#                mint-enrollment-token` on the manager)
# --group        Wazuh group to assign this agent to. Repeat for multiple
#                groups, e.g. --group default --group suspicious_login
# --agent-name   Name to register as (defaults to this host's hostname)
# --version      Agent package version to install. Defaults to
#                WAZUH_AGENT_VERSION if set in the environment, else 4.14.1-1
# --allow-service  (log_volume / linux_resource_utilization) systemd service terminate_service.sh
#                may stop. Repeatable or comma-separated. Anything not listed
#                is refused; with none listed, no service can be stopped.
#
# After install, this script pins wazuh-agent to the installed version and
# disables automatic updates for it (apt-mark hold / yum|dnf versionlock),
# per Wazuh's own recommendation -- otherwise a routine, unrelated fleet-wide
# OS package update can silently bump the agent version on this endpoint.
# Note: since the install step above is skipped entirely when the agent is
# already present, re-running this script with a different --version will
# NOT move an already-enrolled endpoint to that version -- deliberately
# upgrading a pinned agent is a separate, explicit action (unhold/versionlock
# delete, install the target version, re-hold/versionlock), not this script.

set -Eeuo pipefail

AGENT_NAME="$(hostname)"
MANAGER=""
TOKEN=""
AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.14.1-1}"
TARGET_GROUPS=()
ALLOWED_SERVICES=()

usage() {
  # Prints the header comment block, up to the first non-comment line.
  awk 'NR == 1 { next } /^#/ { sub(/^#/, ""); sub(/^  ?/, ""); print; next } { exit }' "$0"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager)     MANAGER="$2";        shift 2 ;;
    --token)       TOKEN="$2";          shift 2 ;;
    --group)
      IFS=',' read -ra _groups_split <<< "$2"
      TARGET_GROUPS+=("${_groups_split[@]}")
      shift 2
      ;;
    --agent-name)  AGENT_NAME="$2";     shift 2 ;;
    --version)     AGENT_VERSION="$2";  shift 2 ;;
    --allow-service)
      IFS=',' read -ra _services_split <<< "$2"
      ALLOWED_SERVICES+=("${_services_split[@]}")
      shift 2
      ;;
    --help|-h)     usage ;;
    *) echo "Unknown option: $1"; usage 2 ;;
  esac
done

[[ -n "$MANAGER" ]] || { echo "ERROR: --manager is required"; usage 2; }
[[ -n "$TOKEN" ]] || { echo "ERROR: --token is required"; usage 2; }
for _svc in "${ALLOWED_SERVICES[@]}"; do
  [[ "$_svc" =~ ^[A-Za-z0-9][A-Za-z0-9@._:-]*$ ]] \
    || { echo "ERROR: invalid --allow-service name: $_svc"; usage 2; }
done

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run this as root"; exit 1
fi

fail() {
  echo "FAILED: $1" >&2
  echo "Next step: $2" >&2
  exit 1
}

agent_pkg_registered() {
  if command -v dpkg-query >/dev/null 2>&1; then
    local s
    s=$(dpkg-query -W -f='${db:Status-Status}' wazuh-agent 2>/dev/null) || return 1
    [[ -n "$s" && "$s" != "not-installed" ]]
  elif command -v rpm >/dev/null 2>&1; then
    rpm -q wazuh-agent >/dev/null 2>&1
  else
    return 1
  fi
}

# --- Files shipped in this folder --------------------------------------------
# bootstrap-agent.sh must be run from the radar-agent folder it ships in:
# active response scripts, collectors, libraries and package config are all
# read from here, and checked before anything on the system is changed.
RADAR_AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
AR_MAPPING_LIB="$RADAR_AGENT_DIR/helpers/ar-mapping.sh"
AR_DISPATCHER="$RADAR_AGENT_DIR/helpers/ar-dispatch.sh"
AR_DISPATCHER_MARKER="# RADAR active response dispatcher."
RADAR_AGENT_HOME=/var/ossec/radar-agent

COLLECTORS_LIB="$RADAR_AGENT_DIR/helpers/collectors.sh"
WAZUH_YUM_REPO="$RADAR_AGENT_DIR/packaging/wazuh.repo"

[[ -f "$AR_MAPPING_LIB" && -f "$AR_DISPATCHER" && -f "$COLLECTORS_LIB" ]] \
  || fail "$RADAR_AGENT_DIR/helpers is incomplete (need ar-mapping.sh, ar-dispatch.sh and collectors.sh)" \
          "deploy the full radar-agent folder and run bootstrap-agent.sh from inside it"
# shellcheck source-path=SCRIPTDIR source=helpers/ar-mapping.sh
source "$AR_MAPPING_LIB"
AR_MAPPING_FILE="$RADAR_AGENT_DIR/$AR_MAPPING_FILE_NAME"

# Every script in the catalog is installed on every endpoint, whatever its
# groups: which scenario uses which action is decided on the manager
# (ar.yaml, editable from the GUI), and the manager can trigger any of them on
# any agent. Installing only a subset would make a later GUI binding, or a
# later group assignment, fail silently on this endpoint.
# Fail before touching the system if the catalog or a listed script is broken.
AR_PLAN=$(ar_mapping_parse "$AR_MAPPING_FILE") \
  || fail "could not read the active response catalog $AR_MAPPING_FILE (see error above)" \
          "fix the catalog, or deploy the full radar-agent folder"
while IFS=$'\t' read -r AR_NAME AR_PATH; do
  [[ -n "$AR_NAME" ]] || continue
  [[ -f "$RADAR_AGENT_DIR/$AR_PATH" ]] \
    || fail "$AR_MAPPING_FILE_NAME maps ${AR_NAME} to ${AR_PATH}, which is not in $RADAR_AGENT_DIR" \
            "deploy the full radar-agent folder, or fix the catalog"
done <<<"$AR_PLAN"

# Collectors are per scenario: only the groups this endpoint joins get theirs.
# shellcheck source-path=SCRIPTDIR source=helpers/collectors.sh
source "$COLLECTORS_LIB"
COLLECTOR_DIRS=()
for g in "${TARGET_GROUPS[@]}"; do
  d=$(collector_dir "$RADAR_AGENT_DIR" "$g")
  [[ -n "$d" ]] || continue
  collector_validate "$d" \
    || fail "invalid collector for group '$g' (see error above)" \
            "fix $d, or deploy the full radar-agent folder"
  COLLECTOR_DIRS+=("$d")
done

[[ -f "$WAZUH_YUM_REPO" ]] \
  || fail "$WAZUH_YUM_REPO not found" \
          "deploy the full radar-agent folder and run bootstrap-agent.sh from inside it"

echo "=== bootstrap-agent.sh ==="
echo "Manager  : $MANAGER"
echo "Groups   : ${TARGET_GROUPS[*]}"
echo "Name     : $AGENT_NAME"
echo "Version  : $AGENT_VERSION"
echo "==========================="

if [[ ! -x /var/ossec/bin/agent-auth ]] && agent_pkg_registered; then
  if command -v dpkg-query >/dev/null 2>&1; then
    RECOVERY="for s in prerm postrm; do f=/var/lib/dpkg/info/wazuh-agent.\$s; [ -e \"\$f\" ] && printf '#!/bin/sh\\nexit 0\\n' > \"\$f\"; done; sudo apt-mark unhold wazuh-agent; sudo apt-get purge -y wazuh-agent"
  else
    RECOVERY="rpm -e --noscripts wazuh-agent"
  fi
  fail "wazuh-agent is registered with the package manager but /var/ossec/bin/agent-auth is missing (left over from a failed uninstall)" \
       "as root, run: ${RECOVERY} -- then re-run this script"
fi

if [[ ! -x /var/ossec/bin/agent-auth ]]; then
  echo ">>> Installing Wazuh agent package..."
  if command -v apt-get >/dev/null 2>&1; then
    KEYRING=/usr/share/keyrings/wazuh.gpg
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor --yes -o "$KEYRING" \
      || fail "could not import Wazuh GPG key check network access to packages.wazuh.com"
    chmod 644 "$KEYRING"
    echo "deb [signed-by=$KEYRING] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq || fail "apt-get update failed" "check network access and apt sources"
    WAZUH_MANAGER="$MANAGER" apt-get install -y "wazuh-agent=${AGENT_VERSION}" \
      || fail "package install failed for wazuh-agent=${AGENT_VERSION}" \
              "confirm this version exists: apt-cache madison wazuh-agent"
  elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    PKG_MGR=$(command -v dnf || command -v yum)
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      || fail "could not import Wazuh GPG key check network access to packages.wazuh.com"
    install -o root -g root -m 0644 "$WAZUH_YUM_REPO" /etc/yum.repos.d/wazuh.repo
    WAZUH_MANAGER="$MANAGER" "$PKG_MGR" install -y "wazuh-agent-${AGENT_VERSION}" \
      || fail "package install failed for wazuh-agent-${AGENT_VERSION}" \
              "confirm this version exists: ${PKG_MGR} --showduplicates list wazuh-agent"
  else
    fail "no supported package manager found (need apt-get, yum, or dnf)" \
         "install the Wazuh agent manually, then re-run this script"
  fi
  echo "OK - package installed"
else
  echo "OK - Wazuh agent already installed, skipping package install"
fi

warn() {
  echo "WARNING: $1" >&2
}

echo ">>> Pinning wazuh-agent to ${AGENT_VERSION} and disabling automatic updates..."
if command -v apt-get >/dev/null 2>&1; then
  if apt-mark hold wazuh-agent >/dev/null; then
    echo "OK - wazuh-agent held (apt-mark hold); 'apt upgrade' will not touch it"
  else
    warn "'apt-mark hold wazuh-agent' failed on agent. Run 'apt-mark hold wazuh-agent' manually."
  fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PIN_PKG_MGR=$(command -v dnf || command -v yum)
  "$PIN_PKG_MGR" install -y 'dnf-command(versionlock)' >/dev/null 2>&1 || true
  "$PIN_PKG_MGR" install -y dnf-plugin-versionlock >/dev/null 2>&1 || true
  "$PIN_PKG_MGR" install -y yum-plugin-versionlock >/dev/null 2>&1 || true
  if "$PIN_PKG_MGR" versionlock add wazuh-agent >/dev/null 2>&1; then
    echo "OK - wazuh-agent version-locked (${PIN_PKG_MGR} versionlock); a fleet-wide update will not touch it"
  else
    warn "'${PIN_PKG_MGR} versionlock add wazuh-agent' failed"
  fi
else
  warn "no supported package manager found to pin wazuh-agent"
fi

echo ">>> Setting manager address in ossec.conf..."
OSSEC_CONF=/var/ossec/etc/ossec.conf
if grep -q "<address>" "$OSSEC_CONF"; then
  sed -i "s|<address>[^<]*</address>|<address>${MANAGER}</address>|" "$OSSEC_CONF"
elif grep -q "<server>" "$OSSEC_CONF"; then
  perl -0777 -i -pe "s|<server>\s*</server>|<server>\n      <address>${MANAGER}</address>\n      <port>1514</port>\n      <protocol>tcp</protocol>\n    </server>|" "$OSSEC_CONF"
  grep -q "<address>${MANAGER}</address>" "$OSSEC_CONF" \
    || fail "found an empty <server></server> block but could not insert an <address> into it" "check the <server> block manually"
else
  fail "no <server> block found in $OSSEC_CONF" "check the <client> block manually"
fi

GROUPS_CSV=$(IFS=','; echo "${TARGET_GROUPS[*]}")
CLIENT_KEYS=/var/ossec/etc/client.keys

KEY_BACKUP_DIR=/var/lib/radar-agent
KEY_RESTORED=false
if [[ ! -s "$CLIENT_KEYS" && -s "$KEY_BACKUP_DIR/client.keys" ]]; then
  KEPT_NAME=$(awk 'NF >= 4 { print $2; exit }' "$KEY_BACKUP_DIR/client.keys")
  KEPT_MANAGER=$(head -1 "$KEY_BACKUP_DIR/manager" 2>/dev/null || true)
  if [[ "$KEPT_NAME" == "$AGENT_NAME" && "$KEPT_MANAGER" == "$MANAGER" ]]; then
    install -o root -g wazuh -m 0640 "$KEY_BACKUP_DIR/client.keys" "$CLIENT_KEYS"
    KEY_RESTORED=true
    echo "OK - restored this endpoint's previous agent key for '$AGENT_NAME'"
  else
    warn "kept agent key is for '${KEPT_NAME:-?}' on manager '${KEPT_MANAGER:-?}', not '$AGENT_NAME' on '$MANAGER'; not restoring it"
  fi
fi

echo ">>> Registering with manager $MANAGER..."
if ! /var/ossec/bin/agent-auth -m "$MANAGER" -P "$TOKEN" -A "$AGENT_NAME" -G "$GROUPS_CSV" 2>/tmp/agent-auth.err; then
  if grep -q "Duplicate agent name" /tmp/agent-auth.err; then
    if [[ "$KEY_RESTORED" == "true" ]]; then
      echo "OK - reconnecting as the existing agent '$AGENT_NAME': it keeps its ID and groups on the manager"
    elif [[ -s "$CLIENT_KEYS" ]]; then
      echo "OK - agent name already registered, and $CLIENT_KEYS already has a key"
    else
      cat /tmp/agent-auth.err
      fail "the manager already has an agent named '$AGENT_NAME', but this endpoint has no key for it" \
           "deregister '$AGENT_NAME' in the RADAR GUI (Agent Management > Deregister agent), then mint a new token and re-run this script"
    fi
  elif grep -qi "Invalid password\|Unable to connect" /tmp/agent-auth.err; then
    cat /tmp/agent-auth.err
    fail "enrollment rejected by manager" \
           "check the token is correct and not expired, and that $MANAGER:1515 is reachable"
  else
    cat /tmp/agent-auth.err
    fail "agent-auth failed" "see error above"
  fi
fi

# The endpoint has a working key again; the kept copy is no longer needed.
rm -rf "$KEY_BACKUP_DIR"

for COLLECTOR in "${COLLECTOR_DIRS[@]}"; do
  echo ">>> Installing the ${COLLECTOR##*/} metric collector (systemd timer)..."
  STARTED=$(collector_install "$COLLECTOR") \
    || fail "could not install the ${COLLECTOR##*/} collector (see error above)" \
            "check: systemctl status, journalctl -xe"
  while IFS= read -r TIMER; do
    [[ -n "$TIMER" ]] && echo "OK - installed and started ${TIMER}"
  done <<<"$STARTED"
done

echo ">>> Enabling and starting the Wazuh agent service..."
systemctl enable wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent \
  || fail "wazuh-agent service failed to start" "check: journalctl -u wazuh-agent -n 50"

echo ">>> Installing active response scripts..."
mkdir -p /var/ossec/active-response/bin
chown root:wazuh /var/ossec/active-response/bin
chmod 0755 /var/ossec/active-response/bin

in_plan() {
  local want="$1" name _path
  while IFS=$'\t' read -r name _path; do
    [[ "$name" == "$want" ]] && return 0
  done <<<"$AR_PLAN"
  return 1
}

# Copies the mapping, the library and every script under active_responses/
# into RADAR_AGENT_HOME (root-owned), replacing any previous copy. The
# dispatchers read from there at run time, so other script versions shipped
# in the folder can be switched to later by editing the mapping only.
install_radar_agent_home() {
  local staging="${RADAR_AGENT_HOME}.new" rel
  rm -rf "$staging"
  install -d -o root -g wazuh -m 0750 "$staging" "$staging/helpers" "$staging/$AR_SCRIPTS_DIR"
  install -o root -g wazuh -m 0640 "$AR_MAPPING_FILE" "$staging/$AR_MAPPING_FILE_NAME"
  install -o root -g wazuh -m 0640 "$AR_MAPPING_LIB" "$staging/helpers/ar-mapping.sh"
  install -o root -g wazuh -m 0640 "$AR_DISPATCHER" "$staging/helpers/ar-dispatch.sh"
  while IFS= read -r -d '' rel; do
    install -d -o root -g wazuh -m 0750 "$staging/$rel"
  done < <(cd "$RADAR_AGENT_DIR" && find "$AR_SCRIPTS_DIR" -mindepth 1 -type d -print0)
  while IFS= read -r -d '' rel; do
    install -o root -g wazuh -m 0750 "$RADAR_AGENT_DIR/$rel" "$staging/$rel"
  done < <(cd "$RADAR_AGENT_DIR" && find "$AR_SCRIPTS_DIR" -type f -print0)
  rm -rf "$RADAR_AGENT_HOME"
  mv "$staging" "$RADAR_AGENT_HOME"
}

if [[ -n "$AR_PLAN" ]]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo ">>> Installing jq (needed by the active response scripts)..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y -qq jq >/dev/null || true
    elif JQ_PKG_MGR=$(command -v dnf || command -v yum); then
      "$JQ_PKG_MGR" install -y jq >/dev/null || true
    fi
    command -v jq >/dev/null 2>&1 \
      || warn "jq is not installed; the active response scripts will refuse to act until it is"
  fi
fi

# terminate_service.sh is installed on every endpoint, so its allowlist is
# always created. A missing or empty allowlist means no service can be
# stopped; the script can then only kill connections to an IP.
if in_plan "terminate_service.sh"; then
  SERVICES_FILE=/var/ossec/etc/radar-terminable-services
  if [[ ${#ALLOWED_SERVICES[@]} -gt 0 ]]; then
    {
      echo "# Services terminate_service.sh may stop, one per line (written by bootstrap-agent.sh)."
      printf '%s\n' "${ALLOWED_SERVICES[@]}"
    } > "$SERVICES_FILE"
  elif [[ ! -f "$SERVICES_FILE" ]]; then
    echo "# Services terminate_service.sh may stop, one per line. Empty = none." > "$SERVICES_FILE"
  fi
  chown root:wazuh "$SERVICES_FILE"
  chmod 0640 "$SERVICES_FILE"
  if ! grep -qv '^[[:space:]]*\(#\|$\)' "$SERVICES_FILE"; then
    warn "no services listed in $SERVICES_FILE; terminate_service.sh can only kill connections to an IP (use --allow-service to allow stopping a service)"
  fi
fi

if [[ -n "$AR_PLAN" ]]; then
  install_radar_agent_home
  echo "OK - copied active response catalog and scripts to $RADAR_AGENT_HOME"
  while IFS=$'\t' read -r AR_NAME AR_PATH; do
    install -o root -g wazuh -m 0750 "$AR_DISPATCHER" "/var/ossec/active-response/bin/${AR_NAME}"
    ar_resolve_script "$RADAR_AGENT_HOME" "$AR_NAME" 0 >/dev/null \
      || fail "installed ${AR_NAME} but it does not resolve to a trusted script (see error above)" \
              "check ownership and permissions under $RADAR_AGENT_HOME"
    echo "OK - installed ${AR_NAME} -> ${AR_PATH}"
  done <<<"$AR_PLAN"
else
  echo "OK - the active response catalog is empty, no script installed"
fi

# Remove dispatchers left behind for names no longer in the catalog. Only
# files carrying the dispatcher's marker line are touched.
for AR_FILE in /var/ossec/active-response/bin/*; do
  [[ -f "$AR_FILE" ]] || continue
  grep -qxF "$AR_DISPATCHER_MARKER" "$AR_FILE" 2>/dev/null || continue
  in_plan "${AR_FILE##*/}" && continue
  rm -f "$AR_FILE"
  echo "OK - removed ${AR_FILE##*/} (no longer in the catalog)"
done

if systemctl is-active --quiet wazuh-agent; then
  echo "=== SUCCESS ==="
else
  fail "service did not reach the active state" "check: journalctl -u wazuh-agent -n 50"
fi