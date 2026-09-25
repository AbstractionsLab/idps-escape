#!/usr/bin/env bash

dexec() {
  docker exec "$CONTAINER" bash -lc "$1"
}

dexec_quiet() {
  docker exec "$CONTAINER" bash -lc "$1" 2>/dev/null
}

detect_manager_address() {
  local addr
  addr="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')"
  if [[ -z "$addr" ]]; then
    addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  printf '%s' "$addr"
}

_radar_env_value() {
  local raw="$1" out="" i ch next rest
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  if [[ "$raw" == \'* ]]; then
    rest="${raw:1}"
    [[ "$rest" == *\'* ]] || return 1
    out="${rest%%\'*}"
    rest="${rest#*\'}"
    rest="${rest#"${rest%%[![:space:]]*}"}"
    [[ -z "$rest" || "$rest" == \#* ]] || return 1
    REPLY="$out"; return 0
  fi
  if [[ "$raw" == \"* ]]; then
    for (( i = 1; i < ${#raw}; i++ )); do
      ch="${raw:i:1}"
      if [[ "$ch" == '\' && $(( i + 1 )) -lt ${#raw} ]]; then
        next="${raw:i+1:1}"
        case "$next" in
          '\'|'"'|'$'|'`') out+="$next"; (( i++ )); continue ;;
        esac
      fi
      if [[ "$ch" == '"' ]]; then
        rest="${raw:i+1}"
        rest="${rest#"${rest%%[![:space:]]*}"}"
        [[ -z "$rest" || "$rest" == \#* ]] || return 1
        REPLY="$out"; return 0
      fi
      out+="$ch"
    done
    return 1
  fi
  out="$raw"
  for (( i = 1; i < ${#raw}; i++ )); do
    if [[ "${raw:i:1}" == '#' && "${raw:i-1:1}" == [[:space:]] ]]; then
      out="${raw:0:i}"; break
    fi
  done
  out="${out%"${out##*[![:space:]]}"}"
  REPLY="$out"
}

radar_load_env() {
  local radar_root="${1:?radar_load_env: RADAR_ROOT is required}"
  local file="$radar_root/.env" line key n=0
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    (( n++ )) || true
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^export[[:space:]]+(.*)$ ]] && line="${BASH_REMATCH[1]}"
    if [[ ! "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      echo "[!] .env line $n ignored: not KEY=value" >&2
      continue
    fi
    key="${BASH_REMATCH[1]}"
    if ! _radar_env_value "${BASH_REMATCH[2]}"; then
      echo "[!] .env line $n ($key) ignored: unterminated or malformed quoting" >&2
      continue
    fi
    export "$key=$REPLY"
  done < "$file"
}

radar_env_set() {
  local radar_root="${1:?}" key="${2:?}" value="${3-}"
  printf '%s\n' "$value" | PYTHONPATH="$radar_root" python3 -m wazuh_api.envfile set "$key" "$radar_root/.env"
}

radar_manager_container() {
  local radar_root="${1:?radar_manager_container: RADAR_ROOT is required}"
  PYTHONPATH="$radar_root" python3 -m wazuh_api.cli manager-container 2>/dev/null || echo "wazuh.manager"
}

radar_hostpath() {
  local radar_root="${1:?radar_hostpath: RADAR_ROOT is required}"
  local container_path="${2:?radar_hostpath: container_path is required}"
  local container="${3:-}"
  if [[ -n "$container" ]]; then
    PYTHONPATH="$radar_root" python3 -m wazuh_api.cli manager-volume-path "$container_path" --container "$container" 2>/dev/null
  else
    PYTHONPATH="$radar_root" python3 -m wazuh_api.cli manager-volume-path "$container_path" 2>/dev/null
  fi
}

radar_manager_containers() {
  local radar_root="${1:?radar_manager_containers: RADAR_ROOT is required}"
  PYTHONPATH="$radar_root" python3 -m wazuh_api.cli manager-containers 2>/dev/null
}