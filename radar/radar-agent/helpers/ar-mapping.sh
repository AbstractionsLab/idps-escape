#!/usr/bin/env bash
# RADAR agent: catalog of active response scripts (ar-scripts.yaml).
#
# Sourced by bootstrap-agent.sh (install time) and ar-dispatch.sh (run time).
# Functions print tab-separated records on stdout and errors on stderr, and
# return non-zero on failure. They never exit the calling shell.
#
# Supported YAML subset (see ar-scripts.yaml):
#
#   scripts:
#     <ar name>: <relative script path>
#
# Comments, blank lines and single/double-quoted scalars are allowed. Tabs,
# flow collections (other than an empty "{}" catalog) and anchors are not.

AR_MAPPING_FILE_NAME="ar-scripts.yaml"
AR_SCRIPTS_DIR="active_responses"

_ar_err() { echo "ar-mapping: $*" >&2; }

ar_valid_ar_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; }

# A script path must be relative, stay under active_responses/, and contain
# no empty, "." or ".." segment.
ar_valid_rel_path() {
  local p="$1" seg
  local -a segs
  [[ "$p" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
  [[ "$p" == "${AR_SCRIPTS_DIR}/"* ]] || return 1
  [[ "$p" != */ ]] || return 1
  IFS='/' read -ra segs <<<"$p"
  for seg in "${segs[@]}"; do
    [[ -n "$seg" && "$seg" != "." && "$seg" != ".." ]] || return 1
  done
}

# ar_mapping_parse <yaml>
# Prints one "<ar name>\t<script path>" line per catalog entry, in file order.
ar_mapping_parse() {
  local yaml="$1" raw kind name path out=""
  local -A seen=()

  [[ -f "$yaml" ]] || { _ar_err "mapping file not found: $yaml"; return 1; }

  raw=$(awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function unquote(s) {
      if (s ~ /^".*"$/ || s ~ /^\047.*\047$/) return substr(s, 2, length(s) - 2)
      return s
    }
    function fail(msg) { printf "ERR\tline %d: %s\n", NR, msg; bad = 1; exit 1 }
    BEGIN { in_root = 0; entry_ind = -1 }
    {
      line = $0
      sub(/\r$/, "", line)
      if (line ~ /^[ \t]*(#.*)?$/) next
      if (line ~ /\t/) fail("tabs are not allowed, indent with spaces")
      sub(/[ ]+#.*$/, "", line)
      match(line, /^ */); ind = RLENGTH
      content = trim(line)
      colon = index(content, ":")
      if (colon == 0) fail("expected \"key: value\"")
      key = unquote(trim(substr(content, 1, colon - 1)))
      val = unquote(trim(substr(content, colon + 1)))
      if (key == "") fail("empty key")

      if (ind == 0) {
        if (key != "scripts") fail("top-level key must be \"scripts:\"")
        if (val != "" && val != "{}") fail("\"scripts:\" must map active response names to scripts")
        if (in_root) fail("duplicate \"scripts:\" key")
        in_root = 1
        next
      }
      if (!in_root) fail("entries must be under \"scripts:\"")
      if (entry_ind < 0) entry_ind = ind
      else if (ind != entry_ind) fail("inconsistent indentation")
      if (val == "") fail("active response \"" key "\" has no script path")
      print "E\t" key "\t" val
    }
    END {
      if (bad) exit 1
      if (!in_root) { print "ERR\tmissing top-level \"scripts:\" key"; exit 1 }
    }
  ' "$yaml") || {
    _ar_err "$yaml: $(sed -n 's/^ERR\t//p' <<<"$raw")"
    return 1
  }

  while IFS=$'\t' read -r kind name path; do
    [[ "$kind" == "E" ]] || continue
    ar_valid_ar_name "$name" \
      || { _ar_err "$yaml: invalid active response name '$name'"; return 1; }
    ar_valid_rel_path "$path" \
      || { _ar_err "$yaml: invalid script path '$path' for '$name' (must be a relative path under ${AR_SCRIPTS_DIR}/)"; return 1; }
    [[ -z "${seen[$name]:-}" ]] \
      || { _ar_err "$yaml: '$name' is listed more than once"; return 1; }
    seen[$name]=1
    out+="${name}"$'\t'"${path}"$'\n'
  done <<<"$raw"
  # Nothing is printed unless the whole catalog is valid.
  printf '%s' "$out"
}

# ar_mapping_for_name <yaml> <ar name>
# Prints the script path the given active response name maps to.
ar_mapping_for_name() {
  local yaml="$1" want="$2" entries name path
  entries=$(ar_mapping_parse "$yaml") || return 1
  while IFS=$'\t' read -r name path; do
    if [[ "$name" == "$want" ]]; then
      printf '%s\n' "$path"
      return 0
    fi
  done <<<"$entries"
  _ar_err "$yaml: no script mapped for active response '$want'"
  return 1
}

# ar_path_trusted <path> <uid>
# True if <path> is owned by <uid> and is not writable by group or others.
ar_path_trusted() {
  local path="$1" uid="$2" st owner mode
  st=$(stat -c '%u %a' -- "$path" 2>/dev/null) || return 1
  owner="${st%% *}"
  mode="${st##* }"
  [[ "$owner" == "$uid" ]] && (( (8#$mode & 8#022) == 0 ))
}

# ar_resolve_script <home> <ar name> <trusted uid>
# Resolves <ar name> through <home>/ar-scripts.yaml to an executable script
# inside <home>, refusing anything that is missing, escapes <home> (e.g. via
# a symlink) or could be modified by someone other than <trusted uid>.
# Prints the absolute path of the script.
ar_resolve_script() {
  local home="$1" name="$2" uid="$3" home_real yaml rel target dir
  home_real=$(realpath -e -- "$home" 2>/dev/null) \
    || { _ar_err "directory not found: $home"; return 1; }
  ar_path_trusted "$home_real" "$uid" \
    || { _ar_err "$home_real must be owned by uid $uid and not group/world-writable"; return 1; }

  yaml="$home_real/$AR_MAPPING_FILE_NAME"
  [[ -f "$yaml" && ! -L "$yaml" ]] \
    || { _ar_err "mapping file missing or a symlink: $yaml"; return 1; }
  ar_path_trusted "$yaml" "$uid" \
    || { _ar_err "$yaml must be owned by uid $uid and not group/world-writable"; return 1; }

  rel=$(ar_mapping_for_name "$yaml" "$name") || return 1

  target=$(realpath -e -- "$home_real/$rel" 2>/dev/null) \
    || { _ar_err "script for '$name' not found: $home_real/$rel"; return 1; }
  [[ "$target" == "$home_real"/* ]] \
    || { _ar_err "script for '$name' resolves outside $home_real: $target"; return 1; }
  [[ -f "$target" ]] || { _ar_err "script for '$name' is not a regular file: $target"; return 1; }
  [[ -x "$target" ]] || { _ar_err "script for '$name' is not executable: $target"; return 1; }
  ar_path_trusted "$target" "$uid" \
    || { _ar_err "$target must be owned by uid $uid and not group/world-writable"; return 1; }

  dir="${target%/*}"
  while [[ "$dir" != "$home_real" ]]; do
    ar_path_trusted "$dir" "$uid" \
      || { _ar_err "$dir must be owned by uid $uid and not group/world-writable"; return 1; }
    dir="${dir%/*}"
  done

  printf '%s\n' "$target"
}
