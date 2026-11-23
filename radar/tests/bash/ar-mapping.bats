#!/usr/bin/env bats
# Unit tests for radar-agent/helpers/ar-mapping.sh (no root needed).

bats_require_minimum_version 1.5.0

setup() {
  REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  AGENT_DIR="${REPO_ROOT}/radar-agent"
  # shellcheck source=../../radar-agent/helpers/ar-mapping.sh
  source "${AGENT_DIR}/helpers/ar-mapping.sh"
  TMP="$(mktemp -d)"
  ME="$(id -u)"
}

teardown() {
  rm -rf "$TMP"
}

write_yaml() { cat > "$TMP/ar-scripts.yaml"; }

# A minimal, trusted home: catalog + one executable script per given path.
make_home() {
  HOME_DIR="$TMP/home"
  mkdir -p "$HOME_DIR/active_responses"
  chmod 0750 "$HOME_DIR" "$HOME_DIR/active_responses"
  cp "$TMP/ar-scripts.yaml" "$HOME_DIR/ar-scripts.yaml"
  chmod 0640 "$HOME_DIR/ar-scripts.yaml"
  local p
  for p in "$@"; do
    mkdir -p "$(dirname "$HOME_DIR/$p")"
    printf '#!/usr/bin/env bash\necho "%s"\n' "$p" > "$HOME_DIR/$p"
    chmod 0750 "$HOME_DIR/$p"
  done
}

# --- the shipped catalog ------------------------------------------------------

@test "shipped catalog parses and every listed script exists in radar-agent" {
  run ar_mapping_parse "$AGENT_DIR/ar-scripts.yaml"
  [ "$status" -eq 0 ]
  [ -n "$output" ]
  while IFS=$'\t' read -r name path; do
    [ -f "$AGENT_DIR/$path" ]
  done <<<"$output"
}

@test "shipped catalog lists the scripts the bootstrapper used to embed" {
  run ar_mapping_parse "$AGENT_DIR/ar-scripts.yaml"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = $'lock_user_linux.sh\tactive_responses/lock_user_linux_v1.sh' ]
  [ "${lines[1]}" = $'terminate_service.sh\tactive_responses/terminate_service_v1.sh' ]
}

# --- parsing ----------------------------------------------------------------

@test "parse: comments, blank lines, quotes and CRLF are handled" {
  printf '%s\r\n' \
    '# header' \
    'scripts:' \
    '' \
    '  # a comment' \
    "  'a.sh': \"active_responses/a_v1.sh\"   # trailing" \
    '  b.sh: active_responses/b_v1.sh' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = $'a.sh\tactive_responses/a_v1.sh' ]
  [ "${lines[1]}" = $'b.sh\tactive_responses/b_v1.sh' ]
}

@test "parse: any consistent indentation width is accepted, file order kept" {
  write_yaml <<'EOF'
scripts:
      z.sh: active_responses/z.sh
      a.sh: active_responses/a.sh
EOF
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = $'z.sh\tactive_responses/z.sh' ]
  [ "${lines[1]}" = $'a.sh\tactive_responses/a.sh' ]
}

@test "parse: an empty catalog is valid and yields nothing" {
  printf 'scripts:\n' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  printf 'scripts: {}\n' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "parse: missing file fails" {
  run ar_mapping_parse "$TMP/nope.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"mapping file not found"* ]]
}

@test "parse: missing top-level scripts key fails" {
  printf '# only a comment\n' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing top-level \"scripts:\" key"* ]]
}

@test "parse: the old per-scenario format is rejected with its line number" {
  write_yaml <<'EOF'
scenarios:
  suspicious_login:
    lock_user_linux.sh: active_responses/lock_user_linux_v1.sh
EOF
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"line 1: top-level key must be \"scripts:\""* ]]
}

@test "parse: a second top-level key is rejected" {
  write_yaml <<'EOF'
scripts:
  a.sh: active_responses/a.sh
other:
EOF
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"line 3: top-level key must be"* ]]
}

@test "parse: tabs are rejected" {
  printf 'scripts:\n\ta.sh: active_responses/a.sh\n' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"tabs are not allowed"* ]]
}

@test "parse: a scalar value for scripts is rejected" {
  printf 'scripts: lock_user_linux_v1.sh\n' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must map active response names to scripts"* ]]
}

@test "parse: an entry without a script path is rejected" {
  printf 'scripts:\n  a.sh:\n' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"has no script path"* ]]
}

@test "parse: inconsistent indentation (nesting) is rejected" {
  write_yaml <<'EOF'
scripts:
  a.sh: active_responses/a.sh
    b.sh: active_responses/b.sh
EOF
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"inconsistent indentation"* ]]
}

@test "parse: a list item is rejected" {
  printf 'scripts:\n  - active_responses/a.sh\n' | write_yaml
  run ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [[ "$output" == *"expected \"key: value\""* ]]
}

@test "parse: a duplicated name is rejected and nothing is printed" {
  write_yaml <<'EOF'
scripts:
  a.sh: active_responses/a_v1.sh
  a.sh: active_responses/a_v2.sh
EOF
  run --separate-stderr ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [ -z "$output" ]
  [[ "$stderr" == *"'a.sh' is listed more than once"* ]]
}

@test "parse: one invalid entry prints nothing, even after valid ones" {
  write_yaml <<'EOF'
scripts:
  a.sh: active_responses/a.sh
  b.sh: /etc/passwd
EOF
  run --separate-stderr ar_mapping_parse "$TMP/ar-scripts.yaml"
  [ "$status" -ne 0 ]
  [ -z "$output" ]
}

# --- validation of names and paths ------------------------------------------

@test "validate: script paths must be relative, under active_responses/, without '..'" {
  local bad
  for bad in /etc/passwd active_responses/../../etc/passwd other/a.sh \
             active_responses/ active_responses//a.sh active_responses/./a.sh \
             'active_responses/a b.sh' 'active_responses/$(id).sh'; do
    printf 'scripts:\n  a.sh: "%s"\n' "$bad" | write_yaml
    run ar_mapping_parse "$TMP/ar-scripts.yaml"
    [ "$status" -ne 0 ] || { echo "accepted: $bad"; return 1; }
    [[ "$output" == *"invalid script path"* ]]
  done
}

@test "validate: active response names are restricted" {
  local bad
  for bad in ../a.sh .hidden.sh 'a b.sh' 'a/b.sh' '$(id)'; do
    printf 'scripts:\n  "%s": active_responses/a.sh\n' "$bad" | write_yaml
    run ar_mapping_parse "$TMP/ar-scripts.yaml"
    [ "$status" -ne 0 ] || { echo "accepted: $bad"; return 1; }
    [[ "$output" == *"invalid active response name"* ]]
  done
}

# --- lookups ------------------------------------------------------------------

@test "for_name: finds the script, fails clearly for an unlisted name" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  run ar_mapping_for_name "$TMP/ar-scripts.yaml" lock.sh
  [ "$status" -eq 0 ]
  [ "$output" = "active_responses/lock_v1.sh" ]
  run ar_mapping_for_name "$TMP/ar-scripts.yaml" other.sh
  [ "$status" -ne 0 ]
  [[ "$output" == *"no script mapped for active response 'other.sh'"* ]]
}

@test "for_name: a broken catalog fails even for a listed name" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n  bad: /x\n' | write_yaml
  run ar_mapping_for_name "$TMP/ar-scripts.yaml" lock.sh
  [ "$status" -ne 0 ]
}

# --- resolution (what the dispatcher runs) ----------------------------------

@test "resolve: returns the absolute path of the listed script" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home active_responses/lock_v1.sh
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -eq 0 ]
  [ "$output" = "$(realpath "$HOME_DIR")/active_responses/lock_v1.sh" ]
}

@test "resolve: picks up a catalog change immediately (v1 -> v2)" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home active_responses/lock_v1.sh active_responses/lock_v2.sh
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [[ "$output" == */lock_v1.sh ]]
  sed -i 's/lock_v1/lock_v2/' "$HOME_DIR/ar-scripts.yaml"
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -eq 0 ]
  [[ "$output" == */lock_v2.sh ]]
}

@test "resolve: scripts in nested directories are allowed" {
  printf 'scripts:\n  lock.sh: active_responses/linux/lock_v1.sh\n' | write_yaml
  make_home active_responses/linux/lock_v1.sh
  chmod 0750 "$HOME_DIR/active_responses/linux"
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -eq 0 ]
  [[ "$output" == */active_responses/linux/lock_v1.sh ]]
}

@test "resolve: missing home directory fails" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  run ar_resolve_script "$TMP/missing" lock.sh "$ME"
  [ "$status" -ne 0 ]
  [[ "$output" == *"directory not found"* ]]
}

@test "resolve: missing listed script fails" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found"* ]]
}

@test "resolve: non-executable script fails" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home active_responses/lock_v1.sh
  chmod 0640 "$HOME_DIR/active_responses/lock_v1.sh"
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not executable"* ]]
}

@test "resolve: a directory instead of a script fails" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home
  mkdir -m 0750 "$HOME_DIR/active_responses/lock_v1.sh"
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a regular file"* ]]
}

@test "resolve: a symlink escaping the home directory is refused" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home
  printf '#!/bin/sh\necho evil\n' > "$TMP/evil.sh"
  chmod 0750 "$TMP/evil.sh"
  ln -s "$TMP/evil.sh" "$HOME_DIR/active_responses/lock_v1.sh"
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -ne 0 ]
  [[ "$output" == *"resolves outside"* ]]
}

@test "resolve: a group/world-writable catalog, script or directory is refused" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  local target
  for target in ar-scripts.yaml active_responses/lock_v1.sh active_responses .; do
    make_home active_responses/lock_v1.sh
    chmod g+w "$HOME_DIR/$target"
    run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
    [ "$status" -ne 0 ] || { echo "accepted g+w on $target"; return 1; }
    [[ "$output" == *"not group/world-writable"* ]]
    rm -rf "$HOME_DIR"
  done
  make_home active_responses/lock_v1.sh
  chmod o+w "$HOME_DIR/active_responses/lock_v1.sh"
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -ne 0 ]
}

@test "resolve: files owned by another user are refused" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home active_responses/lock_v1.sh
  run ar_resolve_script "$HOME_DIR" lock.sh "$((ME + 1))"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must be owned by uid $((ME + 1))"* ]]
}

@test "resolve: a catalog file that is a symlink is refused" {
  printf 'scripts:\n  lock.sh: active_responses/lock_v1.sh\n' | write_yaml
  make_home active_responses/lock_v1.sh
  mv "$HOME_DIR/ar-scripts.yaml" "$HOME_DIR/real.yaml"
  ln -s real.yaml "$HOME_DIR/ar-scripts.yaml"
  run ar_resolve_script "$HOME_DIR" lock.sh "$ME"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing or a symlink"* ]]
}

@test "shellcheck (informational)" {
  shellcheck "${AGENT_DIR}/helpers/ar-mapping.sh" || true
}
