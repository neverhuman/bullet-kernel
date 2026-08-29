#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT
export GIT_TERMINAL_PROMPT=0
export LC_ALL=C
export TZ=UTC

# shellcheck source=ops/ci/inventory.sh
source "$(dirname "${BASH_SOURCE[0]}")/inventory.sh"

CI_CARGO_TARGET_ADMITTED=false
if [[ ${BULLET_CI_CARGO_TARGET_DIR+x} || ${BULLET_CI_CARGO_TARGET_ID+x} ]]; then
  CI_CARGO_TARGET_ADMITTED=true
fi

log() { printf '[ci] %s\n' "$*"; }

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[ci] missing required tool: %s\n' "$1" >&2
    return 1
  fi
}

refuse() {
  printf '[ci] %s: %s\n' "$1" "$2" >&2
  return 1
}

verify_ci_cargo_target() {
  local canonical current suffix uid
  $CI_CARGO_TARGET_ADMITTED || return 0
  uid="$(id -u)" || return 1
  suffix="${BULLET_CI_CARGO_TARGET_DIR:-}"
  suffix="${suffix#"$REPO_ROOT/.git/bullet-ci-target."}"
  [[ ${BULLET_CI_CARGO_TARGET_DIR+x} && ${BULLET_CI_CARGO_TARGET_ID+x} \
    && "${CARGO_TARGET_DIR:-}" == "$BULLET_CI_CARGO_TARGET_DIR" \
    && "$BULLET_CI_CARGO_TARGET_DIR" == "$REPO_ROOT/.git"/bullet-ci-target.* \
    && "$suffix" =~ ^[A-Za-z0-9]{10}$ \
    && "$BULLET_CI_CARGO_TARGET_DIR" != / \
    && "$BULLET_CI_CARGO_TARGET_DIR" != "$REPO_ROOT" \
    && "$BULLET_CI_CARGO_TARGET_DIR" != "$REPO_ROOT/target" \
    && ( -z "${HOME:-}" || "$BULLET_CI_CARGO_TARGET_DIR" != "$HOME" ) \
    && -d "$BULLET_CI_CARGO_TARGET_DIR" && ! -L "$BULLET_CI_CARGO_TARGET_DIR" \
    && "$(find "$BULLET_CI_CARGO_TARGET_DIR" -maxdepth 0 -type d -uid "$uid" -perm 0700 -print 2>/dev/null)" \
      == "$BULLET_CI_CARGO_TARGET_DIR" \
    && "$BULLET_CI_CARGO_TARGET_ID" =~ ^[0-9]+:[0-9]+:[0-9]+:700:directory$ ]] || {
    refuse CI_PROOF_TARGET_UNTRUSTED 'private Cargo target custody is ambiguous'
    return 1
  }
  canonical="$(cd "$BULLET_CI_CARGO_TARGET_DIR" && pwd -P)" || return 1
  current="$(stat -Lc '%d:%i:%u:%a:%F' -- "$BULLET_CI_CARGO_TARGET_DIR" 2>/dev/null)" \
    || return 1
  [[ "$canonical" == "$BULLET_CI_CARGO_TARGET_DIR" \
    && "$current" == "$BULLET_CI_CARGO_TARGET_ID" \
    && "${current#*:*:}" == "$uid:700:directory" ]] || {
    refuse CI_PROOF_TARGET_UNTRUSTED 'private Cargo target identity changed'
    return 1
  }
}

verify_ci_cargo_target

require_exact_output() {
  local expected="$1"
  shift
  local actual
  actual="$("$@")" || return 1
  actual="${actual%%$'\n'*}"
  if [[ "$actual" != "$expected" ]]; then
    refuse TOOL_VERSION_MISMATCH "expected '$expected', found '$actual'"
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    refuse SHA256_TOOL_MISSING "install sha256sum or shasum"
    return 1
  fi
}

scan_current_source_secrets() {
  local source_root="${1:-$REPO_ROOT}"
  local manifest path invalid_code="" invalid_detail=""
  local had_errexit=0
  local -a statuses
  require_tool git || return 1
  require_tool gitleaks || return 1
  [[ "$source_root" == /* && -d "$source_root/.git" ]] \
    || { refuse SECRET_SCAN_ROOT_INVALID "$source_root is not an absolute Git checkout"; return 1; }

  manifest="$(mktemp)" || return 1
  if ! git -C "$source_root" ls-files --cached --others --exclude-standard -z >"$manifest"; then
    rm -f -- "$manifest"
    refuse SECRET_SCAN_MANIFEST_FAILED "Git could not enumerate current source"
    return 1
  fi
  if [[ ! -s "$manifest" ]]; then
    rm -f -- "$manifest"
    refuse SECRET_SCAN_MANIFEST_EMPTY "Git enumerated zero current-source files"
    return 1
  fi
  while IFS= read -r -d '' path; do
    case "$path" in
      ''|/*|..|../*|*/../*)
        invalid_code=SECRET_SCAN_PATH_INVALID
        invalid_detail="$path"
        break
        ;;
    esac
    if [[ ! -f "$source_root/$path" || -L "$source_root/$path" ]]; then
      invalid_code=SECRET_SCAN_ENTRY_INVALID
      invalid_detail="$path must be a non-symlink regular file"
      break
    fi
  done <"$manifest"
  if [[ -n "$invalid_code" ]]; then
    rm -f -- "$manifest"
    refuse "$invalid_code" "$invalid_detail"
    return 1
  fi

  [[ $- == *e* ]] && had_errexit=1
  set +e
  (
    cd "$source_root" || exit 125
    xargs -0 cat -- <"$manifest"
  ) | gitleaks detect --pipe --redact --no-banner
  statuses=("${PIPESTATUS[@]}")
  (( had_errexit == 1 )) && set -e
  rm -f -- "$manifest"
  if [[ "${statuses[0]}" -ne 0 ]]; then
    refuse SECRET_SCAN_READ_FAILED "could not read the admitted current-source manifest"
    return 1
  fi
  return "${statuses[1]}"
}

deny_sibling_gitd() {
  unset BULLET_GITD_BIN BULLET_GITD_SHA256
}

partition_count() {
  local filter="$1"
  require_tool cargo-nextest || return 1
  require_tool jq || return 1
  verify_ci_cargo_target || return 1
  cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all --message-format json -E "$filter" \
    | jq -er '[
        ."rust-suites" | to_entries[] | .value.testcases | to_entries[] |
        select(.value["filter-match"].status == "matches")
      ] | length'
}

readonly JUNIT_RAW_MAX_BYTES=$((16 * 1024 * 1024))

sha256_bounded_junit_raw() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    head -c "$((JUNIT_RAW_MAX_BYTES + 1))" "$path" | sha256sum | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    head -c "$((JUNIT_RAW_MAX_BYTES + 1))" "$path" | shasum -a 256 | awk '{ print $1 }'
  else
    refuse SHA256_TOOL_MISSING "install sha256sum or shasum"
    return 1
  fi
}

junit_owned_directory() {
  local path="$1"
  local uid="$2"
  [[ -d "$path" && ! -L "$path" \
    && "$(find "$path" -maxdepth 0 -type d -uid "$uid" -print 2>/dev/null)" == "$path" ]]
}

junit_prepare_directory() {
  local path="$1"
  local uid="$2"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    (umask 077; mkdir -- "$path") || return 1
  fi
  junit_owned_directory "$path" "$uid" || {
    refuse JUNIT_STORE_CUSTODY_INVALID "$path is not an owned non-symlink directory"
    return 1
  }
}

prepare_junit_store() {
  local profile="$1"
  local lane="$2"
  local uid tool
  for tool in find id mkdir stat; do
    require_tool "$tool" || return 1
  done
  [[ "$profile" =~ ^[a-z0-9][a-z0-9-]{0,31}$ \
    && "$lane" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || {
    refuse JUNIT_STORE_CUSTODY_INVALID "profile or lane is not a closed path segment"
    return 1
  }
  uid="$(id -u)" || return 1
  junit_owned_directory "$REPO_ROOT" "$uid" || {
    refuse JUNIT_STORE_CUSTODY_INVALID "$REPO_ROOT is not an owned non-symlink directory"
    return 1
  }
  junit_prepare_directory "$REPO_ROOT/target" "$uid" || return 1
  junit_prepare_directory "$REPO_ROOT/target/nextest" "$uid" || return 1
  junit_prepare_directory "$REPO_ROOT/target/nextest/$profile" "$uid" || return 1
  junit_prepare_directory "$REPO_ROOT/.ci-artifacts" "$uid" || return 1
  junit_prepare_directory "$REPO_ROOT/.ci-artifacts/junit" "$uid" || return 1
}

junit_store_identity() {
  local profile="$1"
  stat -Lc '%d:%i:%u:%a:%F' -- \
    "$REPO_ROOT" \
    "$REPO_ROOT/target" \
    "$REPO_ROOT/target/nextest" \
    "$REPO_ROOT/target/nextest/$profile" \
    "$REPO_ROOT/.ci-artifacts" \
    "$REPO_ROOT/.ci-artifacts/junit"
}

junit_file_identity() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || return 1
  stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "$path"
}

junit_destination_absent() {
  local path="$1"
  [[ ! -e "$path" && ! -L "$path" ]] || {
    refuse JUNIT_STORE_CUSTODY_INVALID "$path must be absent before publication"
    return 1
  }
}

validate_junit_raw_schema() {
  LC_ALL=C awk '
function refuse_raw(detail) {
  print "[ci] JUNIT_RAW_SCHEMA_INVALID: " detail > "/dev/stderr"
  refused = 1
  exit 1
}
function trim(value) {
  sub(/^[ \t\r\n]+/, "", value)
  sub(/[ \t\r\n]+$/, "", value)
  return value
}
function digit_value(character) {
  if (character >= "0" && character <= "9") return character + 0
  character = tolower(character)
  if (character >= "a" && character <= "f") return index("abcdef", character) + 9
  return -1
}
function valid_numeric_reference(entity, base, digits, value, index_value, digit) {
  if (entity ~ /^#[0-9]+$/) {
    base = 10
    digits = substr(entity, 2)
  } else if (entity ~ /^#x[0-9A-Fa-f]+$/) {
    base = 16
    digits = substr(entity, 3)
  } else {
    return 0
  }
  value = 0
  for (index_value = 1; index_value <= length(digits); index_value++) {
    digit = digit_value(substr(digits, index_value, 1))
    if (digit < 0 || digit >= base) return 0
    value = value * base + digit
    if (value > 1114111) return 0
  }
  return value == 9 || value == 10 || value == 13 ||
    (value >= 32 && value <= 55295) ||
    (value >= 57344 && value <= 65533) ||
    (value >= 65536 && value <= 1114111)
}
function valid_named_reference(entity) {
  return entity == "amp" || entity == "lt" || entity == "gt" ||
    entity == "quot" || entity == "apos"
}
function outcome_attribute(key, normalized) {
  normalized = tolower(key)
  sub(/^.*:/, "", normalized)
  return normalized == "status" || normalized == "result" ||
    normalized == "failure" || normalized == "error" || normalized == "skipped"
}
function preserved_attribute(tag, key) {
  if (tag == "testsuites" || tag == "testsuite")
    return key == "name" || key == "tests" || key == "errors" ||
      key == "failures" || key == "disabled" || key == "time"
  if (tag == "testcase") return key == "name" || key == "classname" || key == "time"
  return 0
}
function inspect_entities(value, offset, amp, semi, entity) {
  offset = 1
  while ((amp = index(substr(value, offset), "&")) != 0) {
    amp += offset - 1
    semi = index(substr(value, amp), ";")
    if (semi == 0) refuse_raw("unterminated entity reference")
    entity = substr(value, amp + 1, semi - 2)
    if (substr(entity, 1, 1) == "#") {
      if (!valid_numeric_reference(entity))
        refuse_raw("invalid numeric character reference " entity)
    } else if (!valid_named_reference(entity)) {
      refuse_raw("unknown named entity reference " entity)
    }
    offset = amp + semi
  }
}
function inspect_attributes(raw, tag, equals, key, rest, quote_end, value) {
  raw = trim(raw)
  while (length(raw) != 0) {
    equals = index(raw, "=")
    if (equals <= 1) return
    key = trim(substr(raw, 1, equals - 1))
    rest = substr(raw, equals + 1)
    sub(/^[ \t\r\n]+/, "", rest)
    if (substr(rest, 1, 1) != "\"") return
    quote_end = index(substr(rest, 2), "\"")
    if (quote_end == 0) return
    value = substr(rest, 2, quote_end - 1)
    if (outcome_attribute(key))
      refuse_raw("outcome-like attribute " key)
    if (preserved_attribute(tag, key)) inspect_entities(value)
    rest = substr(rest, quote_end + 2)
    raw = trim(rest)
  }
}
{
  document = document $0 "\n"
}
END {
  if (refused) exit 1
  inspect_entities(document)
  position = 1
  while (position <= length(document)) {
    relative = index(substr(document, position), "<")
    if (relative == 0) break
    opening = position + relative - 1
    quoted = 0
    closing = 0
    for (cursor = opening + 1; cursor <= length(document); cursor++) {
      character = substr(document, cursor, 1)
      if (character == "\"") quoted = !quoted
      else if (character == ">" && !quoted) {
        closing = cursor
        break
      }
    }
    if (closing == 0) break
    content = trim(substr(document, opening + 1, closing - opening - 1))
    position = closing + 1
    if (content == "" || substr(content, 1, 1) ~ /[\/?!]/) continue
    if (substr(content, length(content), 1) == "/")
      content = trim(substr(content, 1, length(content) - 1))
    split_at = match(content, /[ \t\r\n]/)
    if (split_at == 0) continue
    tag = substr(content, 1, split_at - 1)
    inspect_attributes(substr(content, split_at), tag)
  }
}
' "$1"
}

sanitize_junit() (
  local profile="$1"
  local lane="$2"
  local source_path destination source_fd source_fd_path source_identity source_after
  local source_digest source_digest_after snapshot snapshot_identity snapshot_digest
  local store_identity store_after uid owner mode links size kind
  require_tool awk || return 1
  require_tool head || return 1
  require_tool mktemp || return 1
  verify_ci_cargo_target || return 1
  prepare_junit_store "$profile" "$lane" || return 1
  store_identity="$(junit_store_identity "$profile")" || return 1
  source_path="$REPO_ROOT/target/nextest/$profile/junit.xml"
  destination="$REPO_ROOT/.ci-artifacts/junit/$lane.xml"
  junit_destination_absent "$destination" || return 1
  source_identity="$(junit_file_identity "$source_path")" || {
    refuse JUNIT_RAW_SUBJECT_INVALID "$source_path is not a non-symlink regular file"
    return 1
  }
  IFS=: read -r _ _ owner mode links size kind <<<"$source_identity"
  uid="$(id -u)" || return 1
  [[ "$owner" == "$uid" && "$mode" == 600 && "$links" == 1 \
    && "$size" =~ ^[1-9][0-9]*$ && "$kind" == "regular file" ]] || {
    refuse JUNIT_RAW_SUBJECT_INVALID "$source_path has ambiguous identity"
    return 1
  }
  [[ "$size" -le "$JUNIT_RAW_MAX_BYTES" ]] || {
    refuse JUNIT_RAW_TOO_LARGE "$source_path exceeds $JUNIT_RAW_MAX_BYTES bytes"
    return 1
  }
  exec {source_fd}<"$source_path" || {
    refuse JUNIT_RAW_SUBJECT_INVALID "$source_path could not be opened"
    return 1
  }
  source_fd_path="/proc/self/fd/$source_fd"
  [[ "$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "$source_fd_path")" == "$source_identity" ]] || {
    refuse JUNIT_RAW_SUBJECT_INVALID "$source_path changed while opening"
    return 1
  }
  snapshot="$(mktemp "$REPO_ROOT/.ci-artifacts/junit/.raw-$lane.XXXXXXXXXX.xml")" || return 1
  trap 'rm -f -- "$snapshot"' EXIT
  source_digest="$(sha256_bounded_junit_raw "$source_fd_path")" || return 1
  head -c "$((JUNIT_RAW_MAX_BYTES + 1))" "$source_fd_path" >"$snapshot" || return 1
  source_after="$(stat -Lc '%d:%i:%u:%a:%h:%s:%F' -- "$source_fd_path")" || return 1
  source_digest_after="$(sha256_bounded_junit_raw "$source_fd_path")" || return 1
  snapshot_identity="$(junit_file_identity "$snapshot")" || return 1
  snapshot_digest="$(sha256_file "$snapshot")" || return 1
  IFS=: read -r _ _ owner mode links size kind <<<"$snapshot_identity"
  [[ "$source_after" == "$source_identity" && "$source_digest_after" == "$source_digest" \
    && "$snapshot_digest" == "$source_digest" && "$owner" == "$uid" && "$mode" == 600 \
    && "$links" == 1 && "$size" -le "$JUNIT_RAW_MAX_BYTES" && "$kind" == "regular file" ]] || {
    refuse JUNIT_RAW_SUBJECT_INVALID "$source_path changed or snapshot identity is ambiguous"
    return 1
  }
  validate_junit_raw_schema "$snapshot" || return 1
  junit_destination_absent "$destination" || return 1
  bash "$REPO_ROOT/ops/ci/sanitize-junit.sh" "$snapshot" "$destination" || return 1
  prepare_junit_store "$profile" "$lane" || return 1
  store_after="$(junit_store_identity "$profile")" || return 1
  [[ "$store_after" == "$store_identity" ]] || {
    refuse JUNIT_STORE_CUSTODY_INVALID "JUnit store identity changed during sanitation"
    return 1
  }
  [[ "$(junit_file_identity "$destination")" =~ ^[^:]+:[^:]+:$uid:600:1:[1-9][0-9]*:regular\ file$ ]] || {
    refuse JUNIT_STORE_CUSTODY_INVALID "$destination is not an exact published file"
    return 1
  }
)

run_partition_tests() {
  local lane="$1"
  local profile="$2"
  local expected="$3"
  local filter="$4"
  local selected
  require_tool cargo-nextest || return 1
  verify_ci_cargo_target || return 1
  selected="$(partition_count "$filter")" || return 1
  if [[ "$selected" -ne "$expected" || "$selected" -eq 0 ]]; then
    refuse TEST_PARTITION_DRIFT "$lane selected $selected tests; expected $expected"
    return 1
  fi
  prepare_junit_store "$profile" "$lane" || return 1
  rm -f -- "$REPO_ROOT/target/nextest/$profile/junit.xml" \
    "$REPO_ROOT/.ci-artifacts/junit/$lane.xml"
  log "$lane tests via nextest profile=$profile selected=$selected"
  set +e
  cargo nextest run --locked --workspace "${NEXTEST_FEATURES[@]}" --profile "$profile" -E "$filter"
  local code=$?
  set -e
  sanitize_junit "$profile" "$lane" || return 1
  return "$code"
}
