#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT
export GIT_TERMINAL_PROMPT=0
export LC_ALL=C
export TZ=UTC

# shellcheck source=ops/ci/inventory.sh
source "$(dirname "${BASH_SOURCE[0]}")/inventory.sh"

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
  cargo nextest list --locked --workspace --run-ignored all --message-format json -E "$filter" \
    | jq -er '[
        ."rust-suites" | to_entries[] | .value.testcases | to_entries[] |
        select(.value["filter-match"].status == "matches")
      ] | length'
}

sanitize_junit() {
  local profile="$1"
  local lane="$2"
  local source_path="$REPO_ROOT/target/nextest/$profile/junit.xml"
  local destination="$REPO_ROOT/.ci-artifacts/junit/$lane.xml"
  [[ -f "$source_path" ]] \
    || { refuse JUNIT_MISSING "$source_path was not produced"; return 1; }
  mkdir -p "$(dirname "$destination")"
  bash "$REPO_ROOT/ops/ci/sanitize-junit.sh" "$source_path" "$destination"
}

run_partition_tests() {
  local lane="$1"
  local profile="$2"
  local expected="$3"
  local filter="$4"
  local selected
  require_tool cargo-nextest || return 1
  selected="$(partition_count "$filter")" || return 1
  if [[ "$selected" -ne "$expected" || "$selected" -eq 0 ]]; then
    refuse TEST_PARTITION_DRIFT "$lane selected $selected tests; expected $expected"
    return 1
  fi
  rm -f "$REPO_ROOT/target/nextest/$profile/junit.xml" \
    "$REPO_ROOT/.ci-artifacts/junit/$lane.xml"
  log "$lane tests via nextest profile=$profile selected=$selected"
  set +e
  cargo nextest run --locked --workspace --profile "$profile" -E "$filter"
  local code=$?
  set -e
  sanitize_junit "$profile" "$lane" || return 1
  return "$code"
}
