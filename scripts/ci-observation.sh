#!/usr/bin/env bash
# Emit an unsigned diagnostic observation. This is not Bullet Evidence and is
# never a release receipt.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

lane="${1:-}"
exit_code="${2:-}"
command_text="${3:-}"
shift "$(( $# >= 3 ? 3 : $# ))"

refuse() { printf '[ci-observation] %s: %s\n' "$1" "$2" >&2; exit 1; }
[[ "$lane" =~ ^[a-z][a-z0-9-]*$ ]] \
  || refuse LANE_INVALID "lane must match ^[a-z][a-z0-9-]*$"
[[ "$exit_code" =~ ^[0-9]+$ ]] || refuse EXIT_CODE_INVALID "$exit_code"
(( exit_code <= 255 )) || refuse EXIT_CODE_INVALID "$exit_code exceeds 255"
[[ -n "$command_text" ]] || refuse COMMAND_REQUIRED "command must be non-empty"
for tool in git jq; do
  command -v "$tool" >/dev/null 2>&1 || refuse TOOL_MISSING "$tool"
done

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    refuse TOOL_MISSING "sha256sum or shasum"
  fi
}

commit_oid="$(git rev-parse HEAD)"
tree_oid="$(git rev-parse 'HEAD^{tree}')"
[[ "$commit_oid" =~ ^[0-9a-f]{40}$ ]] || refuse COMMIT_OID_INVALID "$commit_oid"
[[ "$tree_oid" =~ ^[0-9a-f]{40}$ ]] || refuse TREE_OID_INVALID "$tree_oid"

clean=true
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  clean=false
fi
status=PASS
[[ "$exit_code" -eq 0 ]] || status=FAIL

tool_versions='{}'
record_tool() {
  local key="$1"
  shift
  local value
  if command -v "$1" >/dev/null 2>&1; then
    value="$("$@" 2>/dev/null | head -n 1)"
    [[ -n "$value" ]] && tool_versions="$(jq -c --arg key "$key" --arg value "$value" '. + {($key): $value}' <<<"$tool_versions")"
  fi
}
record_tool git git --version
record_tool rustc rustc --version
record_tool cargo cargo --version
record_tool cargo-nextest cargo nextest --version
record_tool actionlint actionlint -version
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck_version="$(shellcheck --version | awk '$1 == "version:" { print $2 }')"
  tool_versions="$(jq -c --arg value "$shellcheck_version" '. + {shellcheck: $value}' <<<"$tool_versions")"
fi
record_tool gitleaks gitleaks version
record_tool cargo-deny cargo deny --version
record_tool zizmor zizmor --version
record_tool lychee lychee --version
record_tool cargo-llvm-cov cargo llvm-cov --version

artifact_hashes='[]'
for artifact in "$@"; do
  case "$artifact" in
    ''|/*|..|../*|*/..|*/../*) refuse ARTIFACT_PATH_INVALID "$artifact" ;;
  esac
  [[ -f "$artifact" ]] || refuse ARTIFACT_MISSING "$artifact"
  digest="$(hash_file "$artifact")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || refuse ARTIFACT_HASH_INVALID "$artifact"
  artifact_hashes="$(jq -c --arg path "$artifact" --arg sha256 "$digest" '. + [{path: $path, sha256: $sha256}]' <<<"$artifact_hashes")"
done

output=".ci-artifacts/observations/$lane.json"
mkdir -p "$(dirname "$output")"
jq -n \
  --arg repository "bullet-kernel" \
  --arg commit_oid "$commit_oid" \
  --arg tree_oid "$tree_oid" \
  --arg command "$command_text" \
  --arg lane "$lane" \
  --arg status "$status" \
  --argjson clean "$clean" \
  --argjson exit_code "$exit_code" \
  --argjson tool_versions "$tool_versions" \
  --argjson artifact_hashes "$artifact_hashes" \
  '{
    schema_version: "bullet.ci-observation.v1",
    repository: $repository,
    commit_oid: $commit_oid,
    tree_oid: $tree_oid,
    clean: $clean,
    commands: [$command],
    tool_versions: $tool_versions,
    outcomes: [{lane: $lane, status: $status, exit_code: $exit_code}],
    artifact_hashes: $artifact_hashes,
    signed: false,
    evidence_class: "DIAGNOSTIC_ONLY"
  }' >"$output"
jq -e . "$output" >/dev/null
printf '%s\n' "$output"
