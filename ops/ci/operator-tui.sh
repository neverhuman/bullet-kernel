#!/usr/bin/env bash
# Local component qualification only. No provider or installed-service credit.
set -euo pipefail
umask 077
unavailable() { printf 'OPERATOR_TUI_%s: %s\n' "$1" "$2" >&2; exit 78; }
[[ ! ${CI+x} && ! ${GITHUB_ACTIONS+x} ]] \
  || unavailable HOSTED_RUN_REFUSED 'CI and GITHUB_ACTIONS must be absent'
[[ "$(uname -s)" == Linux && "$(</proc/sys/kernel/hostname)" == xbabe2 ]] \
  || unavailable HOST_NOT_ADMITTED 'requires Linux on xbabe2'
[[ $# -eq 0 ]] || unavailable ARGUMENTS_UNSUPPORTED 'select exact inputs through the documented environment'
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
[[ "$CI_CARGO_TARGET_ADMITTED" == true ]] \
  || unavailable WRAPPER_REQUIRED 'run bash scripts/ci-local.sh operator-tui'
verify_ci_cargo_target
for tool in cmp cp cut env find jq od realpath sha256sum sort stat tr wc xargs; do require_tool "$tool" || exit 1; done

# Inputs are exact tool/binary subjects. The external proof review must admit
# their source, dependency/configuration closure and the compilation window.
admit_binary() {
  local label="$1" path="$2" digest="$3" owner mode
  [[ "$path" == /* && -f "$path" && ! -L "$path" && -x "$path" \
    && "$(realpath -e -- "$path")" == "$path" && "$digest" =~ ^[0-9a-f]{64}$ ]] \
    || { refuse OPERATOR_TUI_BINARY_INPUT_INVALID "$label"; return 1; }
  owner="$(stat -Lc '%u' -- "$path")"; mode="$(stat -Lc '%a' -- "$path")"
  [[ ( "$owner" == 0 || "$owner" == "$(id -u)" ) && $((8#$mode & 8#022)) -eq 0 ]] \
    || { refuse OPERATOR_TUI_BINARY_CUSTODY_INVALID "$label"; return 1; }
  [[ "$(od -An -tx1 -N4 -- "$path" | tr -d ' \n')" == 7f454c46 ]] \
    || { refuse OPERATOR_TUI_NATIVE_BINARY_REQUIRED "$label"; return 1; }
  [[ "$(sha256_file "$path")" == "$digest" ]] \
    || { refuse OPERATOR_TUI_BINARY_DIGEST_MISMATCH "$label"; return 1; }
}
cargo_bin="${BULLET_TUIWRIGHT_CARGO_BIN:-}"
cargo_sha="${BULLET_TUIWRIGHT_CARGO_SHA256:-}"
rustc_bin="${BULLET_TUIWRIGHT_RUSTC_BIN:-}"
rustc_sha="${BULLET_TUIWRIGHT_RUSTC_SHA256:-}"
bullet_bin="${BULLET_TUIWRIGHT_BULLET_BIN:-}"
bullet_sha="${BULLET_TUIWRIGHT_BULLET_SHA256:-}"
admit_binary cargo "$cargo_bin" "$cargo_sha"
admit_binary rustc "$rustc_bin" "$rustc_sha"
admit_binary bullet "$bullet_bin" "$bullet_sha"
output="${BULLET_TUIWRIGHT_OUTPUT:-}"
[[ "$output" == /* && ! -e "$output" && ! -L "$output" \
  && "$(realpath -m -- "$output")" == "$output" ]] \
  || { refuse OPERATOR_TUI_OUTPUT_NOT_FRESH 'require a new canonical absolute directory'; exit 1; }
parent="$(dirname -- "$output")"
[[ -d "$parent" && ! -L "$parent" \
  && "$(stat -Lc '%u:%a:%F' -- "$parent")" == "$(id -u):700:directory" ]] \
  || { refuse OPERATOR_TUI_OUTPUT_PARENT_UNTRUSTED "$parent"; exit 1; }
[[ "$output" != "$REPO_ROOT"/* && "$output" != "$CARGO_TARGET_DIR"/* ]] \
  || { refuse OPERATOR_TUI_OUTPUT_INSIDE_SOURCE 'retain observations outside the checkout and build target'; exit 1; }

suite=ops/qualification/tuiwright
source_digest="${BULLET_TUIWRIGHT_SOURCE_SHA256:-}"
[[ "$source_digest" =~ ^[0-9a-f]{64}$ ]] \
  || { refuse OPERATOR_TUI_SOURCE_DIGEST_REQUIRED 'SHA256 of sorted relative-path sha256sum inventory'; exit 1; }
source_inventory() {
  local links
  links="$(find "$suite" -type l -print)" || return 1
  [[ -z "$links" ]] || return 1
  find "$suite" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
}
# Only the existing standalone workspace is compiled; no arbitrary harness path
# or old receipt can substitute for a build and complete component invocation.
[[ -f "$suite/Cargo.toml" && -f "$suite/Cargo.lock" && -f "$suite/src/main.rs" ]] \
  || { refuse OPERATOR_TUI_SUITE_MISSING "$suite"; exit 1; }
source_before="$(source_inventory)" || { refuse OPERATOR_TUI_SOURCE_UNTRUSTED "$suite"; exit 1; }
[[ "$(printf '%s\n' "$source_before" | sha256sum | cut -d ' ' -f1)" == "$source_digest" ]] \
  || { refuse OPERATOR_TUI_SOURCE_DIGEST_MISMATCH "$suite"; exit 1; }
mkdir -m 0700 -- "$output"
printf '%s\n' "$source_before" >"$output/source.sha256"
finish() {
  local exit_status=$?
  trap - EXIT
  printf '%s\n' "$exit_status" >"$output/exit-status"
  printf 'OPERATOR_TUI_OBSERVATION: %s (exit %s; component only)\n' "$output" "$exit_status" >&2
}
trap finish EXIT
jq -n --arg cargo "$cargo_bin" --arg cargo_sha "$cargo_sha" --arg rustc "$rustc_bin" \
  --arg rustc_sha "$rustc_sha" --arg bullet "$bullet_bin" --arg bullet_sha "$bullet_sha" \
  --arg source "$source_digest" '{cargo:{path:$cargo,sha256:$cargo_sha},rustc:{path:$rustc,sha256:$rustc_sha},
    bullet:{path:$bullet,sha256:$bullet_sha},suite_sha256:$source,
    evidence_class:"COMPONENT_PROOF",source_build_binding:"EXTERNAL_REVIEW_REQUIRED",
    installed_authenticated:false,release_eligible:false}' >"$output/inputs.json"

# Remove ambient compiler wrappers and flags. Frozen prevents dependency fetches
# or lockfile repair. Selected Cargo still consumes the reviewed source/config.
env -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
  RUSTC="$rustc_bin" "$cargo_bin" build --frozen --release \
  --manifest-path "$suite/Cargo.toml" --bin bullet-tuiwright-qualification \
  --message-format=json >"$output/build.jsonl" 2>"$output/build.stderr"
compiled="$CARGO_TARGET_DIR/release/bullet-tuiwright-qualification"
[[ -f "$compiled" && ! -L "$compiled" && -x "$compiled" ]] \
  || { refuse OPERATOR_TUI_BUILD_ARTIFACT_MISSING "$compiled"; exit 1; }
jq -se --arg executable "$compiled" '
  [ .[] | select(.reason == "compiler-artifact" and .target.name == "bullet-tuiwright-qualification"
    and .executable == $executable) ] | length == 1' "$output/build.jsonl" >/dev/null \
  || { refuse OPERATOR_TUI_BUILD_IDENTITY_MISSING "$output/build.jsonl"; exit 1; }
[[ "$(source_inventory)" == "$source_before" ]] \
  || { refuse OPERATOR_TUI_SOURCE_CHANGED 'during build'; exit 1; }
cp -- "$compiled" "$output/harness"
chmod 0500 -- "$output/harness"
harness_sha="$(sha256_file "$output/harness")"
# Listing is expected-selection data only. Success requires the component run.
"$output/harness" --list >"$output/selected.json" 2>"$output/list.stderr"
jq -e 'type == "array" and length > 0 and all(.[]; type == "string" and length > 0)
  and ((unique | length) == length)' "$output/selected.json" >/dev/null
status=0
"$output/harness" component --bullet "$bullet_bin" --sha256 "$bullet_sha" \
  --output "$output/run" >"$output/run.stdout" 2>"$output/run.stderr" || status=$?
[[ -f "$output/run/manifest.json" && ! -L "$output/run/manifest.json" ]] \
  || { refuse OPERATOR_TUI_MANIFEST_MISSING "$output/run"; exit 1; }
admit_binary cargo "$cargo_bin" "$cargo_sha"
admit_binary rustc "$rustc_bin" "$rustc_sha"
admit_binary bullet "$bullet_bin" "$bullet_sha"
[[ "$(sha256_file "$output/harness")" == "$harness_sha" && "$(source_inventory)" == "$source_before" ]] \
  || { refuse OPERATOR_TUI_INPUT_CHANGED 'during component execution'; exit 1; }
jq -e --slurpfile selected "$output/selected.json" --arg bullet "$bullet_bin" --arg sha "$bullet_sha" \
  --arg harness "$output/harness" --arg harness_sha "$harness_sha" '
  .schema == 1 and .evidence_class == "COMPONENT_PROOF" and .outcome == "PASS" and
  .installed_authenticated == false and .release_eligible == false and .failures == [] and
  .selected == $selected[0] and [.completed[].id] == $selected[0] and
  all(.completed[]; .outcome == "PASS" and .error == null) and
  .subjects.bullet == {path:$bullet,sha256:$sha} and
  .subjects.harness == {path:$harness,sha256:$harness_sha} and
  (.artifacts | length > 0) and ([.artifacts[].path] | unique | length) == (.artifacts | length)
' "$output/run/manifest.json" >/dev/null \
  || { refuse OPERATOR_TUI_EXECUTION_INCOMPLETE "$output/run/manifest.json"; exit 1; }
while IFS=$'\t' read -r artifact expected; do
  [[ "$artifact" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ && "$expected" =~ ^[0-9a-f]{64}$ \
    && -f "$output/run/$artifact" && ! -L "$output/run/$artifact" \
    && "$(sha256_file "$output/run/$artifact")" == "$expected" ]] \
    || { refuse OPERATOR_TUI_ARTIFACT_CHANGED "$artifact"; exit 1; }
done < <(jq -r '.artifacts[] | [.path,.sha256] | @tsv' "$output/run/manifest.json")
[[ "$(find "$output/run" -mindepth 1 | wc -l)" -eq "$(jq '.artifacts | length + 1' "$output/run/manifest.json")" ]] \
  || { refuse OPERATOR_TUI_ARTIFACT_INVENTORY_DRIFT "$output/run"; exit 1; }
# Do not turn a nonzero process outcome into acceptance, even with a good report.
[[ "$status" -eq 0 ]] || { refuse OPERATOR_TUI_PROCESS_FAILED "$status"; exit "$status"; }
printf 'OPERATOR_TUI_COMPONENT_PASS: selected and completed identities match; observations=%s\n' "$output"
