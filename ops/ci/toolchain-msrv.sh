#!/usr/bin/env bash
# Explicit MSRV lane: build and test bullet-kernel under Rust 1.95.0.
#
# The Hub release contract (bullet-farm docs/release.md) requires every Rust workspace to
# build at MSRV Rust 1.95 and at pinned Rust 1.97.1; this repository pins 1.97.1 in
# rust-toolchain.toml and in .github/workflows/ci.yml, so 1.95.0 is only ever proved here.
# There is no scripts/ci-doctor.sh in this repository; the checks below are this lane's doctor.
# This lane never changes that pin and is not part of `fast`, `required`, or any
# hosted job. It builds and tests the whole workspace under rustup toolchain
# 1.95.0 using the exact argv and environment bindings that the Hub MSRV
# receipt schema expects (bullet-farm `src/check/release_evidence/verify.rs`,
# `expected_commands`), isolated in `target/toolchain-1.95.0/`, and writes one
# machine-local observation file under `.bullet-family/` (ignored). That file is an
# input for a future operator-signed `release.rust-msrv-1-95` receipt; it is not a receipt,
# not gate evidence, and cannot clear any release gate.
#
# Fail-closed: a missing rustup toolchain, tool, or subject is a typed refusal
# (exit 1), never a skip. A failing build or test fails the lane after the
# observation is written, so the failure itself stays on record.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

lane="toolchain-msrv"
toolchain="1.95.0"
repository="bullet-kernel"
gate_id="release.rust-msrv-1-95"
b3sum_version="b3sum 1.8.2"
observation_dir="$REPO_ROOT/.bullet-family"
observation="$observation_dir/toolchain-$toolchain-$repository.json"
build_log="$observation_dir/toolchain-$toolchain-$repository.build.log"
test_log="$observation_dir/toolchain-$toolchain-$repository.test.log"
target_dir="$REPO_ROOT/target/toolchain-$toolchain"
build_argv=(build --workspace --all-targets --locked)
test_argv=(test --workspace --all-targets --locked --no-fail-fast)

refuse() {
  printf '[ci] %s: %s\n' "$1" "$2" >&2
  exit 1
}


export RUSTUP_AUTO_INSTALL=0
for tool in b3sum git jq rustup; do
  command -v "$tool" >/dev/null 2>&1 \
    || refuse TOOLCHAIN_LANE_TOOL_MISSING "$tool is required for $lane"
done
[[ "$(b3sum --version)" == "$b3sum_version" ]] \
  || refuse TOOLCHAIN_LANE_TOOL_VERSION "expected $b3sum_version, found $(b3sum --version)"
rustup toolchain list | grep -q "^${toolchain}-" \
  || refuse TOOLCHAIN_LANE_TOOLCHAIN_MISSING \
    "rustup toolchain $toolchain is not installed; run: rustup toolchain install $toolchain --profile minimal"
cargo_bin="$(rustup which --toolchain "$toolchain" cargo)" \
  || refuse TOOLCHAIN_LANE_TOOLCHAIN_MISSING "rustup cannot resolve cargo for $toolchain"
rustc_bin="$(rustup which --toolchain "$toolchain" rustc)" \
  || refuse TOOLCHAIN_LANE_TOOLCHAIN_MISSING "rustup cannot resolve rustc for $toolchain"
[[ "$cargo_bin" == /* && -x "$cargo_bin" && "$rustc_bin" == /* && -x "$rustc_bin" ]] \
  || refuse TOOLCHAIN_LANE_TOOLCHAIN_MISSING "resolved $toolchain tools are not absolute executables"
rustc_version="$("$rustc_bin" --version)"
cargo_version="$("$cargo_bin" --version)"
[[ "$rustc_version" == "rustc $toolchain "* ]] \
  || refuse TOOLCHAIN_LANE_TOOLCHAIN_MISMATCH "expected rustc $toolchain, found $rustc_version"
[[ "$cargo_version" == "cargo $toolchain "* ]] \
  || refuse TOOLCHAIN_LANE_TOOLCHAIN_MISMATCH "expected cargo $toolchain, found $cargo_version"
[[ -f Cargo.lock ]] || refuse TOOLCHAIN_LANE_SUBJECT_MISSING "Cargo.lock is absent"
git rev-parse --verify --quiet 'HEAD^{commit}' >/dev/null \
  || refuse TOOLCHAIN_LANE_SUBJECT_MISSING "HEAD is not a commit"

object_format="$(git rev-parse --show-object-format)"
commit_oid="$object_format:$(git rev-parse --verify 'HEAD^{commit}')"
tree_oid="$object_format:$(git rev-parse --verify 'HEAD^{tree}')"
dirty_entries="$(git status --porcelain --untracked-files=all | wc -l | tr -d ' ')"
lockfile_digest="blake3:$(b3sum --no-names Cargo.lock)"
rustc_digest="blake3:$(b3sum --no-names "$rustc_bin")"
cargo_digest="blake3:$(b3sum --no-names "$cargo_bin")"

if [[ -d "$target_dir" ]]; then target_preexisting=true; else target_preexisting=false; fi
mkdir -p "$observation_dir"
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
export RUSTC="$rustc_bin"
export RUSTUP_TOOLCHAIN="$toolchain"
export CARGO_TARGET_DIR="$target_dir"

log "$lane: $rustc_version; $cargo_version"
log "$lane: subject $commit_oid (worktree entries changed: $dirty_entries); target $target_dir"
started_at="$(date +%s%3N)"

log "$lane: cargo ${build_argv[*]}"
set +e
"$cargo_bin" "${build_argv[@]}" 2>&1 | tee "$build_log"
build_exit="${PIPESTATUS[0]}"
set -e
build_units="$(grep -c '^ *Compiling ' "$build_log" || true)"
build_digest="blake3:$(b3sum --no-names "$build_log")"

log "$lane: cargo ${test_argv[*]}"
set +e
"$cargo_bin" "${test_argv[@]}" 2>&1 | tee "$test_log"
test_exit="${PIPESTATUS[0]}"
set -e
read -r tests_passed tests_failed tests_ignored < <(awk '
  /^test result: / {
    for (i = 1; i <= NF; i++) {
      if ($(i + 1) == "passed;") passed += $i
      if ($(i + 1) == "failed;") failed += $i
      if ($(i + 1) == "ignored;") ignored += $i
    }
  }
  END { printf "%d %d %d\n", passed, failed, ignored }' "$test_log")
test_digest="blake3:$(b3sum --no-names "$test_log")"
completed_at="$(date +%s%3N)"

# The recorded argv is derived from the arrays actually executed above, so the
# observation can never drift from the commands this lane ran.
build_argv_json="$(printf '%s\n' "${build_argv[@]}" | jq -Rsc 'split("\n")[:-1]')"
test_argv_json="$(printf '%s\n' "${test_argv[@]}" | jq -Rsc 'split("\n")[:-1]')"
jq -n \
  --arg family bullet-farm --arg gate_id "$gate_id" --arg repository "$repository" \
  --arg lane "$lane" --arg toolchain "$toolchain" \
  --arg rustc_path "$rustc_bin" --arg rustc_version "$rustc_version" --arg rustc_digest "$rustc_digest" \
  --arg cargo_path "$cargo_bin" --arg cargo_version "$cargo_version" --arg cargo_digest "$cargo_digest" \
  --arg commit_oid "$commit_oid" --arg tree_oid "$tree_oid" --arg lockfile_digest "$lockfile_digest" \
  --argjson dirty_entries "$dirty_entries" --arg target_dir "$target_dir" \
  --argjson target_preexisting "$target_preexisting" \
  --argjson started_at "$started_at" --argjson completed_at "$completed_at" \
  --argjson build_exit "$build_exit" --argjson build_units "$build_units" --arg build_digest "$build_digest" \
  --arg build_log "$build_log" \
  --argjson test_exit "$test_exit" --argjson tests_passed "$tests_passed" \
  --argjson tests_failed "$tests_failed" --argjson tests_skipped "$tests_ignored" \
  --arg test_digest "$test_digest" --arg test_log "$test_log" \
  --argjson build_argv "$build_argv_json" --argjson test_argv "$test_argv_json" '
  def environment: [
    { name: "CARGO_INCREMENTAL", value: "0" },
    { name: "CARGO_NET_OFFLINE", value: "true" },
    { name: "RUSTC", value: $rustc_path },
    { name: "RUSTUP_TOOLCHAIN", value: $toolchain }
  ];
  def blockers: [
    (if $dirty_entries > 0 then "worktree is not the clean committed subject (\($dirty_entries) changed entries)" else empty end),
    (if $build_exit != 0 then "build exit code \($build_exit)" else empty end),
    (if $target_preexisting then "cargo target directory already existed, so this was a warm incremental build; a receipt needs a full build from a clean target directory" else empty end),
    (if $build_units == 0 then "build compiled zero units; a receipt needs a nonempty build" else empty end),
    (if $test_exit != 0 then "test exit code \($test_exit)" else empty end),
    (if $tests_failed > 0 then "\($tests_failed) failed tests" else empty end),
    (if $tests_skipped > 0 then "\($tests_skipped) ignored tests count as skipped; a receipt requires zero" else empty end),
    (if $tests_passed == 0 then "zero passing tests" else empty end)
  ];
  {
    toolchain_observation_schema_version: "1",
    family: $family,
    gate_id: $gate_id,
    lane: $lane,
    toolchain: $toolchain,
    authority: "machine-local observation written by ops/ci/\($lane).sh; not a receipt, not gate evidence. The signed receipt schema for this gate is bullet-farm src/check/release_evidence/schema.rs (CommandObservation); the command entries below use that exact field set",
    subject: {
      repository: $repository,
      commit_oid: $commit_oid,
      tree_oid: $tree_oid,
      lockfile_path: "Cargo.lock",
      lockfile_digest: $lockfile_digest,
      worktree_dirty_entries: $dirty_entries
    },
    rustc: { path: $rustc_path, version: $rustc_version, digest: $rustc_digest },
    cargo: { path: $cargo_path, version: $cargo_version, digest: $cargo_digest },
    cargo_target_dir: $target_dir,
    cargo_target_dir_preexisting: $target_preexisting,
    tests_skipped_source: "cargo test `ignored` counter summed over every `test result:` line",
    started_at_unix_ms: $started_at,
    completed_at_unix_ms: $completed_at,
    command: [
      {
        repository: $repository,
        kind: "BUILD",
        program: $cargo_path,
        argv: $build_argv,
        environment: environment,
        build_units: $build_units,
        tests_passed: 0,
        tests_failed: 0,
        tests_skipped: 0,
        exit_code: $build_exit,
        output_digest: $build_digest
      },
      {
        repository: $repository,
        kind: "TEST",
        program: $cargo_path,
        argv: $test_argv,
        environment: environment,
        build_units: 0,
        tests_passed: $tests_passed,
        tests_failed: $tests_failed,
        tests_skipped: $tests_skipped,
        exit_code: $test_exit,
        output_digest: $test_digest
      }
    ],
    output_logs: [$build_log, $test_log],
    receipt_grade: (blockers | length == 0),
    receipt_grade_blockers: blockers
  }' > "$observation.tmp"
mv "$observation.tmp" "$observation"

log "$lane: observation $observation"
log "$lane: build exit $build_exit ($build_units units); test exit $test_exit ($tests_passed passed, $tests_failed failed, $tests_ignored ignored)"
if [[ "$build_exit" -ne 0 || "$test_exit" -ne 0 ]]; then
  refuse TOOLCHAIN_LANE_FAILED "$repository does not build and test cleanly under Rust $toolchain"
fi
if [[ "$(jq -r '.receipt_grade' "$observation")" != "true" ]]; then
  jq -r '.receipt_grade_blockers[] | "[ci] '"$lane"': observation is below receipt grade: \(.)"' "$observation"
fi
log "$lane passed under Rust $toolchain (observation only; $gate_id stays BLOCKED until an operator receipt exists)"
