#!/usr/bin/env bash
# Exercise actual partition dispatch and retention with a synthetic test runner.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
origin="$REPO_ROOT"
umask 077
fixture="$(mktemp -d)"
cleanup() {
  local status=$?
  if (( status == 0 )); then rm -rf -- "$fixture";
  else printf '[ci] retained failed JUnit fixture: %s\n' "$fixture" >&2; fi
}
trap cleanup EXIT
make_case() {
  REPO_ROOT="$fixture/$1"
  mkdir -p "$REPO_ROOT/ops/ci"
  cp "$origin/ops/ci/junit-retention.sh" "$origin/ops/ci/sanitize-junit.sh" "$REPO_ROOT/ops/ci/"
  prepare_junit_store fast fast
  printf 'original failed raw report\n' >"$REPO_ROOT/target/nextest/fast/junit.xml"
  printf 'original published failure\n' >"$REPO_ROOT/.ci-artifacts/junit/fast.xml"
}
partition_count() { printf '1\n'; }
cargo() {
  if [[ -n "${EXPECTED_PRIOR_RAW_SHA:-}" ]]; then
    [[ ! -e "$REPO_ROOT/target/nextest/fast/junit.xml" ]] || return 91
    [[ "$(cat "$REPO_ROOT/.ci-artifacts/junit/fast.xml")" == 'original published failure' ]] || return 92
    local archived found=false
    while IFS= read -r archived; do
      if [[ "$(sha256_file "$archived")" == "$EXPECTED_PRIOR_RAW_SHA" ]]; then found=true; fi
    done < <(find "$REPO_ROOT/.ci-artifacts/junit/history" -name raw.xml)
    "$found" || return 93
  fi
  printf 'launched\n' >>"$REPO_ROOT/launched"
  cat >"$REPO_ROOT/target/nextest/fast/junit.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="fixture" tests="1" failures="0" errors="0">
  <testsuite name="suite" tests="1" failures="0" errors="0">
    <testcase name="case" classname="suite" time="0.1"/>
  </testsuite>
</testsuites>
XML
  case "${RAW_REPORT_MODE:-valid}" in
    empty) : >"$REPO_ROOT/target/nextest/fast/junit.xml" ;;
    malformed) printf '<testsuites><unexpected/></testsuites>\n' >"$REPO_ROOT/target/nextest/fast/junit.xml" ;;
    missing) rm -- "$REPO_ROOT/target/nextest/fast/junit.xml" ;;
    valid) ;;
    *) return 94 ;;
  esac
  return "${RUNNER_STATUS:-0}"
}
assert_retained() {
  local raw published
  raw="$(find "$REPO_ROOT/.ci-artifacts/junit/history" -name raw.xml -print -quit)"
  published="$(find "$REPO_ROOT/.ci-artifacts/junit/history" -name published.xml -print -quit)"
  [[ "$(cat "$raw")" == 'original failed raw report' ]]
  [[ "$(cat "$published")" == 'original published failure' ]]
  (cd "$(dirname "$raw")"; sha256sum --check SHA256SUMS)
}
CI_CARGO_TARGET_ADMITTED=false
make_case successful-retry
run_partition_tests fast fast 1 fixture
assert_retained
[[ -s "$REPO_ROOT/.ci-artifacts/junit/fast.xml" ]]
make_case failed-new-run
RUNNER_STATUS=42
status=0
(run_partition_tests fast fast 1 fixture) || status=$?
[[ "$status" == 42 ]]
assert_retained
failed_raw_sha="$(sha256_file "$REPO_ROOT/target/nextest/fast/junit.xml")"
failed_published_sha="$(sha256_file "$REPO_ROOT/.ci-artifacts/junit/fast.xml")"
unset RUNNER_STATUS
run_partition_tests fast fast 1 fixture
for kind in raw published; do
  retained=false
  expected_sha="$failed_raw_sha"
  [[ "$kind" != published ]] || expected_sha="$failed_published_sha"
  while IFS= read -r report; do
    if [[ "$(sha256_file "$report")" == "$expected_sha" ]]; then retained=true; fi
  done < <(find "$REPO_ROOT/.ci-artifacts/junit/history" -name "$kind.xml")
  "$retained"
done
make_case first-run
rm -- "$REPO_ROOT/target/nextest/fast/junit.xml" "$REPO_ROOT/.ci-artifacts/junit/fast.xml"
run_partition_tests fast fast 1 fixture
[[ ! -e "$REPO_ROOT/.ci-artifacts/junit/history" ]]
for hostile in raw-symlink raw-hardlink public-mode history-symlink; do
  make_case "$hostile"
  case "$hostile" in
    raw-symlink) mv "$REPO_ROOT/target/nextest/fast/junit.xml" "$REPO_ROOT/outside"
      ln -s "$REPO_ROOT/outside" "$REPO_ROOT/target/nextest/fast/junit.xml" ;;
    raw-hardlink) ln "$REPO_ROOT/target/nextest/fast/junit.xml" "$REPO_ROOT/peer" ;;
    public-mode) chmod 644 "$REPO_ROOT/.ci-artifacts/junit/fast.xml" ;;
    history-symlink) mkdir "$REPO_ROOT/outside"; ln -s "$REPO_ROOT/outside" "$REPO_ROOT/.ci-artifacts/junit/history" ;;
  esac
  status=0
  (run_partition_tests fast fast 1 fixture) >"$REPO_ROOT/result.log" 2>&1 || status=$?
  [[ "$status" != 0 && ! -e "$REPO_ROOT/launched" ]]
  [[ "$(cat "$REPO_ROOT/target/nextest/fast/junit.xml")" == 'original failed raw report' ]]
  [[ "$(cat "$REPO_ROOT/.ci-artifacts/junit/fast.xml")" == 'original published failure' ]]
done
make_case partial-move-failure
# Invoked by retain_junit_reports in the sourced production helper.
# shellcheck disable=SC2317
mv() { if [[ "$3" == */junit/fast.xml ]]; then return 73; fi; command mv "$@"; }
status=0
(run_partition_tests fast fast 1 fixture) >"$REPO_ROOT/result.log" 2>&1 || status=$?
unset -f mv
[[ "$status" != 0 && ! -e "$REPO_ROOT/launched" ]]
[[ "$(cat "$REPO_ROOT/.ci-artifacts/junit/fast.xml")" == 'original published failure' ]]
raw="$(find "$REPO_ROOT/.ci-artifacts/junit/history" -name raw.xml -print -quit)"
[[ "$(cat "$raw")" == 'original failed raw report' ]]
run_partition_tests fast fast 1 fixture
assert_retained
make_case shared-profile
EXPECTED_PRIOR_RAW_SHA="$(sha256_file "$REPO_ROOT/target/nextest/fast/junit.xml")"
run_partition_tests lint-receipt-group fast 1 fixture
[[ "$(cat "$REPO_ROOT/.ci-artifacts/junit/fast.xml")" == 'original published failure' ]]
[[ -s "$REPO_ROOT/.ci-artifacts/junit/lint-receipt-group.xml" ]]
[[ "$(wc -l <"$REPO_ROOT/launched")" -eq 1 ]]
EXPECTED_PRIOR_RAW_SHA="$(sha256_file "$REPO_ROOT/target/nextest/fast/junit.xml")"
group_published_sha="$(sha256_file "$REPO_ROOT/.ci-artifacts/junit/lint-receipt-group.xml")"
run_partition_tests lint-receipt-group fast 1 fixture
[[ "$(wc -l <"$REPO_ROOT/launched")" -eq 2 ]]
published="$(find "$REPO_ROOT/.ci-artifacts/junit/history" -name published.xml -print -quit)"
[[ "$(sha256_file "$published")" == "$group_published_sha" ]]
unset EXPECTED_PRIOR_RAW_SHA
make_case sync-failure
# Durability failure must stop before a test runner can overwrite anything.
# shellcheck disable=SC2317
sync() { return 74; }
status=0
(run_partition_tests fast fast 1 fixture) >"$REPO_ROOT/result.log" 2>&1 || status=$?
unset -f sync
[[ "$status" != 0 && ! -e "$REPO_ROOT/launched" ]]
[[ "$(cat "$REPO_ROOT/.ci-artifacts/junit/fast.xml")" == 'original published failure' ]]
raw="$(find "$REPO_ROOT/.ci-artifacts/junit/history" -name raw.xml -print -quit)"
[[ "$(cat "$raw")" == 'original failed raw report' ]]
(cd "$(dirname "$raw")"; sha256sum --check SHA256SUMS)
run_partition_tests fast fast 1 fixture
assert_retained
# Run the real observation emitter as the hosted workflow does after a failed
# lane. Tool version probes use a closed synthetic PATH, never a real compiler.
observation_bin="$fixture/observation-bin"
mkdir "$observation_bin"
for tool in bash dirname git jq sha256sum awk head mkdir; do
  ln -s "$(command -v "$tool")" "$observation_bin/$tool"
done
for runner_status in 42 0; do
  for RAW_REPORT_MODE in malformed missing empty; do
    make_case "staging-$runner_status-$RAW_REPORT_MODE"
    RUNNER_STATUS="$runner_status"
    status=0
    (run_partition_tests fast fast 1 fixture) >"$REPO_ROOT/result.log" 2>&1 || status=$?
    expected_status="$runner_status"
    [[ "$expected_status" != 0 ]] || expected_status=1
    [[ "$status" == "$expected_status" ]] || {
      printf '[ci] primary failure changed: runner=%s staging=%s actual=%s expected=%s\n' \
        "$runner_status" "$RAW_REPORT_MODE" "$status" "$expected_status" >&2
      exit 1
    }
    grep -Fq "JUNIT_SANITATION_FAILED: lane=fast runner_exit=$runner_status sanitation_exit=1" "$REPO_ROOT/result.log"
    [[ ! -e "$REPO_ROOT/.ci-artifacts/junit/fast.xml" ]]
    assert_retained
    current_raw="$REPO_ROOT/target/nextest/fast/junit.xml"
    if [[ "$RAW_REPORT_MODE" == missing ]]; then
      [[ ! -e "$current_raw" ]]
    else
      [[ -f "$current_raw" && ! -L "$current_raw" ]]
      rejected_sha="$(sha256_file "$current_raw")"
      if [[ "$RAW_REPORT_MODE" == empty ]]; then [[ ! -s "$current_raw" ]];
      else [[ "$(cat "$current_raw")" == '<testsuites><unexpected/></testsuites>' ]]; fi
    fi
    mkdir "$REPO_ROOT/scripts"
    cp "$origin/scripts/ci-observation.sh" "$REPO_ROOT/scripts/ci-observation.sh"
    git -c init.templateDir= init --quiet "$REPO_ROOT"
    git -C "$REPO_ROOT" add -- scripts ops
    git -C "$REPO_ROOT" -c core.hooksPath=/dev/null -c commit.gpgsign=false \
      -c user.name=Fixture -c user.email=fixture@example.invalid commit --quiet -m fixture
    PATH="$observation_bin" bash "$REPO_ROOT/scripts/ci-observation.sh" fast "$status" \
      'bash scripts/ci-local.sh fast' >"$REPO_ROOT/observation.log"
    jq -e --argjson code "$expected_status" \
      --arg commit "$(git -C "$REPO_ROOT" rev-parse HEAD)" \
      --arg tree "$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" '
      .schema_version == "bullet.ci-observation.v1" and .repository == "bullet-kernel" and
      .commit_oid == $commit and .tree_oid == $tree and (.clean | type == "boolean") and
      .commands == ["bash scripts/ci-local.sh fast"] and (.tool_versions | type == "object") and
      .outcomes == [{lane:"fast",status:"FAIL",exit_code:$code}] and .artifact_hashes == [] and
      .signed == false and .evidence_class == "DIAGNOSTIC_ONLY" and
      (keys | sort) == (["artifact_hashes","clean","commands","commit_oid","evidence_class",
        "outcomes","repository","schema_version","signed","tool_versions","tree_oid"] | sort)
    ' "$REPO_ROOT/.ci-artifacts/observations/fast.json" >/dev/null
    unset RUNNER_STATUS
    previous_mode="$RAW_REPORT_MODE"
    RAW_REPORT_MODE=valid
    run_partition_tests fast fast 1 fixture >"$REPO_ROOT/retry.log" 2>&1
    if [[ "$previous_mode" != missing ]]; then
      retained=false
      while IFS= read -r raw; do
        if [[ "$(sha256_file "$raw")" == "$rejected_sha" ]]; then retained=true; fi
      done < <(find "$REPO_ROOT/.ci-artifacts/junit/history" -name raw.xml)
      "$retained"
    fi
    # A later successful retry cannot rewrite the recorded failed observation.
    jq -e --argjson code "$expected_status" '.outcomes[0].exit_code == $code and .outcomes[0].status == "FAIL"' \
      "$REPO_ROOT/.ci-artifacts/observations/fast.json" >/dev/null
    printf '[ci] staging observation runner=%s report=%s: ' "$runner_status" "$previous_mode"
    jq -c . "$REPO_ROOT/.ci-artifacts/observations/fast.json"
  done
done
unset RAW_REPORT_MODE
printf '[ci] JUnit predecessor retention: 16 cases passed, including primary/staging failures and diagnostic observations\n'
