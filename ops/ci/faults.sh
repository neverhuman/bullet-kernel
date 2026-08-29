#!/usr/bin/env bash
# Bounded component fault sampler. This is a closed named filter inside the
# standalone partition, not a fifth inventory class or a release fault gate.
set -euo pipefail
umask 077
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

if ! $CI_CARGO_TARGET_ADMITTED; then
  refuse CI_PROOF_TARGET_UNTRUSTED \
    'faults lane requires the custody wrapper private Cargo target'
  exit 1
fi

readonly EXPECTED_COMPONENT_FAULT_TESTS=13
readonly COMPONENT_FAULT_FILTER='
  (binary_id(bullet-harness-core) & (
    test(=spawnrun::tests::provider_crash_is_nonzero_and_descendants_are_killed) |
    test(=spawnrun::tests::timeout_kills_the_process_group_and_keeps_partial_output) |
    test(=spawnrun::tests::explicit_cancel_kills_the_process_group) |
    test(=spawnrun::tests::heartbeat_failure_kills_the_process_group)
  )) |
  (binary_id(bullet::bin/bullet) &
    test(=demo_synthetic::verify::tests::hostile_oversized_child_is_killed_and_reaped_promptly)) |
  (binary_id(bullet-adapters::cross_process) &
    test(=expired_lease_is_reclaimed_by_another_process)) |
  (binary_id(bullet-adapters::restart_process) &
    test(=process_restart_fault_matrix_uses_separate_os_processes)) |
  (binary_id(bullet-adapters::chaos) & (
    test(=killed_writer_is_reclaimed_and_successor_gets_next_fence) |
    test(=exact_preservation_decision_is_consumed_before_cleanup)
  )) |
  (binary_id(bullet-verifier-core::aggregate) & (
    test(=zero_tests_infra_and_timeout_never_pass) |
    test(=oracle_modifying_diff_is_classified)
  )) |
  (binary_id(bullet-effects-core::reconcile) & (
    test(=lost_response_after_push_is_unknown_then_adopted) |
    test(=remote_moved_while_unknown_is_quarantined_not_retried)
  ))
'
readonly COMPONENT_FAULT_IDENTITIES=(
  'bullet-adapters::chaos::exact_preservation_decision_is_consumed_before_cleanup'
  'bullet-adapters::chaos::killed_writer_is_reclaimed_and_successor_gets_next_fence'
  'bullet-adapters::cross_process::expired_lease_is_reclaimed_by_another_process'
  'bullet-adapters::restart_process::process_restart_fault_matrix_uses_separate_os_processes'
  'bullet-effects-core::reconcile::lost_response_after_push_is_unknown_then_adopted'
  'bullet-effects-core::reconcile::remote_moved_while_unknown_is_quarantined_not_retried'
  'bullet-harness-core::spawnrun::tests::explicit_cancel_kills_the_process_group'
  'bullet-harness-core::spawnrun::tests::heartbeat_failure_kills_the_process_group'
  'bullet-harness-core::spawnrun::tests::provider_crash_is_nonzero_and_descendants_are_killed'
  'bullet-harness-core::spawnrun::tests::timeout_kills_the_process_group_and_keeps_partial_output'
  'bullet-verifier-core::aggregate::oracle_modifying_diff_is_classified'
  'bullet-verifier-core::aggregate::zero_tests_infra_and_timeout_never_pass'
  'bullet::bin/bullet::demo_synthetic::verify::tests::hostile_oversized_child_is_killed_and_reaped_promptly'
)

for tool in cargo-nextest jq cmp sort mktemp awk; do
  require_tool "$tool" || exit 1
done
deny_sibling_gitd

inventory_json="$(mktemp)"
actual_identities="$(mktemp)"
expected_identities="$(mktemp)"
cleanup() {
  rm -f -- "$inventory_json" "$actual_identities" "$expected_identities"
}
trap cleanup EXIT

cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all \
  --message-format json -E "$COMPONENT_FAULT_FILTER" >"$inventory_json"
jq -r '
  ."rust-suites" | to_entries[] | .key as $binary |
  .value.testcases | to_entries[] |
  select(.value["filter-match"].status == "matches") |
  "\($binary)::\(.key)"
' "$inventory_json" | sort -u >"$actual_identities"
printf '%s\n' "${COMPONENT_FAULT_IDENTITIES[@]}" | sort -u >"$expected_identities"
if ! cmp -s "$expected_identities" "$actual_identities"; then
  diff -u "$expected_identities" "$actual_identities" >&2 || true
  refuse COMPONENT_FAULT_IDENTITY_DRIFT \
    "named component fault identities changed"
  exit 1
fi

log "faults lane: exact 13-case component identity set"
selected="$(partition_count "$COMPONENT_FAULT_FILTER")" || exit 1
if [[ "$selected" -ne "$EXPECTED_COMPONENT_FAULT_TESTS" || "$selected" -eq 0 ]]; then
  refuse TEST_PARTITION_DRIFT \
    "component faults selected $selected tests; expected $EXPECTED_COMPONENT_FAULT_TESTS"
  exit 1
fi
outside="$(partition_count "($COMPONENT_FAULT_FILTER) & not ($STANDALONE_FILTER)")" || exit 1
if [[ "$outside" -ne 0 ]]; then
  refuse COMPONENT_FAULT_PARTITION_DRIFT \
    "$outside named component identities escaped the standalone partition"
  exit 1
fi

run_partition_tests faults fast "$EXPECTED_COMPONENT_FAULT_TESTS" "$COMPONENT_FAULT_FILTER"
fault_junit="$REPO_ROOT/.ci-artifacts/junit/faults.xml"
if ! awk -v expected="$EXPECTED_COMPONENT_FAULT_TESTS" '
  NR == 2 && /^<testsuites / {
    if (match($0, / tests="[0-9]+"/)) {
      result_count = substr($0, RSTART + 8, RLENGTH - 9) + 0
      root_seen = 1
    }
    if (match($0, / failures="[0-9]+"/))
      failures = substr($0, RSTART + 11, RLENGTH - 12) + 0
    if (match($0, / errors="[0-9]+"/))
      errors = substr($0, RSTART + 9, RLENGTH - 10) + 0
  }
  index($0, "<skipped") != 0 || $0 ~ / disabled="[1-9][0-9]*"/ { skipped = 1 }
  END {
    exit !(root_seen && result_count == expected && failures == 0 &&
      errors == 0 && !skipped)
  }
' "$fault_junit"; then
  refuse COMPONENT_FAULT_JUNIT_DRIFT \
    "expected exactly $EXPECTED_COMPONENT_FAULT_TESTS results and zero failures/errors/skips"
  exit 1
fi
log "component fault sampler passed; release fault receipt remains unavailable"
