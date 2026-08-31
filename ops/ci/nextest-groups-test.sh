#!/usr/bin/env bash
# Prove the exact fast-profile serialization and bounded slow-test controls.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

for tool in awk cargo-nextest cmp cp jq mktemp rg sort; do
  require_tool "$tool" || exit 1
done

readonly group=sqlite-migration-identity
readonly filter='(binary_id(bullet-adapters) & test(sqlite::migrations::)) | (binary_id(bullet-adapters::candidate_preparation) & test(=schema::exact_schema_eighteen_is_refused_without_byte_mutation))'
readonly receipt_group=command-receipt-filesystem-hostiles
readonly receipt_filter='binary_id(bullet-runner::bin/bullet-command-worker) & (test(=receipt::tests::candidate_identity::cleanup_target_and_every_tombstone_subject_are_exact) | test(=receipt::tests::candidate_identity::preservation_token_state_artifact_and_cleanup_substitutions_refuse) | test(=receipt::tests::ledger::semantic_ledger_substitutions_refuse_without_further_mutation) | test(=receipt::tests::provider_fixture::provider_transcript_drift_truncation_open_shape_and_symlink_refuse) | test(=receipt::tests::provider_fixture::self_consistent_provider_operation_substitutions_refuse))'
readonly receipt_timeout='slow-timeout = { period = "45s", terminate-after = 2 }'
readonly fast_timeout='slow-timeout = { period = "20s", terminate-after = 2 }'
test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

validate_timeout_config() {
  local config="$1"
  awk -v fast_timeout="$fast_timeout" \
    -v migration_filter="filter = '$filter'" \
    -v migration_group="test-group = 'sqlite-migration-identity'" \
    -v migration_group_line="sqlite-migration-identity = { max-threads = 1 }" \
    -v receipt_filter="filter = '$receipt_filter'" \
    -v receipt_group="test-group = '$receipt_group'" \
    -v receipt_group_line="$receipt_group = { max-threads = 1 }" \
    -v receipt_timeout="$receipt_timeout" '
    function close_section() {
      if (section == "fast") {
        if (section_entries != 2 || section_fast_timeouts != 1 || section_fast_fail != 1) invalid = 1
      } else if (section == "test_groups") {
        if (section_entries != 2 || section_migration_group_lines != 1 ||
            section_receipt_group_lines != 1) invalid = 1
      } else if (section == "fast_override") {
        if (section_entries == 2 && section_migration_filters == 1 && section_migration_groups == 1) {
          migration_override_blocks++
        } else if (section_entries == 3 && section_receipt_filters == 1 &&
                   section_receipt_groups == 1 && section_timeouts == 1) {
          receipt_override_blocks++
        } else {
          invalid = 1
        }
      }
    }
    function reset_section() {
      section_entries = 0
      section_fast_timeouts = 0
      section_fast_fail = 0
      section_migration_group_lines = 0
      section_receipt_group_lines = 0
      section_receipt_filters = 0
      section_receipt_groups = 0
      section_migration_filters = 0
      section_migration_groups = 0
      section_timeouts = 0
    }
    /^[[:space:]]*($|#)/ { next }
    /^[[:space:]]*\[/ {
      close_section()
      reset_section()
      if ($0 == "[profile.fast]") {
        section = "fast"
        fast_sections++
      } else if ($0 == "[test-groups]") {
        section = "test_groups"
        test_group_sections++
      } else if ($0 == "[[profile.fast.overrides]]") {
        section = "fast_override"
      } else if ($0 == "[profile.default]" ||
                 $0 == "[profile.fast.junit]" || $0 == "[profile.contract]" ||
                 $0 == "[profile.contract.junit]" || $0 == "[profile.family]" ||
                 $0 == "[profile.family.junit]" || $0 == "[profile.coverage]") {
        section = "other"
      } else {
        section = "unknown"
        invalid = 1
      }
      next
    }
    section == "fast" {
      section_entries++
      if (index($0, "slow-timeout") != 0) {
        if ($0 == fast_timeout) section_fast_timeouts++
        else invalid = 1
      }
      if ($0 == "fail-fast = true") section_fast_fail++
      next
    }
    section == "test_groups" {
      section_entries++
      if ($0 == migration_group_line) section_migration_group_lines++
      if ($0 == receipt_group_line) section_receipt_group_lines++
      next
    }
    section == "fast_override" {
      section_entries++
      if ($0 == migration_filter) section_migration_filters++
      if ($0 == migration_group) section_migration_groups++
      if ($0 == receipt_filter) section_receipt_filters++
      if ($0 == receipt_group) section_receipt_groups++
      if (index($0, "slow-timeout") != 0) {
        if ($0 == receipt_timeout) section_timeouts++
      }
      next
    }
    section == "" || section == "unknown" {
      invalid = 1
    }
    END {
      close_section()
      exit !(fast_sections == 1 && test_group_sections == 1 &&
             migration_override_blocks == 1 && receipt_override_blocks == 1 && !invalid)
    }
  ' "$config"
}

validate_timeout_config .config/nextest.toml \
  || { refuse NEXTEST_TIMEOUT_POLICY_INVALID 'fast timeout or exact override drifted'; exit 1; }

rewrite_exact_line() {
  local from="$1"
  local to="$2"
  local target="$3"
  awk -v from="$from" -v to="$to" '
    $0 == from { print to; replaced++; next }
    { print }
    END { if (replaced != 1) exit 2 }
  ' .config/nextest.toml >"$target"
}

remove_exact_line() {
  local removed="$1"
  local target="$2"
  awk -v removed="$removed" '
    $0 == removed { matches++; next }
    { print }
    END { if (matches != 1) exit 2 }
  ' .config/nextest.toml >"$target"
}

rewrite_line_after() {
  local marker="$1"
  local from="$2"
  local to="$3"
  local target="$4"
  awk -v marker="$marker" -v from="$from" -v to="$to" '
    $0 == marker { marked++; armed = 1; print; next }
    armed && $0 == from { print to; replaced++; armed = 0; next }
    { print }
    END { if (marked != 1 || replaced != 1) exit 2 }
  ' .config/nextest.toml >"$target"
}

remove_line_after() {
  local marker="$1"
  local removed="$2"
  local target="$3"
  awk -v marker="$marker" -v removed="$removed" '
    $0 == marker { marked++; armed = 1; print; next }
    armed && $0 == removed { matches++; armed = 0; next }
    { print }
    END { if (marked != 1 || matches != 1) exit 2 }
  ' .config/nextest.toml >"$target"
}

reject_hostile_config() {
  local path="$1"
  local reason="$2"
  if validate_timeout_config "$path"; then
    refuse NEXTEST_TIMEOUT_HOSTILE_ACCEPTED "$reason"
    exit 1
  fi
}

readonly receipt_filter_line="filter = '$receipt_filter'"
readonly receipt_filter_display="${receipt_filter//\//\\/}"
readonly receipt_group_line="$receipt_group = { max-threads = 1 }"
readonly receipt_group_override="test-group = '$receipt_group'"
readonly cleanup_term='test(=receipt::tests::candidate_identity::cleanup_target_and_every_tombstone_subject_are_exact) | '
readonly receipt_filter_omitted="${receipt_filter/"$cleanup_term"/}"
readonly receipt_filter_injected="${receipt_filter%?} | test(=receipt::tests::unreviewed_sixth_case))"

rewrite_exact_line "$receipt_filter_line" "filter = 'all()'" "$test_root/filter-all.toml"
reject_hostile_config "$test_root/filter-all.toml" 'an all() receipt filter was accepted'
rewrite_exact_line "$receipt_filter_line" \
  "filter = 'binary_id(bullet-runner::bin/bullet-command-worker)'" \
  "$test_root/filter-binary.toml"
reject_hostile_config "$test_root/filter-binary.toml" 'a binary-wide receipt filter was accepted'
rewrite_exact_line "$receipt_filter_line" \
  "filter = 'binary_id(bullet-runner::bin/bullet-command-worker) & test(receipt::tests::)'" \
  "$test_root/filter-module.toml"
reject_hostile_config "$test_root/filter-module.toml" 'a module-prefix receipt filter was accepted'
rewrite_exact_line "$receipt_filter_line" "filter = '$receipt_filter_omitted'" \
  "$test_root/filter-omitted.toml"
reject_hostile_config "$test_root/filter-omitted.toml" 'a four-identity receipt filter was accepted'
rewrite_exact_line "$receipt_filter_line" "filter = '$receipt_filter_injected'" \
  "$test_root/filter-injected.toml"
reject_hostile_config "$test_root/filter-injected.toml" 'a sixth receipt identity was accepted'

rewrite_exact_line "$receipt_group_line" "$receipt_group = { max-threads = 2 }" \
  "$test_root/group-threads.toml"
reject_hostile_config "$test_root/group-threads.toml" 'receipt max-threads=2 was accepted'
rewrite_exact_line "$receipt_group_line" 'renamed-receipt-group = { max-threads = 1 }' \
  "$test_root/group-renamed.toml"
reject_hostile_config "$test_root/group-renamed.toml" 'a renamed receipt group was accepted'
remove_exact_line "$receipt_group_line" "$test_root/group-removed.toml"
reject_hostile_config "$test_root/group-removed.toml" 'a missing receipt group was accepted'

rewrite_line_after "$receipt_group_override" "$receipt_timeout" \
  'slow-timeout = { period = "90s", terminate-after = 2 }' \
  "$test_root/timeout-changed.toml"
reject_hostile_config "$test_root/timeout-changed.toml" 'a widened receipt timeout was accepted'
remove_line_after "$receipt_group_override" "$receipt_timeout" "$test_root/timeout-removed.toml"
reject_hostile_config "$test_root/timeout-removed.toml" 'a missing receipt timeout was accepted'
remove_line_after "$receipt_group_override" "$receipt_timeout" "$test_root/timeout-displaced.toml"
printf '\n%s\n' "$receipt_timeout" >>"$test_root/timeout-displaced.toml"
reject_hostile_config "$test_root/timeout-displaced.toml" 'a displaced receipt timeout was accepted'

cp .config/nextest.toml "$test_root/duplicate-receipt-override.toml"
printf '\n%s\n%s\n%s\n%s\n' \
  '[[profile.fast.overrides]]' "$receipt_filter_line" "$receipt_group_override" \
  "$receipt_timeout" >>"$test_root/duplicate-receipt-override.toml"
reject_hostile_config "$test_root/duplicate-receipt-override.toml" \
  'a duplicate receipt override was accepted'

awk -v replacement='slow-timeout = { period = "25s", terminate-after = 2 }' '
  $0 == "[profile.fast]" { fast = 1 }
  /^\[/ && $0 != "[profile.fast]" { fast = 0 }
  fast && /^slow-timeout[[:space:]]*=/ { print replacement; next }
  { print }
  END {
    print ""
    print "[proof.synthetic]"
    print "slow-timeout = { period = \"20s\", terminate-after = 2 }"
  }
' .config/nextest.toml >"$test_root/displaced-global.toml"
if validate_timeout_config "$test_root/displaced-global.toml"; then
  refuse NEXTEST_TIMEOUT_HOSTILE_ACCEPTED 'a displaced global fast timeout was accepted'
  exit 1
fi

cp .config/nextest.toml "$test_root/broad-override.toml"
printf '\n%s\n%s\n%s\n%s\n' \
  '[[profile.fast.overrides]]' \
  "filter = 'all()'" \
  "$receipt_group_override" \
  "$receipt_timeout" >>"$test_root/broad-override.toml"
if validate_timeout_config "$test_root/broad-override.toml"; then
  refuse NEXTEST_TIMEOUT_HOSTILE_ACCEPTED 'an additional broad grouped timeout override was accepted'
  exit 1
fi

cp .config/nextest.toml "$test_root/quoted-override.toml"
printf '\n%s\n%s\n%s\n' \
  '[[profile.fast.overrides]]' \
  "filter = 'all()'" \
  '"slow-timeout" = { period = "45s", terminate-after = 2 }' \
  >>"$test_root/quoted-override.toml"
if validate_timeout_config "$test_root/quoted-override.toml"; then
  refuse NEXTEST_TIMEOUT_HOSTILE_ACCEPTED 'a quoted broad slow-timeout override was accepted'
  exit 1
fi

for hostile_header in \
  '[[profile.fast.overrides]] # bypass' \
  '  [[profile.fast.overrides]]' \
  '[["profile"."fast"."overrides"]]'; do
  hostile_name="$(printf '%s' "$hostile_header" | sha256_file /dev/stdin)"
  hostile_path="$test_root/header-$hostile_name.toml"
  cp .config/nextest.toml "$hostile_path"
  printf '\n%s\n%s\n%s\n' \
    "$hostile_header" \
    "filter = 'all()'" \
    "$receipt_timeout" >>"$hostile_path"
  if validate_timeout_config "$hostile_path"; then
    refuse NEXTEST_TIMEOUT_HOSTILE_ACCEPTED 'a noncanonical broad-override header was accepted'
    exit 1
  fi
done

[[ "$(rg -Fxc 'sqlite-migration-identity = { max-threads = 1 }' .config/nextest.toml)" -eq 1 ]] \
  || { refuse NEXTEST_SCHEMA_GROUP_INVALID 'expected one max-one migration group'; exit 1; }
[[ "$(rg -Fxc 'test-group = '\''sqlite-migration-identity'\''' .config/nextest.toml)" -eq 1 ]] \
  || { refuse NEXTEST_SCHEMA_GROUP_INVALID 'group must have exactly one override'; exit 1; }
rg -Fxq "filter = '$filter'" .config/nextest.toml \
  || { refuse NEXTEST_SCHEMA_FILTER_DRIFT 'migration group filter changed'; exit 1; }
[[ "$(rg -Fxc "$receipt_group = { max-threads = 1 }" .config/nextest.toml)" -eq 1 ]] \
  || { refuse NEXTEST_RECEIPT_GROUP_INVALID 'expected one max-one filesystem-hostile group'; exit 1; }
[[ "$(rg -Fxc "test-group = '$receipt_group'" .config/nextest.toml)" -eq 1 ]] \
  || { refuse NEXTEST_RECEIPT_GROUP_INVALID 'filesystem-hostile group must have exactly one override'; exit 1; }
rg -Fxq "filter = '$receipt_filter'" .config/nextest.toml \
  || { refuse NEXTEST_RECEIPT_FILTER_DRIFT 'filesystem-hostile group filter changed'; exit 1; }
cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all \
  --message-format json -E "$receipt_filter" >"$test_root/receipt-inventory.json"
jq -r '."rust-suites" | to_entries[] | .key as $binary | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($binary)::\(.key)"' \
  "$test_root/receipt-inventory.json" | sort -u >"$test_root/receipt-actual"
printf '%s\n' \
  'bullet-runner::bin/bullet-command-worker::receipt::tests::candidate_identity::cleanup_target_and_every_tombstone_subject_are_exact' \
  'bullet-runner::bin/bullet-command-worker::receipt::tests::candidate_identity::preservation_token_state_artifact_and_cleanup_substitutions_refuse' \
  'bullet-runner::bin/bullet-command-worker::receipt::tests::ledger::semantic_ledger_substitutions_refuse_without_further_mutation' \
  'bullet-runner::bin/bullet-command-worker::receipt::tests::provider_fixture::provider_transcript_drift_truncation_open_shape_and_symlink_refuse' \
  'bullet-runner::bin/bullet-command-worker::receipt::tests::provider_fixture::self_consistent_provider_operation_substitutions_refuse' \
  >"$test_root/receipt-expected"
cmp -s "$test_root/receipt-expected" "$test_root/receipt-actual" \
  || { refuse NEXTEST_RECEIPT_FILTER_DRIFT 'filesystem-hostile group must match exactly five reviewed identities'; exit 1; }

cargo nextest show-config test-groups --locked --workspace "${NEXTEST_FEATURES[@]}" \
  --profile fast --groups "$group" --no-pager >"$test_root/show-config"

rg -Fxq 'group: sqlite-migration-identity (max threads = 1)' "$test_root/show-config" \
  || { refuse NEXTEST_SCHEMA_GROUP_INVALID 'nextest did not apply max-threads=1'; exit 1; }
rg -Fq "* override for fast profile with filter '$filter':" "$test_root/show-config" \
  || { refuse NEXTEST_SCHEMA_OVERRIDE_MISSING 'nextest did not apply the exact fast override'; exit 1; }

awk '
  /^      [^[:space:]]/ {
    binary=$0
    sub(/^ +/, "", binary)
    sub(/:$/, "", binary)
    next
  }
  /^          [^[:space:]]/ {
    test=$0
    sub(/^ +/, "", test)
    print binary "::" test
  }
' "$test_root/show-config" | sort -u >"$test_root/actual"

printf '%s\n' \
  'bullet-adapters::sqlite::migrations::identity::tests::schema_eight_legacy_receipt_is_refused_byte_for_byte' \
  'bullet-adapters::sqlite::migrations::identity::tests::sqlite_admission_rejects_legacy_uppercase_and_wrong_prefix_receipts' \
  'bullet-adapters::sqlite::migrations::tests::altered_metadata_schema_is_refused' \
  'bullet-adapters::sqlite::migrations::tests::altered_name_and_checksum_are_refused' \
  'bullet-adapters::sqlite::migrations::tests::checksum_binds_domain_version_name_and_sql' \
  'bullet-adapters::sqlite::migrations::tests::command_identity_is_unique_and_outbox_correlation_is_foreign_keyed' \
  'bullet-adapters::sqlite::migrations::tests::configured_connection_enforces_the_receipt_foreign_key' \
  'bullet-adapters::sqlite::migrations::tests::corrupt_or_pending_restore_state_fails_closed' \
  'bullet-adapters::sqlite::migrations::tests::fresh_creation_records_exact_checksums_and_reopens' \
  'bullet-adapters::sqlite::migrations::tests::lease_migration_matches_the_frozen_phase_one_maximum' \
  'bullet-adapters::sqlite::migrations::tests::legacy_checksumless_metadata_is_refused_without_touching_truth' \
  'bullet-adapters::sqlite::migrations::tests::legacy_schema_without_metadata_is_refused_without_mutation' \
  'bullet-adapters::sqlite::migrations::tests::missing_or_corrupt_identity_contract_is_refused' \
  'bullet-adapters::sqlite::migrations::tests::missing_product_table_is_refused_despite_valid_migration_rows' \
  'bullet-adapters::sqlite::migrations::tests::partial_future_and_unrecognized_versions_are_refused' \
  'bullet-adapters::sqlite::migrations::tests::preexisting_foreign_key_violation_prevents_reopen' \
  'bullet-adapters::sqlite::migrations::tests::schema_nineteen_without_scope_admission_is_refused_byte_for_byte' \
  'bullet-adapters::sqlite::migrations::tests::schema_twenty_without_command_dispatch_claims_is_refused_byte_for_byte' \
  'bullet-adapters::sqlite::migrations::tests::schema_twenty_two_without_effect_recovery_claims_is_refused_byte_for_byte' \
  'bullet-adapters::sqlite::migrations::tests::schema_seven_with_legacy_subject_is_refused_byte_for_byte' \
  'bullet-adapters::sqlite::migrations::tests::schema_ten_without_context_authority_is_refused_byte_for_byte' \
  'bullet-adapters::sqlite::migrations::tests::unclaimed_sqlite_version_metadata_is_refused' \
  'bullet-adapters::candidate_preparation::schema::exact_schema_eighteen_is_refused_without_byte_mutation' \
  | sort -u >"$test_root/expected"

if ! cmp -s "$test_root/expected" "$test_root/actual"; then
  diff -u "$test_root/expected" "$test_root/actual" >&2 || true
  refuse NEXTEST_SCHEMA_GROUP_EXPANSION_DRIFT 'migration group must contain exactly 23 reviewed identities'
  exit 1
fi

cargo nextest show-config test-groups --locked --workspace "${NEXTEST_FEATURES[@]}" \
  --profile fast --groups "$receipt_group" --no-pager >"$test_root/receipt-show-config"
rg -Fxq "group: $receipt_group (max threads = 1)" "$test_root/receipt-show-config" \
  || { refuse NEXTEST_RECEIPT_GROUP_INVALID 'nextest did not apply receipt max-threads=1'; exit 1; }
rg -Fq "* override for fast profile with filter '$receipt_filter_display':" \
  "$test_root/receipt-show-config" \
  || { refuse NEXTEST_RECEIPT_OVERRIDE_MISSING 'nextest did not apply the exact receipt override'; exit 1; }
awk '
  /^      [^[:space:]]/ {
    binary=$0
    sub(/^ +/, "", binary)
    sub(/:$/, "", binary)
    next
  }
  /^          [^[:space:]]/ {
    test=$0
    sub(/^ +/, "", test)
    print binary "::" test
  }
' "$test_root/receipt-show-config" | sort -u >"$test_root/receipt-group-actual"
cmp -s "$test_root/receipt-expected" "$test_root/receipt-group-actual" \
  || { refuse NEXTEST_RECEIPT_GROUP_EXPANSION_DRIFT 'receipt group must contain exactly five reviewed identities'; exit 1; }

cargo nextest run --locked --workspace "${NEXTEST_FEATURES[@]}" --profile fast \
  --run-ignored all -E "$receipt_filter"

rg -Fxq 'bash ops/ci/nextest-groups-test.sh' ops/ci/lint.sh \
  || { refuse NEXTEST_SCHEMA_GROUP_ROUTING_MISSING ops/ci/lint.sh; exit 1; }
log 'nextest controls passed: 23 serialized migrations and five bounded receipt hostiles'
