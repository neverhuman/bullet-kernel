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
readonly fsync_filter='binary_id(bullet-runner::bin/bullet-command-worker) & test(=receipt::tests::ledger::semantic_ledger_substitutions_refuse_without_further_mutation)'
readonly fsync_timeout='slow-timeout = { period = "45s", terminate-after = 2 }'
readonly fast_timeout='slow-timeout = { period = "20s", terminate-after = 2 }'
test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

validate_timeout_config() {
  local config="$1"
  awk -v fast_timeout="$fast_timeout" \
    -v migration_filter="filter = '$filter'" \
    -v migration_group="test-group = 'sqlite-migration-identity'" \
    -v fsync_filter="filter = '$fsync_filter'" \
    -v fsync_timeout="$fsync_timeout" '
    function close_section() {
      if (section == "fast") {
        if (section_entries != 2 || section_fast_timeouts != 1 || section_fast_fail != 1) invalid = 1
      } else if (section == "fast_override") {
        if (section_entries == 2 && section_migration_filters == 1 && section_migration_groups == 1) {
          migration_override_blocks++
        } else if (section_entries == 2 && section_fsync_filters == 1 && section_timeouts == 1) {
          slow_override_blocks++
        } else {
          invalid = 1
        }
      }
    }
    function reset_section() {
      section_entries = 0
      section_fast_timeouts = 0
      section_fast_fail = 0
      section_fsync_filters = 0
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
      } else if ($0 == "[[profile.fast.overrides]]") {
        section = "fast_override"
      } else if ($0 == "[profile.default]" || $0 == "[test-groups]" ||
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
    section == "fast_override" {
      section_entries++
      if ($0 == migration_filter) section_migration_filters++
      if ($0 == migration_group) section_migration_groups++
      if ($0 == fsync_filter) section_fsync_filters++
      if (index($0, "slow-timeout") != 0) {
        if ($0 == fsync_timeout) section_timeouts++
      }
      next
    }
    section == "" || section == "unknown" {
      invalid = 1
    }
    END {
      close_section()
      exit !(fast_sections == 1 && migration_override_blocks == 1 &&
             slow_override_blocks == 1 && !invalid)
    }
  ' "$config"
}

validate_timeout_config .config/nextest.toml \
  || { refuse NEXTEST_TIMEOUT_POLICY_INVALID 'fast timeout or exact override drifted'; exit 1; }

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
printf '\n%s\n%s\n%s\n' \
  '[[profile.fast.overrides]]' \
  "filter = 'all()'" \
  "$fsync_timeout" >>"$test_root/broad-override.toml"
if validate_timeout_config "$test_root/broad-override.toml"; then
  refuse NEXTEST_TIMEOUT_HOSTILE_ACCEPTED 'an additional broad slow-timeout override was accepted'
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
    "$fsync_timeout" >>"$hostile_path"
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
cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all \
  --message-format json -E "$fsync_filter" >"$test_root/fsync-inventory.json"
jq -r '."rust-suites" | to_entries[] | .key as $binary | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($binary)::\(.key)"' \
  "$test_root/fsync-inventory.json" | sort -u >"$test_root/fsync-actual"
printf '%s\n' \
  'bullet-runner::bin/bullet-command-worker::receipt::tests::ledger::semantic_ledger_substitutions_refuse_without_further_mutation' \
  >"$test_root/fsync-expected"
cmp -s "$test_root/fsync-expected" "$test_root/fsync-actual" \
  || { refuse NEXTEST_FSYNC_FILTER_DRIFT 'retained-ledger timeout must match exactly one reviewed identity'; exit 1; }

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

rg -Fxq 'bash ops/ci/nextest-groups-test.sh' ops/ci/lint.sh \
  || { refuse NEXTEST_SCHEMA_GROUP_ROUTING_MISSING ops/ci/lint.sh; exit 1; }
log 'nextest controls passed: 23 serialized migrations and one bounded fsync-hostile override'
