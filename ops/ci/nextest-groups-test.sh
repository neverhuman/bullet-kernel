#!/usr/bin/env bash
# Prove the fast profile serializes only SQLite migration/schema-identity tests.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

for tool in awk cargo-nextest cmp mktemp rg sort; do
  require_tool "$tool" || exit 1
done

readonly group=sqlite-migration-identity
readonly filter='(binary_id(bullet-adapters) & test(sqlite::migrations::)) | (binary_id(bullet-adapters::candidate_preparation) & test(=schema::exact_schema_eighteen_is_refused_without_byte_mutation))'
test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

rg -Fxq 'slow-timeout = { period = "20s", terminate-after = 2 }' .config/nextest.toml \
  || { refuse NEXTEST_FAST_TIMEOUT_DRIFT 'the reviewed fast timeout changed'; exit 1; }
[[ "$(rg -Fxc 'sqlite-migration-identity = { max-threads = 1 }' .config/nextest.toml)" -eq 1 ]] \
  || { refuse NEXTEST_SCHEMA_GROUP_INVALID 'expected one max-one migration group'; exit 1; }
[[ "$(rg -Fxc 'test-group = '\''sqlite-migration-identity'\''' .config/nextest.toml)" -eq 1 ]] \
  || { refuse NEXTEST_SCHEMA_GROUP_INVALID 'group must have exactly one override'; exit 1; }
rg -Fxq "filter = '$filter'" .config/nextest.toml \
  || { refuse NEXTEST_SCHEMA_FILTER_DRIFT 'migration group filter changed'; exit 1; }

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
log 'nextest migration group passed: 23 exact identities, max-threads=1, fast timeout unchanged'
