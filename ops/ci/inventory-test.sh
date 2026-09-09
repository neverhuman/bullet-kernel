#!/usr/bin/env bash
# Prove that the four nextest filters are non-empty, pairwise disjoint, cover
# the complete inventory, retain reviewed identity/member subjects, reject a
# count-neutral identity substitution, and enumerate every test source that
# can resolve bullet-gitd.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool cargo-nextest || exit 1
require_tool jq || exit 1
require_tool rg || exit 1
if [[ "${NEXTEST_FEATURES[*]}" != '--features bullet-verifier/fixture-executor' ]]; then
  refuse VERIFIER_FIXTURE_FEATURE_INVALID "nextest must enumerate and run the explicit fixture executor"
  exit 1
fi

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

list_matches() {
  local output="$1"
  local filter="${2:-}"
  local inventory
  inventory="$test_root/$(basename "$output")-inventory.json"
  if [[ -n "$filter" ]]; then
    cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all --message-format json -E "$filter" >"$inventory"
  else
    cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all --message-format json >"$inventory"
  fi
  jq -r '."rust-suites" | to_entries[] | .key as $binary | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($binary)::\(.key)"' \
    "$inventory" | sort -u >"$output"
}

list_ignored_matches() {
  local output="$1"
  local filter="${2:-}"
  local inventory="$test_root/ignored-inventory.json"
  if [[ -n "$filter" ]]; then
    cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all --message-format json -E "$filter" >"$inventory"
  else
    cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all --message-format json >"$inventory"
  fi
  jq -r '."rust-suites" | to_entries[] | .key as $binary | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches" and .value.ignored == true) | "\($binary)::\(.key)"' \
    "$inventory" | sort -u >"$output"
}

line_count() { awk 'END { print NR + 0 }' "$1"; }
validate_count() {
  local name="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" -eq 0 || "$actual" -ne "$expected" ]]; then
    refuse TEST_PARTITION_DRIFT "$name contains $actual identities; expected $expected"
    return 1
  fi
}

assert_count() {
  local name="$1"
  local path="$2"
  local expected="$3"
  validate_count "$name" "$(line_count "$path")" "$expected" || exit 1
}

expect_count_rejection() {
  local name="$1"
  local actual="$2"
  local expected="$3"
  local output code
  set +e
  output="$(validate_count "$name" "$actual" "$expected" 2>&1)"
  code=$?
  set -e
  if [[ "$code" -ne 1 || "$output" != *TEST_PARTITION_DRIFT* ]]; then
    refuse TEST_PARTITION_HOSTILE_FAILED "$name code=$code output=$output"
    exit 1
  fi
}

assert_empty() {
  local name="$1"
  local path="$2"
  if [[ -s "$path" ]]; then
    refuse TEST_PARTITION_DRIFT "$name must contain zero identities"
    exit 1
  fi
}

assert_digest() {
  local name="$1"
  local path="$2"
  local expected="$3"
  local actual
  actual="$(sha256_file "$path")" || exit 1
  if [[ "$actual" != "$expected" ]]; then
    refuse TEST_IDENTITY_DIGEST_DRIFT "$name identity digest is $actual; expected $expected"
    exit 1
  fi
}

expect_digest_rejection() {
  local source="$1"
  local expected="$2"
  local mutated="$test_root/count-neutral-identity-substitution"
  local output code
  awk 'NR == 1 { $0 = "synthetic::count_neutral_identity_substitution" } { print }' \
    "$source" >"$mutated"
  if [[ "$(line_count "$source")" -ne "$(line_count "$mutated")" ]]; then
    refuse TEST_PARTITION_HOSTILE_FAILED "identity substitution changed the count"
    exit 1
  fi
  set +e
  output="$(assert_digest count-neutral-substitution "$mutated" "$expected" 2>&1)"
  code=$?
  set -e
  if [[ "$code" -ne 1 || "$output" != *TEST_IDENTITY_DIGEST_DRIFT* ]]; then
    refuse TEST_PARTITION_HOSTILE_FAILED "identity substitution code=$code output=$output"
    exit 1
  fi
}

expect_count_rejection inventory-zero 0 "$EXPECTED_TOTAL_TESTS"
expect_count_rejection inventory-minus-one "$((EXPECTED_TOTAL_TESTS - 1))" "$EXPECTED_TOTAL_TESTS"
expect_count_rejection inventory-plus-one "$((EXPECTED_TOTAL_TESTS + 1))" "$EXPECTED_TOTAL_TESTS"

list_matches "$test_root/all"
list_matches "$test_root/standalone" "$STANDALONE_FILTER"
list_matches "$test_root/egress" "$EGRESS_FILTER"
list_matches "$test_root/contract" "$CONTRACT_FILTER"
list_matches "$test_root/family" "$FAMILY_FILTER"
list_ignored_matches "$test_root/all-ignored"
list_ignored_matches "$test_root/standalone-ignored" "$STANDALONE_FILTER"
list_ignored_matches "$test_root/egress-ignored" "$EGRESS_FILTER"

cargo metadata --locked --no-deps --format-version 1 >"$test_root/metadata.json"
jq -r '.workspace_members[] as $id | .packages[] | select(.id == $id) | .name' \
  "$test_root/metadata.json" | sort -u >"$test_root/workspace-members"
jq -r '."rust-suites" | to_entries[] | .value["package-name"]' \
  "$test_root/all-inventory.json" | sort -u >"$test_root/nextest-packages"

assert_count all "$test_root/all" "$EXPECTED_TOTAL_TESTS"
assert_count standalone "$test_root/standalone" "$EXPECTED_STANDALONE_TESTS"
assert_empty standalone-ignored "$test_root/standalone-ignored"
assert_count egress "$test_root/egress" "$EXPECTED_EGRESS_TESTS"
assert_count egress-ignored "$test_root/egress-ignored" "$EXPECTED_EGRESS_TESTS"
assert_count all-ignored "$test_root/all-ignored" "$EXPECTED_EGRESS_TESTS"
assert_count contract "$test_root/contract" "$EXPECTED_CONTRACT_TESTS"
assert_count family "$test_root/family" "$EXPECTED_FAMILY_TESTS"
assert_digest all "$test_root/all" "$EXPECTED_ALL_IDENTITIES_SHA256"
assert_digest standalone "$test_root/standalone" "$EXPECTED_STANDALONE_IDENTITIES_SHA256"
assert_digest egress "$test_root/egress" "$EXPECTED_EGRESS_IDENTITIES_SHA256"
assert_digest contract "$test_root/contract" "$EXPECTED_CONTRACT_IDENTITIES_SHA256"
assert_digest family "$test_root/family" "$EXPECTED_FAMILY_IDENTITIES_SHA256"
assert_count workspace-members "$test_root/workspace-members" "$EXPECTED_WORKSPACE_MEMBERS"
assert_digest workspace-members "$test_root/workspace-members" "$EXPECTED_WORKSPACE_MEMBERS_SHA256"
if ! cmp -s "$test_root/workspace-members" "$test_root/nextest-packages"; then
  diff -u "$test_root/workspace-members" "$test_root/nextest-packages" >&2 || true
  refuse TEST_WORKSPACE_MEMBER_OMITTED "nextest inventory does not contain every workspace member"
  exit 1
fi
expect_digest_rejection "$test_root/all" "$EXPECTED_ALL_IDENTITIES_SHA256"

if [[ $((EXPECTED_STANDALONE_TESTS + EXPECTED_EGRESS_TESTS + EXPECTED_CONTRACT_TESTS + EXPECTED_FAMILY_TESTS)) -ne "$EXPECTED_TOTAL_TESTS" ]]; then
  refuse TEST_PARTITION_DECLARATION_INVALID "declared partition counts do not sum to total"
  exit 1
fi

for pair in \
  'standalone egress' \
  'standalone contract' \
  'standalone family' \
  'egress contract' \
  'egress family' \
  'contract family'; do
  read -r left right <<<"$pair"
  if [[ -n "$(comm -12 "$test_root/$left" "$test_root/$right")" ]]; then
    refuse TEST_PARTITION_OVERLAP "$left and $right select the same test identity"
    exit 1
  fi
done

sort -u \
  "$test_root/standalone" \
  "$test_root/egress" \
  "$test_root/contract" \
  "$test_root/family" >"$test_root/union"
if ! cmp -s "$test_root/all" "$test_root/union"; then
  diff -u "$test_root/all" "$test_root/union" >&2 || true
  refuse TEST_PARTITION_GAP "partition union differs from the complete nextest inventory"
  exit 1
fi

printf '%s\n' "${FAMILY_TEST_IDENTITIES[@]}" | sort -u >"$test_root/expected-family"
if ! cmp -s "$test_root/expected-family" "$test_root/family"; then
  diff -u "$test_root/expected-family" "$test_root/family" >&2 || true
  refuse FAMILY_TEST_INVENTORY_DRIFT "family test identities changed"
  exit 1
fi

printf '%s\n' "${EGRESS_TEST_IDENTITIES[@]}" | sort -u >"$test_root/expected-egress"
for actual_egress in "$test_root/egress" "$test_root/egress-ignored" "$test_root/all-ignored"; do
  if ! cmp -s "$test_root/expected-egress" "$actual_egress"; then
    diff -u "$test_root/expected-egress" "$actual_egress" >&2 || true
    refuse EGRESS_TEST_INVENTORY_DRIFT "egress or ignored test identities changed"
    exit 1
  fi
done

rg -Fxq 'selected="$(partition_count "$EGRESS_FILTER")"' ops/ci/egress.sh \
  || { refuse EGRESS_PARTITION_COUNT_GUARD_MISSING ops/ci/egress.sh; exit 1; }
rg -Fxq 'cargo nextest run --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all --no-tests fail -E "$EGRESS_FILTER"' \
  ops/ci/egress.sh \
  || { refuse EGRESS_EXECUTION_POLICY_MISSING ops/ci/egress.sh; exit 1; }
rg -Fxq '  cargo nextest run --locked --workspace "${NEXTEST_FEATURES[@]}" --profile "$profile" -E "$filter"' \
  ops/ci/lib.sh \
  || { refuse VERIFIER_FIXTURE_FEATURE_MISSING ops/ci/lib.sh; exit 1; }
rg -Fq 'cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}"' ops/ci/lib.sh \
  || { refuse VERIFIER_FIXTURE_FEATURE_MISSING ops/ci/lib.sh; exit 1; }
[[ "$(rg -c '^[[:space:]]+cargo nextest list .*NEXTEST_FEATURES' ops/ci/inventory-test.sh)" -eq 4 ]] \
  || { refuse VERIFIER_FIXTURE_FEATURE_MISSING ops/ci/inventory-test.sh; exit 1; }
rg -Fq 'cargo llvm-cov nextest --locked --workspace "${NEXTEST_FEATURES[@]}" --profile coverage' \
  ops/ci/coverage.sh \
  || { refuse VERIFIER_FIXTURE_FEATURE_MISSING ops/ci/coverage.sh; exit 1; }
mapfile -t ignored_runners < <(
  rg -l --glob '*.sh' --glob '!inventory-test.sh' -- 'cargo nextest run .*--run-ignored' \
    ops/ci scripts | sort -u
)
if [[ "${#ignored_runners[@]}" -ne 1 ]]; then
  refuse EGRESS_RUNNER_DRIFT "ignored tests must have exactly one runner; found ${#ignored_runners[@]}"
  exit 1
fi
if [[ "${ignored_runners[0]}" != ops/ci/egress.sh ]]; then
  refuse EGRESS_RUNNER_DRIFT "ignored tests must run only through ops/ci/egress.sh"
  exit 1
fi
rg -Fxq 'bash ops/ci/inventory-test.sh' ops/ci/lint.sh \
  || { refuse INVENTORY_REQUIRED_ROUTING_MISSING ops/ci/lint.sh; exit 1; }
rg -Fxq 'bash ops/ci/lint.sh' ops/ci/required.sh \
  || { refuse INVENTORY_REQUIRED_ROUTING_MISSING ops/ci/required.sh; exit 1; }
rg -Fq 'bash scripts/ci-local.sh lint' .github/workflows/ci.yml \
  || { refuse INVENTORY_HOSTED_ROUTING_MISSING .github/workflows/ci.yml; exit 1; }


for standalone_lane in ops/ci/fast.sh ops/ci/contract.sh ops/ci/coverage.sh; do
  rg -Fxq 'deny_sibling_gitd' "$standalone_lane" \
    || { refuse SIBLING_GITD_GUARD_MISSING "$standalone_lane"; exit 1; }
done
deny_sibling_gitd
[[ -z "${BULLET_GITD_BIN+x}" && -z "${BULLET_GITD_SHA256+x}" ]] \
  || { refuse SIBLING_GITD_GUARD_INVALID "standalone lanes must leave daemon admission unprovisioned"; exit 1; }

family_wrapper="$(<ops/ci/family.sh)"
[[ "$family_wrapper" == *'BULLET_GITD_SHA256_REQUIRED'* \
  && "$(grep -Fc 'sha256_file' ops/ci/family.sh)" -eq 2 \
  && "$family_wrapper" == *'export BULLET_GITD_SHA256'* ]] \
  || { refuse FAMILY_DAEMON_DIGEST_GUARD_MISSING ops/ci/family.sh; exit 1; }

gitd_admission="$(<crates/runner/src/gitd/binary.rs)"
for required in 'GITD_BINARY_UNPROVISIONED' 'BULLET_GITD_SHA256' 'OFlags::NOFOLLOW' \
  'MemfdFlags::ALLOW_SEALING' 'SealFlags::WRITE' 'native ELF64 little-endian' '/proc/self/fd/' \
  'sha256_and_count(&mut sealed_file)' \
  'invalid_subjects_never_execute_canary' 'sealed_image_survives_same_inode_overwrite'; do
  [[ "$gitd_admission" == *"$required"* ]] \
    || { refuse PRODUCT_DAEMON_ADMISSION_GUARD_MISSING "$required"; exit 1; }
done

search_roots=()
for candidate in apps/*/tests crates/*/tests tests; do
  [[ -d "$candidate" ]] && search_roots+=("$candidate")
done
rg -l 'require_gitd\(\)|gitd_binary\(\)|BULLET_GITD_BIN|bullet-git/target/(debug|release)/bullet-gitd' \
  "${search_roots[@]}" | sort -u >"$test_root/actual-family-sources"
printf '%s\n' "${FAMILY_TEST_SOURCES[@]}" | sort -u >"$test_root/expected-family-sources"
if ! cmp -s "$test_root/expected-family-sources" "$test_root/actual-family-sources"; then
  diff -u "$test_root/expected-family-sources" "$test_root/actual-family-sources" >&2 || true
  refuse FAMILY_SOURCE_INVENTORY_DRIFT "bullet-gitd-aware test sources changed"
  exit 1
fi

log "inventory passed: ${EXPECTED_TOTAL_TESTS} total = ${EXPECTED_STANDALONE_TESTS} standalone + ${EXPECTED_EGRESS_TESTS} egress + ${EXPECTED_CONTRACT_TESTS} contract + ${EXPECTED_FAMILY_TESTS} family; fast has zero ignored tests"
