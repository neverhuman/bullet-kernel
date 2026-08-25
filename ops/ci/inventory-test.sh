#!/usr/bin/env bash
# Prove that the three nextest filters are non-empty, pairwise disjoint, cover
# the complete inventory, retain the reviewed counts, and enumerate every test
# source that can resolve bullet-gitd.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool cargo-nextest || exit 1
require_tool jq || exit 1
require_tool rg || exit 1

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

list_matches() {
  local output="$1"
  local filter="${2:-}"
  local inventory="$test_root/inventory.json"
  if [[ -n "$filter" ]]; then
    cargo nextest list --locked --workspace --message-format json -E "$filter" >"$inventory"
  else
    cargo nextest list --locked --workspace --message-format json >"$inventory"
  fi
  jq -r '."rust-suites" | to_entries[] | .key as $binary | .value.testcases | to_entries[] | "\($binary)::\(.key)"' \
    "$inventory" | sort -u >"$output"
}

list_ignored_matches() {
  local output="$1"
  local filter="${2:-}"
  local inventory="$test_root/ignored-inventory.json"
  if [[ -n "$filter" ]]; then
    cargo nextest list --locked --workspace --message-format json -E "$filter" >"$inventory"
  else
    cargo nextest list --locked --workspace --message-format json >"$inventory"
  fi
  jq -r '."rust-suites" | to_entries[] | .key as $binary | .value.testcases | to_entries[] | select(.value.ignored == true) | "\($binary)::\(.key)"' \
    "$inventory" | sort -u >"$output"
}

line_count() { awk 'END { print NR + 0 }' "$1"; }
assert_count() {
  local name="$1"
  local path="$2"
  local expected="$3"
  local actual
  actual="$(line_count "$path")"
  if [[ "$actual" -eq 0 || "$actual" -ne "$expected" ]]; then
    refuse TEST_PARTITION_DRIFT "$name contains $actual identities; expected $expected"
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

list_matches "$test_root/all"
list_matches "$test_root/standalone" "$STANDALONE_FILTER"
list_matches "$test_root/contract" "$CONTRACT_FILTER"
list_matches "$test_root/family" "$FAMILY_FILTER"
list_ignored_matches "$test_root/all-ignored"
list_ignored_matches "$test_root/standalone-ignored" "$STANDALONE_FILTER"
comm -23 "$test_root/standalone" "$test_root/standalone-ignored" >"$test_root/standalone-executed"

assert_count all "$test_root/all" "$EXPECTED_TOTAL_TESTS"
assert_count standalone "$test_root/standalone" "$EXPECTED_STANDALONE_TESTS"
assert_count standalone-executed "$test_root/standalone-executed" "$EXPECTED_STANDALONE_EXECUTED_TESTS"
assert_count standalone-ignored "$test_root/standalone-ignored" "$EXPECTED_STANDALONE_IGNORED_TESTS"
assert_count all-ignored "$test_root/all-ignored" "$EXPECTED_STANDALONE_IGNORED_TESTS"
assert_count contract "$test_root/contract" "$EXPECTED_CONTRACT_TESTS"
assert_count family "$test_root/family" "$EXPECTED_FAMILY_TESTS"
assert_digest all "$test_root/all" "$EXPECTED_ALL_IDENTITIES_SHA256"
assert_digest standalone "$test_root/standalone" "$EXPECTED_STANDALONE_IDENTITIES_SHA256"
assert_digest contract "$test_root/contract" "$EXPECTED_CONTRACT_IDENTITIES_SHA256"
assert_digest family "$test_root/family" "$EXPECTED_FAMILY_IDENTITIES_SHA256"

if [[ $((EXPECTED_STANDALONE_TESTS + EXPECTED_CONTRACT_TESTS + EXPECTED_FAMILY_TESTS)) -ne "$EXPECTED_TOTAL_TESTS" ]]; then
  refuse TEST_PARTITION_DECLARATION_INVALID "declared partition counts do not sum to total"
  exit 1
fi

if [[ $((EXPECTED_STANDALONE_EXECUTED_TESTS + EXPECTED_STANDALONE_IGNORED_TESTS)) -ne "$EXPECTED_STANDALONE_TESTS" ]]; then
  refuse TEST_PARTITION_DECLARATION_INVALID "standalone executed and ignored counts do not sum to standalone total"
  exit 1
fi

for pair in 'standalone contract' 'standalone family' 'contract family'; do
  read -r left right <<<"$pair"
  if [[ -n "$(comm -12 "$test_root/$left" "$test_root/$right")" ]]; then
    refuse TEST_PARTITION_OVERLAP "$left and $right select the same test identity"
    exit 1
  fi
done

sort -u "$test_root/standalone" "$test_root/contract" "$test_root/family" >"$test_root/union"
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


printf '%s\n' "${STANDALONE_IGNORED_TEST_IDENTITIES[@]}" | sort -u >"$test_root/expected-ignored"
for actual_ignored in "$test_root/all-ignored" "$test_root/standalone-ignored"; do
  if ! cmp -s "$test_root/expected-ignored" "$actual_ignored"; then
    diff -u "$test_root/expected-ignored" "$actual_ignored" >&2 || true
    refuse IGNORED_TEST_INVENTORY_DRIFT "ignored test identities changed"
    exit 1
  fi
done


for standalone_lane in ops/ci/fast.sh ops/ci/contract.sh ops/ci/coverage.sh; do
  rg -Fxq 'deny_sibling_gitd' "$standalone_lane" \
    || { refuse SIBLING_GITD_GUARD_MISSING "$standalone_lane"; exit 1; }
done
deny_sibling_gitd
[[ "$BULLET_GITD_BIN" == /* && ! -e "$BULLET_GITD_BIN" && ! -L "$BULLET_GITD_BIN" ]] \
  || { refuse SIBLING_GITD_GUARD_INVALID "$BULLET_GITD_BIN"; exit 1; }

search_roots=()
for candidate in apps/*/tests crates/*/tests tests; do
  [[ -d "$candidate" ]] && search_roots+=("$candidate")
done
rg -l 'require_gitd\(\)|BULLET_GITD_BIN|bullet-git/target/(debug|release)/bullet-gitd' \
  "${search_roots[@]}" | sort -u >"$test_root/actual-family-sources"
printf '%s\n' "${FAMILY_TEST_SOURCES[@]}" | sort -u >"$test_root/expected-family-sources"
if ! cmp -s "$test_root/expected-family-sources" "$test_root/actual-family-sources"; then
  diff -u "$test_root/expected-family-sources" "$test_root/actual-family-sources" >&2 || true
  refuse FAMILY_SOURCE_INVENTORY_DRIFT "bullet-gitd-aware test sources changed"
  exit 1
fi

log "inventory passed: 545 total = 502 standalone (499 executed + 3 ignored) + 34 contract + 9 family"
