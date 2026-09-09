#!/usr/bin/env bash
# Prove that hosted JUnit is structural only and fails closed on schema drift.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool rg || exit 1
require_tool sed || exit 1
require_tool truncate || exit 1
require_tool awk || exit 1

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
# jankurai:allow HLT-010-SECRET-SPRAWL reason=synthetic JUnit redaction canary expires=2027-08-26
canary='AKIAIOSFODNN7EXAMPLE'
junit_raw_max_bytes=$((16 * 1024 * 1024))

write_junit() {
  local path="$1"
  local suite_name="$2"
  local testcase_attributes="${3:-}"
  printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    "<testsuites name=\"$suite_name\" tests=\"1\" failures=\"0\" errors=\"0\">" \
    '  <testsuite name="suite" tests="1" failures="0" errors="0">' \
    "    <testcase name=\"case\" classname=\"suite\" time=\"0.1\"$testcase_attributes/>" \
    '  </testsuite>' \
    '</testsuites>' >"$path"
  chmod 0600 "$path"
}

prepare_store_fixture() {
  local root="$1"
  mkdir -p "$root/ops/ci" "$root/target/nextest/fast" "$root/.ci-artifacts/junit"
  cp ops/ci/sanitize-junit.sh "$root/ops/ci/sanitize-junit.sh"
  write_junit "$root/target/nextest/fast/junit.xml" repository-store
}

run_fixture_sanitize() {
  local root="$1"
  local output="$2"
  set +e
  (
    CI_CARGO_TARGET_ADMITTED=false
    REPO_ROOT="$root"
    CARGO_TARGET_DIR="$root/cargo-target"
    sanitize_junit fast fast
  ) >"$output" 2>&1
  LAST_STATUS=$?
  set -e
}

expect_fixture_refusal() {
  local label="$1"
  local reason="$2"
  local root="$3"
  local output="$test_root/$label.output"
  run_fixture_sanitize "$root" "$output"
  if [[ "$LAST_STATUS" -eq 0 ]] || ! rg -Fq "$reason" "$output"; then
    refuse JUNIT_HOSTILE_ACCEPTED "$label status=$LAST_STATUS expected=$reason"
    return 1
  fi
}

assert_nextest_store_contract() {
  local source="$1"
  rg -Fqx '  source_path="$REPO_ROOT/target/nextest/$profile/junit.xml"' "$source" \
    && rg -Fq '  rm -f -- "$REPO_ROOT/target/nextest/$profile/junit.xml"' "$source" \
    && [[ "$(rg -c '^[[:space:]]*source_path=' "$source")" -eq 1 ]] \
    && ! rg -q 'cargo_target_root' "$source"
}

assert_nextest_store_contract ops/ci/lib.sh \
  || { refuse JUNIT_STORE_CONTRACT_DRIFT "raw report custody left nextest's repository store"; exit 1; }
dollar='$'
repository_store_literal="${dollar}REPO_ROOT/target/nextest/"
cargo_target_literal="${dollar}{CARGO_TARGET_DIR}/nextest/"
sed "s#$repository_store_literal#$cargo_target_literal#g" \
  ops/ci/lib.sh >"$test_root/cargo-target-substitution.sh"
if assert_nextest_store_contract "$test_root/cargo-target-substitution.sh"; then
  refuse JUNIT_STORE_HOSTILE_FAILED "Cargo target substitution was accepted"
  exit 1
fi
source_assignment="  source_path=\"${dollar}REPO_ROOT/target/nextest/${dollar}profile/junit.xml\""
effective_assignment="  source_path=\"${dollar}{CARGO_TARGET_DIR}/nextest/${dollar}profile/junit.xml\""
awk -v needle="$source_assignment" -v extra="$effective_assignment" \
  '{ print; if ($0 == needle) print extra }' ops/ci/lib.sh >"$test_root/effective-reassignment.sh"
if assert_nextest_store_contract "$test_root/effective-reassignment.sh"; then
  refuse JUNIT_STORE_HOSTILE_FAILED "effective source-path reassignment was accepted"
  exit 1
fi

behavior_root="$test_root/behavior"
prepare_store_fixture "$behavior_root"
run_fixture_sanitize "$behavior_root" "$test_root/behavior.output"
[[ "$LAST_STATUS" -eq 0 \
  && -f "$behavior_root/.ci-artifacts/junit/fast.xml" \
  && ! -L "$behavior_root/.ci-artifacts/junit/fast.xml" ]] \
  || {
    sed -n '1,5p' "$test_root/behavior.output" >&2
    refuse JUNIT_STORE_BEHAVIOR_FAILED "repository-store fixture refused"
    exit 1
  }
rg -Fq 'name="repository-store"' "$behavior_root/.ci-artifacts/junit/fast.xml" \
  || { refuse JUNIT_STORE_BEHAVIOR_FAILED "effective source was not the repository store"; exit 1; }

target_link_root="$test_root/target-link"
mkdir -p "$target_link_root/ops/ci" "$target_link_root/.ci-artifacts/junit" \
  "$test_root/outside-target/nextest/fast"
cp ops/ci/sanitize-junit.sh "$target_link_root/ops/ci/sanitize-junit.sh"
write_junit "$test_root/outside-target/nextest/fast/junit.xml" outside-target
ln -s "$test_root/outside-target" "$target_link_root/target"
expect_fixture_refusal target-parent-symlink JUNIT_STORE_CUSTODY_INVALID "$target_link_root"

publication_link_root="$test_root/publication-link"
mkdir -p "$publication_link_root/ops/ci" "$publication_link_root/target/nextest/fast" \
  "$publication_link_root/.ci-artifacts" "$test_root/outside-publication"
cp ops/ci/sanitize-junit.sh "$publication_link_root/ops/ci/sanitize-junit.sh"
write_junit "$publication_link_root/target/nextest/fast/junit.xml" publication-link
ln -s "$test_root/outside-publication" "$publication_link_root/.ci-artifacts/junit"
expect_fixture_refusal publication-parent-symlink JUNIT_STORE_CUSTODY_INVALID "$publication_link_root"

publication_leaf_root="$test_root/publication-leaf-link"
prepare_store_fixture "$publication_leaf_root"
mkdir "$test_root/outside-publication-leaf"
ln -s "$test_root/outside-publication-leaf" \
  "$publication_leaf_root/.ci-artifacts/junit/fast.xml"
expect_fixture_refusal publication-leaf-symlink JUNIT_STORE_CUSTODY_INVALID \
  "$publication_leaf_root"
if [[ -n "$(find "$test_root/outside-publication-leaf" -mindepth 1 -print -quit)" ]]; then
  refuse JUNIT_PUBLICATION_ESCAPE "publication leaf symlink mutated an outside directory"
  exit 1
fi
rg -Fq 'mv -fT -- "$temporary" "$destination"' ops/ci/sanitize-junit.sh \
  || { refuse JUNIT_ATOMIC_PUBLICATION_DRIFT "sanitizer move can follow a directory symlink"; exit 1; }

raw_link_root="$test_root/raw-link"
prepare_store_fixture "$raw_link_root"
mv "$raw_link_root/target/nextest/fast/junit.xml" "$test_root/outside-raw.xml"
ln -s "$test_root/outside-raw.xml" "$raw_link_root/target/nextest/fast/junit.xml"
expect_fixture_refusal raw-symlink JUNIT_RAW_SUBJECT_INVALID "$raw_link_root"

hardlink_root="$test_root/raw-hardlink"
prepare_store_fixture "$hardlink_root"
ln "$hardlink_root/target/nextest/fast/junit.xml" "$hardlink_root/target/nextest/fast/peer.xml"
expect_fixture_refusal raw-hardlink JUNIT_RAW_SUBJECT_INVALID "$hardlink_root"

mode_root="$test_root/raw-mode"
prepare_store_fixture "$mode_root"
chmod 0644 "$mode_root/target/nextest/fast/junit.xml"
expect_fixture_refusal raw-mode JUNIT_RAW_SUBJECT_INVALID "$mode_root"

mutation_root="$test_root/raw-mutation"
prepare_store_fixture "$mutation_root"
mkdir -p "$mutation_root/bin"
write_junit "$mutation_root/replacement.xml" mutated-store
real_sha256sum="$(command -v sha256sum)" \
  || { refuse JUNIT_MUTATION_FIXTURE_INVALID "sha256sum is unavailable"; exit 1; }
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  "\"${dollar}JUNIT_REAL_SHA256SUM\" \"${dollar}@\"" \
  "if [[ ! -e \"${dollar}JUNIT_MUTATION_MARKER\" ]]; then" \
  "  cp \"${dollar}JUNIT_MUTATION_REPLACEMENT\" \"${dollar}JUNIT_MUTATION_SOURCE\"" \
  "  : >\"${dollar}JUNIT_MUTATION_MARKER\"" \
  'fi' >"$mutation_root/bin/sha256sum"
chmod 0700 "$mutation_root/bin/sha256sum"
set +e
(
  CI_CARGO_TARGET_ADMITTED=false
  REPO_ROOT="$mutation_root"
  CARGO_TARGET_DIR="$mutation_root/cargo-target"
  PATH="$mutation_root/bin:$PATH"
  JUNIT_REAL_SHA256SUM="$real_sha256sum"
  JUNIT_MUTATION_MARKER="$mutation_root/mutated"
  JUNIT_MUTATION_REPLACEMENT="$mutation_root/replacement.xml"
  JUNIT_MUTATION_SOURCE="$mutation_root/target/nextest/fast/junit.xml"
  export PATH JUNIT_REAL_SHA256SUM JUNIT_MUTATION_MARKER
  export JUNIT_MUTATION_REPLACEMENT JUNIT_MUTATION_SOURCE
  sanitize_junit fast fast
) >"$test_root/raw-mutation.output" 2>&1
mutation_status=$?
set -e
[[ "$mutation_status" -ne 0 \
  && -f "$mutation_root/mutated" \
  && "$(<"$mutation_root/target/nextest/fast/junit.xml")" == *mutated-store* \
  && "$(<"$test_root/raw-mutation.output")" == *JUNIT_RAW_SUBJECT_INVALID* ]] \
  || { refuse JUNIT_MUTATION_HOSTILE_ACCEPTED "source changed during bounded snapshot"; exit 1; }

oversize_root="$test_root/raw-oversize"
prepare_store_fixture "$oversize_root"
truncate -s "$((junit_raw_max_bytes + 1))" "$oversize_root/target/nextest/fast/junit.xml"
expect_fixture_refusal raw-oversize JUNIT_RAW_TOO_LARGE "$oversize_root"

for outcome_attribute in status result failure error skipped; do
  outcome_root="$test_root/outcome-$outcome_attribute"
  prepare_store_fixture "$outcome_root"
  write_junit "$outcome_root/target/nextest/fast/junit.xml" outcome \
    " $outcome_attribute=\"failed\""
  expect_fixture_refusal "outcome-$outcome_attribute" JUNIT_RAW_SCHEMA_INVALID "$outcome_root"
done

for outcome_attribute in Status STATUS x:status; do
  outcome_label="${outcome_attribute//[^A-Za-z0-9]/-}"
  outcome_root="$test_root/outcome-alias-$outcome_label"
  prepare_store_fixture "$outcome_root"
  write_junit "$outcome_root/target/nextest/fast/junit.xml" outcome \
    " $outcome_attribute=\"failed\""
  expect_fixture_refusal "outcome-alias-$outcome_label" JUNIT_RAW_SCHEMA_INVALID "$outcome_root"
done

for invalid_reference in '&#0;' '&#xD800;' '&#x110000;'; do
  reference_root="$test_root/invalid-reference-${invalid_reference//[^A-Za-z0-9]/-}"
  prepare_store_fixture "$reference_root"
  write_junit "$reference_root/target/nextest/fast/junit.xml" "$invalid_reference"
  expect_fixture_refusal "invalid-reference-${invalid_reference//[^A-Za-z0-9]/-}" \
    JUNIT_RAW_SCHEMA_INVALID "$reference_root"
done

for invalid_reference in '&#0' '&#xD800' '&#x110000' '&#xZZ;' '&#;' '&unknown;' '&amp'; do
  reference_label="${invalid_reference//[^A-Za-z0-9]/-}"
  reference_root="$test_root/invalid-reference-$reference_label"
  prepare_store_fixture "$reference_root"
  write_junit "$reference_root/target/nextest/fast/junit.xml" "$invalid_reference"
  expect_fixture_refusal "invalid-reference-$reference_label" \
    JUNIT_RAW_SCHEMA_INVALID "$reference_root"
done

reference_body_root="$test_root/invalid-reference-body"
prepare_store_fixture "$reference_body_root"
printf '%s\n' \
  '<testsuites><testsuite><testcase>' \
  '<failure>&#0;</failure>' \
  '</testcase></testsuite></testsuites>' \
  >"$reference_body_root/target/nextest/fast/junit.xml"
chmod 0600 "$reference_body_root/target/nextest/fast/junit.xml"
expect_fixture_refusal invalid-reference-body JUNIT_RAW_SCHEMA_INVALID "$reference_body_root"

valid_reference_root="$test_root/valid-references"
prepare_store_fixture "$valid_reference_root"
write_junit "$valid_reference_root/target/nextest/fast/junit.xml" \
  '&#9;&#10;&#13;&#x20;&#xD7FF;&#xE000;&#xFFFD;&#x10000;&#x10FFFF;'
run_fixture_sanitize "$valid_reference_root" "$test_root/valid-references.output"
[[ "$LAST_STATUS" -eq 0 && -s "$valid_reference_root/.ci-artifacts/junit/fast.xml" ]] || {
  refuse JUNIT_REFERENCE_RANGE_FAILED "valid XML 1.0 numeric references were refused"
  exit 1
}

valid_named_reference_root="$test_root/valid-named-references"
prepare_store_fixture "$valid_named_reference_root"
write_junit "$valid_named_reference_root/target/nextest/fast/junit.xml" \
  '&amp;&lt;&gt;&quot;&apos;'
run_fixture_sanitize "$valid_named_reference_root" "$test_root/valid-named-references.output"
[[ "$LAST_STATUS" -eq 0 && -s "$valid_named_reference_root/.ci-artifacts/junit/fast.xml" ]] || {
  refuse JUNIT_REFERENCE_RANGE_FAILED "valid XML named references were refused"
  exit 1
}

printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<testsuites name="nextest-run" tests="1" failures="1" errors="0" timestamp="host" uuid="host">' \
  '  <testsuite name="suite" tests="1" failures="1" errors="0">' \
  '    <testcase name="fails" classname="suite" time="0.1" timestamp="host">' \
  "      <failure message=\"$canary\" type=\"assertion\">$canary</failure>" \
  "      <system-out>$canary</system-out>" \
  "      <system-err>$canary</system-err>" \
  '    </testcase>' \
  '  </testsuite>' \
  '</testsuites>' >"$test_root/raw.xml"

bash ops/ci/sanitize-junit.sh "$test_root/raw.xml" "$test_root/sanitized.xml"
if rg -q "$canary|system-out|system-err|timestamp=|uuid=|message=|type=" "$test_root/sanitized.xml"; then
  refuse JUNIT_REDACTION_FAILED "captured output or host metadata survived"
  exit 1
fi
rg -Fqx '<testsuites name="nextest-run" tests="1" failures="1" errors="0">' "$test_root/sanitized.xml" \
  || { refuse JUNIT_ROOT_GUARD_FAILED "sanitized root attributes drifted"; exit 1; }
[[ "$(rg -Fxc '            <failure>' "$test_root/sanitized.xml")" -eq 1 ]] \
  || { refuse JUNIT_FAILURE_GUARD_FAILED "structural failure element was not retained exactly once"; exit 1; }
bash ops/ci/sanitize-junit.sh "$test_root/sanitized.xml" "$test_root/resanitized.xml"
cmp -s "$test_root/sanitized.xml" "$test_root/resanitized.xml" \
  || { refuse JUNIT_IDEMPOTENCE_FAILED "sanitized output is not canonical"; exit 1; }

printf '%s\n' '<testsuites><credential>secret</credential></testsuites>' >"$test_root/unknown.xml"
if bash ops/ci/sanitize-junit.sh "$test_root/unknown.xml" "$test_root/rejected.xml" >/dev/null 2>&1; then
  refuse JUNIT_SCHEMA_GUARD_FAILED "unknown output-bearing element was accepted"
  exit 1
fi
printf 'prior-output\n' >"$test_root/rejected.xml"
if bash ops/ci/sanitize-junit.sh "$test_root/missing.xml" "$test_root/rejected.xml" >/dev/null 2>&1; then
  refuse JUNIT_MISSING_GUARD_FAILED "missing report was accepted"
  exit 1
fi
[[ "$(<"$test_root/rejected.xml")" == prior-output ]] \
  || { refuse JUNIT_ATOMIC_FAILURE_GUARD_FAILED "failed sanitation replaced prior output"; exit 1; }

printf '%s\n' '<!DOCTYPE testsuites [<!ENTITY leak SYSTEM "file:///etc/passwd">]><testsuites/>' \
  >"$test_root/doctype.xml"
if bash ops/ci/sanitize-junit.sh "$test_root/doctype.xml" "$test_root/rejected.xml" >/dev/null 2>&1; then
  refuse JUNIT_DECLARATION_GUARD_FAILED "DOCTYPE input was accepted"
  exit 1
fi

log "JUnit structural sanitizer and secret canary passed"
