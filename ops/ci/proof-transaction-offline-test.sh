#!/usr/bin/env bash
# Hostile CLI admission tests for the connected offline component wrapper.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

mkdir "$test_root/bin"
b3sum_bin="$(command -v b3sum)"
ln -s -- "$b3sum_bin" "$test_root/bin/b3sum"
# The generated shim expands the marker when it runs, not while it is written.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  ': >"${BULLET_PROOF_TEST_CARGO_MARKER:?}"' \
  'exit 91' \
  >"$test_root/bin/cargo"
chmod 0700 "$test_root/bin/cargo"

printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$test_root/gitd"
chmod 0700 "$test_root/gitd"
gitd_digest="$(sha256_file "$test_root/gitd")"

assert_refusal() {
  local name="$1"
  local reason="$2"
  local proof_dir="$test_root/proof-$name"
  shift 2

  rm -f -- "$test_root/cargo-called" "$test_root/$name.stdout" "$test_root/$name.stderr"
  set +e
  env -u CARGO_TARGET_DIR -u BULLET_CI_CARGO_TARGET_DIR \
    -u BULLET_CI_CARGO_TARGET_ID -u BULLET_GITD_BIN -u BULLET_GITD_SHA256 \
    -u BULLET_OFFLINE_PROOF_DIR \
    PATH="$test_root/bin:/usr/bin:/bin" \
    BULLET_PROOF_TEST_CARGO_MARKER="$test_root/cargo-called" \
    BULLET_OFFLINE_PROOF_DIR="$proof_dir" \
    "$@" /usr/bin/bash ops/ci/proof-transaction-offline.sh \
    >"$test_root/$name.stdout" 2>"$test_root/$name.stderr"
  local code=$?
  set -e

  [[ "$code" -eq 1 ]] \
    || { refuse OFFLINE_PROOF_HOSTILE_EXIT_INVALID "$name returned $code"; exit 1; }
  rg -Fq "[ci] $reason:" "$test_root/$name.stderr" \
    || { cat "$test_root/$name.stderr" >&2; refuse OFFLINE_PROOF_HOSTILE_REASON_INVALID "$name"; exit 1; }
  [[ ! -e "$test_root/cargo-called" ]] \
    || { refuse OFFLINE_PROOF_PREBUILD_GUARD_FAILED "$name invoked Cargo"; exit 1; }
  [[ ! -e "$proof_dir" && ! -L "$proof_dir" ]] \
    || { refuse OFFLINE_PROOF_PREBUILD_MUTATION "$name created its output subject"; exit 1; }
}

assert_refusal missing-gitd BULLET_GITD_BIN_REQUIRED
assert_refusal nonexistent-gitd BULLET_GITD_BIN_NOT_EXECUTABLE \
  BULLET_GITD_BIN="$test_root/absent-gitd"
assert_refusal relative-gitd BULLET_GITD_BIN_NOT_ABSOLUTE \
  BULLET_GITD_BIN=relative/gitd
assert_refusal missing-digest BULLET_GITD_SHA256_REQUIRED \
  BULLET_GITD_BIN="$test_root/gitd"
assert_refusal malformed-digest BULLET_GITD_SHA256_REQUIRED \
  BULLET_GITD_BIN="$test_root/gitd" BULLET_GITD_SHA256=ABCDEF
assert_refusal mismatched-digest BULLET_GITD_DIGEST_MISMATCH \
  BULLET_GITD_BIN="$test_root/gitd" \
  BULLET_GITD_SHA256=0000000000000000000000000000000000000000000000000000000000000000
assert_refusal cargo-target CARGO_TARGET_DIR_UNSUPPORTED \
  CARGO_TARGET_DIR="$test_root/foreign-target" \
  BULLET_GITD_BIN="$test_root/gitd" BULLET_GITD_SHA256="$gitd_digest"

preexisting="$test_root/preexisting"
mkdir "$preexisting"
printf 'do-not-touch\n' >"$preexisting/sentinel"
preexisting_identity="$(stat -Lc '%d:%i:%u:%a:%F' -- "$preexisting")"
set +e
env -u CARGO_TARGET_DIR -u BULLET_CI_CARGO_TARGET_DIR \
  -u BULLET_CI_CARGO_TARGET_ID \
  PATH="$test_root/bin:/usr/bin:/bin" \
  BULLET_PROOF_TEST_CARGO_MARKER="$test_root/cargo-called" \
  BULLET_GITD_BIN="$test_root/gitd" BULLET_GITD_SHA256="$gitd_digest" \
  BULLET_OFFLINE_PROOF_DIR="$preexisting" \
  /usr/bin/bash ops/ci/proof-transaction-offline.sh \
  >"$test_root/preexisting.stdout" 2>"$test_root/preexisting.stderr"
preexisting_code=$?
set -e
[[ "$preexisting_code" -eq 1 ]] \
  || { refuse OFFLINE_PROOF_HOSTILE_EXIT_INVALID "pre-existing output returned $preexisting_code"; exit 1; }
rg -Fq '[ci] OFFLINE_COMPONENT_PROOF_DIR_INVALID:' "$test_root/preexisting.stderr" \
  || { cat "$test_root/preexisting.stderr" >&2; refuse OFFLINE_PROOF_HOSTILE_REASON_INVALID preexisting; exit 1; }
[[ ! -e "$test_root/cargo-called" \
  && "$(stat -Lc '%d:%i:%u:%a:%F' -- "$preexisting")" == "$preexisting_identity" \
  && "$(<"$preexisting/sentinel")" == do-not-touch ]] \
  || { refuse OFFLINE_PROOF_PREBUILD_MUTATION "pre-existing output was touched"; exit 1; }

wrapper=ops/ci/proof-transaction-offline.sh
[[ "$(rg -c '^cargo build --offline --locked ' "$wrapper")" -eq 4 ]] \
  || { refuse OFFLINE_PROOF_BUILD_INVENTORY_DRIFT "expected four exact offline locked builds"; exit 1; }
rg -Fxq 'cargo build --offline --locked -p bullet-farmd --bin bullet-farmd' "$wrapper"
rg -Fxq 'cargo build --offline --locked -p bullet-runner --bin bullet-runner' "$wrapper"
rg -Fxq 'cargo build --offline --locked -p bullet --bin transaction_offline' "$wrapper"
rg -Fxq "cargo build --offline --locked -p bullet-verifier --bin bullet-verifier-fixture \\" "$wrapper"
rg -Fxq '  --features fixture-executor' "$wrapper"
for predicate in \
  '.evidence_class == "COMPONENT_PROOF"' \
  '.signing_trust == "UNSIGNED_FIXTURE"' \
  '.transaction_gate_eligible == false' \
  '.independent_evidence_eligible == false' \
  '.command_dispatch.source == "LOCAL_FIXTURE"' \
  '.command_dispatch.transaction_gate_eligible == false' \
  '.command_dispatch.independent_evidence_eligible == false' \
  '.artifact_custody.retained == true' \
  '.artifact_custody.target_oid == .head_oid' \
  '.product_runner_candidate_id == .candidate_id' \
  '.product_runner_outcome == "CANDIDATE_PRESERVED"' \
  '.product_runner_preservation.candidate_id == .candidate_id' \
  '.product_runner_preservation.attempt_id == .attempt_first' \
  '.product_runner_preservation.fence == .fence_first' \
  '.attempt_second != .attempt_first' \
  '.fence_second > 0' \
  '.local_forge.signed_observation.chain_reverified == true' \
  '.local_forge.signed_observation.signed.record.outcome == "MATCHED"' \
  '.effect_candidate_bound == true' \
  '.effect_delivered_oid == .head_oid'; do
  rg -Fq "$predicate" "$wrapper" \
    || { refuse OFFLINE_PROOF_RECEIPT_GUARD_MISSING "$predicate"; exit 1; }
done

log "offline component proof CLI guardrails passed"
