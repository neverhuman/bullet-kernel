#!/usr/bin/env bash
# Pre-build refusal and structural tests for proof-synthetic-dogfood.sh.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d /tmp/bullet-synthetic-dogfood-test.XXXXXXXX)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
mkdir -m 0700 -- "$test_root/bin"
# The marker expands only when the generated guard is executed.
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' ': >"${DOGFOOD_CARGO_MARKER:?}"' 'exit 91' \
  >"$test_root/bin/cargo"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$test_root/bin/b3sum"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$test_root/gitd"
chmod 0700 "$test_root/bin/b3sum" "$test_root/bin/cargo" "$test_root/gitd"
gitd_digest="$(sha256_file "$test_root/gitd")"

assert_refusal() {
  local label="$1" reason="$2"
  shift 2
  rm -f -- "$test_root/cargo-called" "$test_root/stderr"
  set +e
  env -i PATH="$test_root/bin:/usr/bin:/bin" DOGFOOD_CARGO_MARKER="$test_root/cargo-called" \
    "$@" /usr/bin/bash ops/ci/proof-synthetic-dogfood.sh \
    >"$test_root/stdout" 2>"$test_root/stderr"
  local code=$?
  set -e
  [[ "$code" -eq 1 ]] \
    || { refuse SYNTHETIC_DOGFOOD_HOSTILE_EXIT "$label returned $code"; exit 1; }
  rg -Fq "[ci] $reason:" "$test_root/stderr" \
    || { cat "$test_root/stderr" >&2; refuse SYNTHETIC_DOGFOOD_HOSTILE_REASON "$label"; exit 1; }
  [[ ! -e "$test_root/cargo-called" ]] \
    || { refuse SYNTHETIC_DOGFOOD_PREBUILD_GUARD "$label invoked Cargo"; exit 1; }
}

assert_refusal missing-gitd SYNTHETIC_DOGFOOD_GITD_REQUIRED
assert_refusal relative-gitd SYNTHETIC_DOGFOOD_GITD_REQUIRED \
  BULLET_GITD_BIN=relative/gitd BULLET_GITD_SHA256="$gitd_digest"
assert_refusal malformed-digest SYNTHETIC_DOGFOOD_GITD_DIGEST_REQUIRED \
  BULLET_GITD_BIN="$test_root/gitd" BULLET_GITD_SHA256=ABCDEF
assert_refusal mismatched-digest SYNTHETIC_DOGFOOD_GITD_DIGEST_MISMATCH \
  BULLET_GITD_BIN="$test_root/gitd" \
  BULLET_GITD_SHA256=0000000000000000000000000000000000000000000000000000000000000000
assert_refusal cargo-target CARGO_TARGET_DIR_UNSUPPORTED \
  CARGO_TARGET_DIR="$test_root/target" BULLET_GITD_BIN="$test_root/gitd" \
  BULLET_GITD_SHA256="$gitd_digest"
assert_refusal credential SYNTHETIC_DOGFOOD_CREDENTIAL_REFUSED \
  GH_TOKEN=secret BULLET_GITD_BIN="$test_root/gitd" BULLET_GITD_SHA256="$gitd_digest"

wrapper=ops/ci/proof-synthetic-dogfood.sh
expected_wrapper_sha=9505b0622f571c19d32ccd0eb39eac506496c87a9b04bd0c9bbdaf4b5c9ed682
[[ "$(sha256_file "$wrapper")" == "$expected_wrapper_sha" ]] \
  || { refuse SYNTHETIC_DOGFOOD_WRAPPER_SUBJECT_DRIFT "$wrapper"; exit 1; }
[[ "$(rg -c '^cargo build --offline --locked ' "$wrapper")" -eq 3 ]] \
  || { refuse SYNTHETIC_DOGFOOD_BUILD_INVENTORY "expected three locked offline builds"; exit 1; }
rg -Fxq 'cargo build --offline --locked -p bullet-farmd --features test-seams --bin bullet-farmd' "$wrapper"
rg -Fxq 'cargo build --offline --locked -p bullet --features synthetic-dogfood --bin transaction_offline' "$wrapper"
rg -Fxq "cargo build --offline --locked -p bullet-verifier --bin bullet-verifier-fixture \\" "$wrapper"
rg -Fxq '  --features fixture-executor' "$wrapper"
# shellcheck disable=SC2016 # These are literal shell/JQ predicates in the wrapper.
for guard in \
  'env -i PATH=/usr/bin:/bin HOME=' \
  'exec 9<"$verifier_bin"' \
  'BULLET_VERIFIER_FIXTURE_FD=9 BULLET_VERIFIER_FIXTURE_SHA256="$verifier_digest"' \
  'TRANSACTION_OFFLINE_EFFECT_RECEIPT="$root/DF_DOG1_EFFECT_CHAIN.receipt.json"' \
  '.body.evidence_class == "COMPONENT_PROOF"' \
  '.body.signing_trust == "UNSIGNED_FIXTURE"' \
  'all(.body.eligibility[]; . == false)' \
  'all($b.eligibility[]; . == false)' \
  'all($b.grants[]; . == false)' \
  '.body.selection.decision.rubric == "NONQUALITY_TIEBREAK_V1"' \
  'assert_selection_fault fault-a after-acquire SYNTHETIC_DOGFOOD_FAULT_AFTER_ACQUIRE absent' \
  'lane-b-after-acquire' \
  'before-selection' \
  'before-receipt' \
  'after-receipt' \
  'effect-grant-changed' \
  'effect-grant-readback-error' \
  'after-delivery-unknown' \
  'before-effect-receipt' \
  'after-effect-receipt' \
  'verifier-handoff' \
  'candidate-delivery' \
  'check-publication' \
  'integration' \
  'observation-cleanup' \
  '([.body.lanes[].runner_id] | unique | length) == 2' \
  '([.body.lanes[].candidate_id] | unique | length) == 2' \
  '([$s.body.lanes[].runner_id, $b.effect_authority.runner_id] | unique | length) == 3' \
  '$b.effect_authority.attempt_fence == 2' \
  '$b.effect_chain.settled_state == "COMMITTED"' \
  '.schema_version == "bullet.synthetic-effect-chain-receipt.component.v1"' \
  'selection_receipt_hex' \
  'xxd -r -p' \
  'selection_artifact_digest="$(framed_blake3 bullet.synthetic-selection-receipt.artifact.v1 "$selection_artifact")"' \
  '.body_digest == $selection_body_digest' \
  '.body_digest == $effect_body_digest' \
  '($closed | keys == ["acquire_request_digest", "attempt_fence", "attempt_id"' \
  '($closed.subject | keys == ["authority_epoch", "freeze_generation", "graph_revision", "incarnation"' \
  '($closed.subject.incarnation | keys == ["attempt_id", "context_revision", "fence", "scope_revision", "variant_id"])' \
  '$closed.subject.incarnation.scope_revision == $closed.outcome_scope_revision' \
  '$closed.runner_epoch == $request.runner_epoch' \
  '$closed.outcome_workspace_nonce_hex == ($outcome.workspace_nonce | map(' \
  '$closed.outcome_scope_revision > 0 and $closed.outcome_context_revision > 0' \
  '[[ "$summary" == "3:3:1:$expected:0" ]]' \
  'assert_effect_failure fault-grant-changed effect-grant-changed' \
  'assert_effect_failure fault-grant-readback effect-grant-readback-error' \
  '"$(jq -cS . "$effect_receipt")" == "$(<"$effect_receipt")"' \
  'cmp -s -- "$effect_receipt" <(head -c -1 "$run_root/stdout")'; do
  rg -Fq "$guard" "$wrapper" \
    || { refuse SYNTHETIC_DOGFOOD_GUARD_MISSING "$guard"; exit 1; }
done

log "synthetic dogfood wrapper guardrails passed"
