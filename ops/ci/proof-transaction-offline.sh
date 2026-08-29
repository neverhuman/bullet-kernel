#!/usr/bin/env bash
# Reproducible connected component proof. This is deliberately not a signed
# transaction or release receipt: its verifier is the credential-free fixture.
set -euo pipefail
umask 077

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool cargo
require_tool b3sum
require_tool git
require_tool jq
require_tool realpath
require_tool stat

if [[ "$(uname -s)" != Linux ]]; then
  refuse OFFLINE_COMPONENT_PROOF_REQUIRES_LINUX \
    "the verifier fixture requires sealed Linux memfd execution"
  exit 1
fi
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  refuse CARGO_TARGET_DIR_UNSUPPORTED \
    "unset CARGO_TARGET_DIR so every spawned local binary has one exact target path"
  exit 1
fi
if [[ -z "${BULLET_GITD_BIN:-}" ]]; then
  refuse BULLET_GITD_BIN_REQUIRED \
    "set BULLET_GITD_BIN to the exact absolute production daemon path"
  exit 1
fi
if [[ "$BULLET_GITD_BIN" != /* ]]; then
  refuse BULLET_GITD_BIN_NOT_ABSOLUTE "$BULLET_GITD_BIN"
  exit 1
fi
if [[ ! -f "$BULLET_GITD_BIN" || ! -x "$BULLET_GITD_BIN" ]]; then
  refuse BULLET_GITD_BIN_NOT_EXECUTABLE "$BULLET_GITD_BIN"
  exit 1
fi
gitd_resolved="$(realpath -e -- "$BULLET_GITD_BIN")" || {
  refuse BULLET_GITD_BIN_UNRESOLVED "$BULLET_GITD_BIN"
  exit 1
}
if [[ "$gitd_resolved" != "$BULLET_GITD_BIN" ]]; then
  refuse BULLET_GITD_BIN_NOT_CANONICAL "expected $gitd_resolved"
  exit 1
fi
if [[ ! "${BULLET_GITD_SHA256:-}" =~ ^[0-9a-f]{64}$ ]]; then
  refuse BULLET_GITD_SHA256_REQUIRED \
    "set BULLET_GITD_SHA256 to the exact lowercase production daemon digest"
  exit 1
fi
if [[ "$(sha256_file "$BULLET_GITD_BIN")" != "$BULLET_GITD_SHA256" ]]; then
  refuse BULLET_GITD_DIGEST_MISMATCH before-build
  exit 1
fi
if [[ -n "${BULLET_OFFLINE_PROOF_DIR:-}" \
  && ( "$BULLET_OFFLINE_PROOF_DIR" != /* || -e "$BULLET_OFFLINE_PROOF_DIR" ) ]]; then
  refuse OFFLINE_COMPONENT_PROOF_DIR_INVALID \
    "BULLET_OFFLINE_PROOF_DIR must be an absolute path that does not exist"
  exit 1
fi

log "building exact offline component subjects without network access"
cargo build --offline --locked -p bullet-farmd --bin bullet-farmd
cargo build --offline --locked -p bullet-runner --bin bullet-runner
cargo build --offline --locked -p bullet --bin transaction_offline
cargo build --offline --locked -p bullet-verifier --bin bullet-verifier-fixture \
  --features fixture-executor

farmd_bin="$(realpath -e -- target/debug/bullet-farmd)"
runner_bin="$(realpath -e -- target/debug/bullet-runner)"
offline_bin="$(realpath -e -- target/debug/transaction_offline)"
verifier_bin="$(realpath -e -- target/debug/bullet-verifier-fixture)"
for subject in "$farmd_bin" "$runner_bin" "$offline_bin" "$verifier_bin"; do
  if [[ ! -f "$subject" || ! -x "$subject" ]]; then
    refuse OFFLINE_COMPONENT_SUBJECT_INVALID "$subject"
    exit 1
  fi
done

if [[ -n "${BULLET_OFFLINE_PROOF_DIR:-}" ]]; then
  mkdir -m 0700 -- "$BULLET_OFFLINE_PROOF_DIR"
  proof_root="$(realpath -e -- "$BULLET_OFFLINE_PROOF_DIR")"
else
  proof_root="$(mktemp -d /tmp/bullet-offline-component-proof.XXXXXXXX)"
fi
if [[ "$proof_root" == / || "$proof_root" == "$REPO_ROOT" || -L "$proof_root" ]]; then
  refuse OFFLINE_COMPONENT_PROOF_DIR_INVALID "$proof_root"
  exit 1
fi
proof_identity="$(stat -Lc '%u:%a:%F' -- "$proof_root")"
if [[ "$proof_identity" != "$(id -u):700:directory" ]]; then
  refuse OFFLINE_COMPONENT_PROOF_DIR_UNTRUSTED "$proof_identity"
  exit 1
fi
receipt="$proof_root/COMPONENT_PROOF.receipt.json"
artifact_root="$proof_root/artifacts"
if [[ -e "$receipt" || -L "$receipt" ]]; then
  refuse OFFLINE_COMPONENT_RECEIPT_EXISTS "$receipt"
  exit 1
fi

export BULLET_FARMD_BIN="$farmd_bin"
export BULLET_RUNNER_BIN="$runner_bin"
export BULLET_KERNEL_AUTHORITY_SERVER_UID
BULLET_KERNEL_AUTHORITY_SERVER_UID="$(id -u)"
export BULLET_KERNEL_AUTHORITY_SOCKET_GID
BULLET_KERNEL_AUTHORITY_SOCKET_GID="$(id -g)"
export BULLET_DATA_DIR="$proof_root/data"
export TRANSACTION_OFFLINE_RECEIPT="$receipt"
export TRANSACTION_OFFLINE_ARTIFACT_ROOT="$artifact_root"
export BULLET_VERIFIER_FIXTURE_SHA256
BULLET_VERIFIER_FIXTURE_SHA256="$(sha256_file "$verifier_bin")"
export BULLET_VERIFIER_FIXTURE_FD=9

log "running connected offline component bridge"
exec 9<"$verifier_bin"
"$offline_bin"
exec 9<&-

if [[ ! -f "$receipt" || -L "$receipt" ]]; then
  refuse OFFLINE_COMPONENT_RECEIPT_MISSING "$receipt"
  exit 1
fi
receipt_identity="$(stat -Lc '%u:%a:%F' -- "$receipt")"
if [[ "$receipt_identity" != "$(id -u):600:regular file" ]]; then
  refuse OFFLINE_COMPONENT_RECEIPT_UNTRUSTED "$receipt_identity"
  exit 1
fi

intent_label='verification-intent-fixture-1'
verifier_label='verifier-fixture-1'
observer_label='observer-fixture-1'
jq -e \
  --arg intent_label "$intent_label" \
  --arg verifier_label "$verifier_label" \
  --arg observer_label "$observer_label" \
  --arg proof_root "$proof_root" '
  keys == [
    "artifact_custody", "attempt_first", "attempt_second", "base_oid", "candidate_id", "children",
    "command_dispatch", "command_id", "command_phase", "effect_candidate_bound", "effect_delivered_oid",
    "effect_settled", "effect_unknown", "evidence_class",
    "fence_first", "fence_second", "gitd_fixture", "head_oid",
    "independent_evidence_eligible", "local_forge", "product_runner_candidate_id",
    "product_runner_gate_passed", "product_runner_outcome", "product_runner_preservation",
    "provider_execution", "schema_version",
    "scope_authority_epoch", "scope_grant_id", "scope_paths_digest", "signed_verification",
    "signing_trust", "stale_refused", "transaction_gate_eligible", "tree_oid", "unknown_then_adopt",
    "verifier_outcome", "writer_proof_refused"
  ] and
  .schema_version == "v1alpha1" and
  .evidence_class == "COMPONENT_PROOF" and
  .signing_trust == "UNSIGNED_FIXTURE" and
  .transaction_gate_eligible == false and
  .independent_evidence_eligible == false and
  (.command_dispatch | keys == [
    "binary_manifest_sha256", "canonical_claim_blake3", "claim_id", "command_id",
    "independent_evidence_eligible", "request_digest", "runner_epoch", "runner_id", "source",
    "transaction_gate_eligible"
  ]) and
  .command_dispatch.source == "LOCAL_FIXTURE" and
  .command_dispatch.claim_id == null and
  .command_dispatch.command_id == null and
  .command_dispatch.request_digest == null and
  .command_dispatch.runner_id == null and
  .command_dispatch.runner_epoch == null and
  .command_dispatch.canonical_claim_blake3 == null and
  .command_dispatch.binary_manifest_sha256 == null and
  .command_dispatch.transaction_gate_eligible == false and
  .command_dispatch.independent_evidence_eligible == false and
  (.provider_execution | keys == [
    "adapter", "base_checkpoint_digest", "base_checkpoint_id", "credential_free", "gate_ids",
    "producing_attempt_id", "proposal_id", "raw_artifact_blake3", "raw_artifact_relative",
    "session_id", "transaction_gate_eligible", "version"
  ]) and
  .provider_execution.adapter == "sim" and
  .provider_execution.version == "sim-1.0.0" and
  .provider_execution.credential_free == true and
  .provider_execution.transaction_gate_eligible == false and
  (.provider_execution.session_id | test("^cnt_[0-9a-f]{64}$")) and
  (.provider_execution.proposal_id | test("^cnt_[0-9a-f]{64}$")) and
  .provider_execution.producing_attempt_id == .attempt_first and
  (.provider_execution.base_checkpoint_id | test("^ckp_[0-9a-f]{64}$")) and
  (.provider_execution.base_checkpoint_digest | test("^[0-9a-f]{64}$")) and
  .provider_execution.gate_ids == ["gat_8888888888888888888888888888888888888888888888888888888888888888"] and
  (.provider_execution.raw_artifact_blake3 | test("^[0-9a-f]{64}$")) and
  .provider_execution.raw_artifact_relative ==
    ("artifacts/provider-artifacts/" + .provider_execution.session_id + ".raw.jsonl") and
  (.artifact_custody | keys == [
    "artifact_root_relative", "base_oid", "candidate_id", "candidate_repository_relative",
    "head_oid", "ledger_relative", "local_forge_relative", "retained",
    "source_repository_relative", "target_oid", "target_ref", "tree_oid"
  ]) and
  .artifact_custody.retained == true and
  .artifact_custody.artifact_root_relative == "artifacts" and
  .artifact_custody.source_repository_relative == "artifacts/source" and
  .artifact_custody.candidate_repository_relative == "artifacts/preserve/generation/repo" and
  .artifact_custody.local_forge_relative == "artifacts/effects/target.git" and
  .artifact_custody.ledger_relative == "data/ledger.sqlite" and
  .artifact_custody.candidate_id == .candidate_id and
  .artifact_custody.base_oid == .base_oid and
  .artifact_custody.head_oid == .head_oid and
  .artifact_custody.tree_oid == .tree_oid and
  .artifact_custody.target_ref == "refs/heads/main" and
  .artifact_custody.target_oid == .head_oid and
  .gitd_fixture == false and
  .unknown_then_adopt == true and
  .effect_unknown == "OUTCOME_UNKNOWN" and
  .effect_settled == "COMMITTED" and
  .effect_candidate_bound == true and
  .effect_delivered_oid == .head_oid and
  (.local_forge | keys == [
    "check_name", "check_readback_matches", "check_sha", "delivered_oid",
    "effect_candidate_bound", "integration_oid", "integration_previous_oid",
    "integration_subject_id", "observation_target_oid", "proof_root",
    "restart_readback_matches", "signed_observation"
  ]) and
  .local_forge.effect_candidate_bound == true and
  .local_forge.delivered_oid == .head_oid and
  .local_forge.check_sha == .head_oid and
  .local_forge.check_readback_matches == true and
  .local_forge.integration_previous_oid == .base_oid and
  .local_forge.integration_oid == .head_oid and
  .local_forge.observation_target_oid == .head_oid and
  .local_forge.restart_readback_matches == true and
  (.local_forge.proof_root | test("^prf_[0-9a-f]{64}$")) and
  .local_forge.proof_root == .signed_verification.chain.proof_bundle.record.proof_root and
  (.local_forge.integration_subject_id | test("^ins_[0-9a-f]{64}$")) and
  (.local_forge.signed_observation | keys == [
    "canonical_observation_blake3", "chain_reverified", "independent_evidence_eligible",
    "observer_key", "release_gate_eligible", "signed", "signing_trust",
    "transaction_gate_eligible"
  ]) and
  .local_forge.signed_observation.signing_trust == "FIXTURE_KEY_ONLY" and
  .local_forge.signed_observation.independent_evidence_eligible == false and
  .local_forge.signed_observation.transaction_gate_eligible == false and
  .local_forge.signed_observation.release_gate_eligible == false and
  .local_forge.signed_observation.chain_reverified == true and
  (.local_forge.signed_observation.canonical_observation_blake3 | test("^blake3:[0-9a-f]{64}$")) and
  (.local_forge.signed_observation.observer_key | keys == ["issuer", "key_id", "public_hex"]) and
  .local_forge.signed_observation.observer_key.issuer == "bullet-observer" and
  .local_forge.signed_observation.observer_key.key_id == $observer_label and
  (.local_forge.signed_observation.observer_key.public_hex | test("^[0-9a-f]{64}$")) and
  (.local_forge.signed_observation.signed | keys == ["issuer", "key_id", "paseto", "record", "schema_version"]) and
  .local_forge.signed_observation.signed.issuer == .local_forge.signed_observation.observer_key.issuer and
  .local_forge.signed_observation.signed.key_id == .local_forge.signed_observation.observer_key.key_id and
  (.local_forge.signed_observation.signed.paseto | startswith("v4.public.")) and
  .local_forge.signed_observation.signed.record.schema_version == "bullet.integration-observation.v1" and
  .local_forge.signed_observation.signed.record.evidence_class == "COMPONENT_PROOF" and
  .local_forge.signed_observation.signed.record.signing_trust == "FIXTURE_KEY_ONLY" and
  .local_forge.signed_observation.signed.record.independent_evidence_eligible == false and
  .local_forge.signed_observation.signed.record.transaction_gate_eligible == false and
  .local_forge.signed_observation.signed.record.release_gate_eligible == false and
  .local_forge.signed_observation.signed.record.outcome == "MATCHED" and
  .local_forge.signed_observation.signed.record.integration_survived == true and
  .local_forge.signed_observation.signed.record.readback_reason_code == null and
  .local_forge.signed_observation.signed.record.observed_oid == .head_oid and
  .local_forge.signed_observation.signed.record.subject.candidate_id == .candidate_id and
  .local_forge.signed_observation.signed.record.subject.proof_bundle_id == .signed_verification.chain.proof_bundle.record.proof_bundle_id and
  .local_forge.signed_observation.signed.record.subject.proof_root == .signed_verification.chain.proof_bundle.record.proof_root and
  .local_forge.signed_observation.signed.record.subject.integration_subject_id == .local_forge.integration_subject_id and
  .local_forge.signed_observation.signed.record.subject.target == "refs/heads/main" and
  .local_forge.signed_observation.signed.record.subject.previous_oid == .base_oid and
  .local_forge.signed_observation.signed.record.subject.integrated_oid == .head_oid and
  .local_forge.signed_observation.signed.record.subject.check_sha == .head_oid and
  .local_forge.signed_observation.signed.record.subject.check_name == .local_forge.check_name and
  .local_forge.signed_observation.signed.record.subject.check_proof_root == .local_forge.proof_root and
  (.signed_verification | keys == [
    "canonical_chain_blake3", "chain", "chain_reverified",
    "independent_evidence_eligible", "intent_key", "signing_trust",
    "transaction_gate_eligible", "verifier_key", "verifier_outcome",
    "writer_proof_refused"
  ]) and
  .signed_verification.signing_trust == "FIXTURE_KEY_ONLY" and
  .signed_verification.independent_evidence_eligible == false and
  .signed_verification.transaction_gate_eligible == false and
  .signed_verification.chain_reverified == true and
  .signed_verification.verifier_outcome == .verifier_outcome and
  .signed_verification.writer_proof_refused == .writer_proof_refused and
  (.signed_verification.canonical_chain_blake3 | test("^blake3:[0-9a-f]{64}$")) and
  .signed_verification.intent_key.issuer == "bullet-kernel" and
  .signed_verification.intent_key.key_id == $intent_label and
  (.signed_verification.intent_key.public_hex | test("^[0-9a-f]{64}$")) and
  .signed_verification.verifier_key.issuer == "bullet-verifier" and
  .signed_verification.verifier_key.key_id == $verifier_label and
  (.signed_verification.verifier_key.public_hex | test("^[0-9a-f]{64}$")) and
  (.signed_verification.chain | keys == ["evidence", "intent", "proof_bundle", "schema_version"]) and
  .signed_verification.chain.schema_version == "bullet.verification-chain.v1" and
  .signed_verification.chain.intent.record.candidate_id == .candidate_id and
  .signed_verification.chain.intent.record.request.base_sha == .base_oid and
  .signed_verification.chain.intent.record.request.head_sha == .head_oid and
  .signed_verification.chain.intent.record.request.tree_sha == .tree_oid and
  .signed_verification.chain.intent.record.signing_trust == "FIXTURE_KEY_ONLY" and
  .signed_verification.chain.intent.record.independent_evidence_eligible == false and
  .signed_verification.chain.intent.record.transaction_gate_eligible == false and
  (.signed_verification.chain.intent.paseto | startswith("v4.public.")) and
  .signed_verification.chain.evidence.record.candidate_id == .candidate_id and
  .signed_verification.chain.evidence.record.record.outcome == "PASS" and
  .signed_verification.chain.evidence.record.signing_trust == "FIXTURE_KEY_ONLY" and
  .signed_verification.chain.evidence.record.independent_evidence_eligible == false and
  .signed_verification.chain.evidence.record.transaction_gate_eligible == false and
  (.signed_verification.chain.evidence.paseto | startswith("v4.public.")) and
  .signed_verification.chain.proof_bundle.record.candidate_id == .candidate_id and
  .signed_verification.chain.proof_bundle.record.outcome == "PASS" and
  .signed_verification.chain.proof_bundle.record.signing_trust == "FIXTURE_KEY_ONLY" and
  .signed_verification.chain.proof_bundle.record.independent_evidence_eligible == false and
  .signed_verification.chain.proof_bundle.record.transaction_gate_eligible == false and
  (.signed_verification.chain.proof_bundle.record.proof_root | test("^prf_[0-9a-f]{64}$")) and
  (.signed_verification.chain.proof_bundle.paseto | startswith("v4.public.")) and
  .verifier_outcome == "PASS" and
  .writer_proof_refused == true and
  .stale_refused == true and
  .attempt_second != .attempt_first and
  .fence_first > 0 and
  .fence_second > 0 and
  .product_runner_gate_passed == true and
  .product_runner_outcome == "CANDIDATE_PRESERVED" and
  .product_runner_candidate_id == .candidate_id and
  (.product_runner_preservation | keys == [
    "attempt_id", "base_commit", "candidate_id", "fence", "head_commit", "patch_hash",
    "receipt", "tree_hash"
  ]) and
  .product_runner_preservation.candidate_id == .candidate_id and
  .product_runner_preservation.base_commit == ("sha1:" + .base_oid) and
  .product_runner_preservation.head_commit == ("sha1:" + .head_oid) and
  .product_runner_preservation.tree_hash == ("sha1:" + .tree_oid) and
  (.product_runner_preservation.patch_hash | test("^[0-9a-f]{64}$")) and
  .product_runner_preservation.attempt_id == .attempt_first and
  .product_runner_preservation.fence == .fence_first and
  (.product_runner_preservation.receipt | keys == [
    "artifact_digest", "destination", "digest", "token"
  ]) and
  (.product_runner_preservation.receipt.token | test("^[0-9a-f]+$")) and
  (.product_runner_preservation.receipt.digest | test("^[0-9a-f]{64}$")) and
  (.product_runner_preservation.receipt.artifact_digest | test("^[0-9a-f]{64}$")) and
  .product_runner_preservation.receipt.destination ==
    ($proof_root + "/artifacts/preserve") and
  (.children | keys == ["farmd", "gitd", "runner", "verifier"]) and
  (.scope_grant_id | test("^sgr_[0-9a-f]{64}$")) and
  (.candidate_id | test("^can_[0-9a-f]{64}$")) and
  (.product_runner_candidate_id | test("^can_[0-9a-f]{64}$"))
' "$receipt" >/dev/null

source_repo="$artifact_root/source"
candidate_repo="$artifact_root/preserve/generation/repo"
preservation_root="$artifact_root/preserve"
local_forge="$artifact_root/effects/target.git"
for subject in "$artifact_root" "$source_repo" "$candidate_repo" "$local_forge"; do
  if [[ ! -d "$subject" || -L "$subject" || "$(stat -Lc '%u:%F' -- "$subject")" != "$(id -u):directory" ]]; then
    refuse OFFLINE_COMPONENT_ARTIFACT_UNTRUSTED "$subject"
    exit 1
  fi
done
if [[ "$(stat -Lc '%u:%a:%F' -- "$artifact_root")" != "$(id -u):700:directory" ]]; then
  refuse OFFLINE_COMPONENT_ARTIFACT_UNTRUSTED "$artifact_root"
  exit 1
fi
preservation_subject="$preservation_root/subject.json"
if [[ ! -f "$preservation_subject" || -L "$preservation_subject" \
  || "$(stat -Lc '%u:%a:%F' -- "$preservation_subject")" != "$(id -u):600:regular file" ]]; then
  refuse OFFLINE_COMPONENT_PRESERVATION_SUBJECT_UNTRUSTED "$preservation_subject"
  exit 1
fi
ledger="$proof_root/data/ledger.sqlite"
if [[ ! -f "$ledger" || -L "$ledger" || "$(stat -Lc '%u:%a:%F' -- "$ledger")" != "$(id -u):600:regular file" ]]; then
  refuse OFFLINE_COMPONENT_LEDGER_UNTRUSTED "$ledger"
  exit 1
fi
provider_artifact_relative="$(jq -r '.provider_execution.raw_artifact_relative' "$receipt")"
provider_artifact="$proof_root/$provider_artifact_relative"
if [[ ! -f "$provider_artifact" || -L "$provider_artifact" \
  || "$(stat -Lc '%u:%a:%F' -- "$provider_artifact")" != "$(id -u):600:regular file" ]]; then
  refuse OFFLINE_COMPONENT_PROVIDER_ARTIFACT_UNTRUSTED "$provider_artifact"
  exit 1
fi
provider_artifact_blake3="$(jq -r '.provider_execution.raw_artifact_blake3' "$receipt")"
if [[ "$(b3sum "$provider_artifact" | awk '{print $1}')" != "$provider_artifact_blake3" ]]; then
  refuse OFFLINE_COMPONENT_PROVIDER_ARTIFACT_MISMATCH "$provider_artifact"
  exit 1
fi
if ! jq -s -e \
  --arg proposal_id "$(jq -r '.provider_execution.proposal_id' "$receipt")" \
  --arg attempt_id "$(jq -r '.provider_execution.producing_attempt_id' "$receipt")" \
  --arg checkpoint_id "$(jq -r '.provider_execution.base_checkpoint_id' "$receipt")" \
  --arg checkpoint_digest "$(jq -r '.provider_execution.base_checkpoint_digest' "$receipt")" '
    length > 0 and
    all(.[]; type == "object" and (keys == ["kind", "payload"])) and
    (map(select(.kind == "turn.completed")) | length == 1) and
    (map(select(.kind == "turn.failed")) | length == 0) and
    last.kind == "turn.completed" and
    last.payload.proposal.proposal_id == $proposal_id and
    last.payload.proposal.producing_attempt_id == $attempt_id and
    last.payload.proposal.base_checkpoint_id == $checkpoint_id and
    last.payload.proposal.base_checkpoint_digest == $checkpoint_digest and
    last.payload.proposal.gate_ids == ["gat_8888888888888888888888888888888888888888888888888888888888888888"]
  ' "$provider_artifact" >/dev/null; then
  refuse OFFLINE_COMPONENT_PROVIDER_TRANSCRIPT_INVALID "$provider_artifact"
  exit 1
fi
base_oid="$(jq -r '.base_oid' "$receipt")"
head_oid="$(jq -r '.head_oid' "$receipt")"
tree_oid="$(jq -r '.tree_oid' "$receipt")"
preservation_token="$(jq -r '.product_runner_preservation.receipt.token' "$receipt")"
preservation_digest="$(jq -r '.product_runner_preservation.receipt.digest' "$receipt")"
observed_preservation_digest="$(printf '%s' "$preservation_token" | b3sum | awk '{print $1}')"
patch_digest="$(
  git -C "$candidate_repo" diff --binary --no-ext-diff --no-textconv "$base_oid..$head_oid" \
    | b3sum | awk '{print $1}'
)"
if [[ "$(git -C "$source_repo" rev-parse HEAD)" != "$base_oid" \
  || "$(git -C "$candidate_repo" rev-parse HEAD)" != "$head_oid" \
  || "$(git -C "$candidate_repo" rev-parse 'HEAD^{tree}')" != "$tree_oid" \
  || "$(git --git-dir="$local_forge" rev-parse refs/heads/main)" != "$head_oid" ]]; then
  refuse OFFLINE_COMPONENT_ARTIFACT_SUBJECT_MISMATCH \
    "retained source, Candidate, or target differs from the receipt"
  exit 1
fi
if [[ "$observed_preservation_digest" != "$preservation_digest" \
  || "$patch_digest" != "$(jq -r '.product_runner_preservation.patch_hash' "$receipt")" ]]; then
  refuse OFFLINE_COMPONENT_PRESERVATION_BINDING_MISMATCH \
    "sealed-token or exact retained patch differs from the receipt"
  exit 1
fi

if [[ "$(sha256_file "$BULLET_GITD_BIN")" != "$BULLET_GITD_SHA256" ]]; then
  refuse BULLET_GITD_DIGEST_MISMATCH after-proof
  exit 1
fi

log "offline component proof passed"
log "receipt=$receipt"
log "receipt_sha256=$(sha256_file "$receipt")"
log "classification=COMPONENT_PROOF signing_trust=UNSIGNED_FIXTURE release_eligible=false"
