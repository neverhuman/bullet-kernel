use bullet_domain::{CandidateId, GateId, GateOutcome};
use bullet_harness_core::launch_grant::canonical_json;
use bullet_verifier_core::signed_chain::{
    canonical_chain_bytes, decode_and_verify_fixture_chain, FixtureVerifierSigningKey,
    VerificationIntentInputV1, VerificationIntentSigningKey,
};
use bullet_verifier_core::VerifierRequest;
use std::path::Path;
use std::process::Command;

const NOW: u64 = 2_000;

fn sh(dir: &Path, script: &str) {
    let output = Command::new("sh")
        .arg("-ec")
        .arg(script)
        .current_dir(dir)
        .output()
        .expect("run fixture shell");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn source_repo(dir: &Path) -> (String, String, String) {
    sh(
        dir,
        "git init -q -b main . && \
         git config user.name bullet && git config user.email bullet@test && \
         echo PONG > PONG.txt && echo base > f && git add . && git commit -qm base && \
         echo head > f && git add . && git commit -qm head",
    );
    (
        git(dir, &["rev-parse", "HEAD~1"]),
        git(dir, &["rev-parse", "HEAD"]),
        git(dir, &["rev-parse", "HEAD^{tree}"]),
    )
}

fn request(dir: &Path, base: String, head: String, tree: String) -> VerifierRequest {
    VerifierRequest {
        workspace_repo_path: dir.display().to_string(),
        base_sha: base,
        head_sha: head,
        tree_sha: tree,
        gate_id: GateId::parse(bullet_domain::REPOSITORY_GATE_ID).unwrap(),
        author_attempt_id: format!("atm_{}", "0".repeat(64)),
    }
}

fn input(request: VerifierRequest, verifier_key_id: &str) -> VerificationIntentInputV1 {
    VerificationIntentInputV1 {
        candidate_id: CandidateId::from_seed("signed-offline-candidate"),
        request,
        verifier_service_id: "bullet-verifier".into(),
        verifier_key_id: verifier_key_id.into(),
        intent_nonce: format!("non_{}", "1".repeat(64)),
        policy_digest: "2".repeat(64),
        gate_spec_digest: "3".repeat(64),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 20_000,
    }
}

struct Harness {
    intent_signing: VerificationIntentSigningKey,
    verifier_signing: FixtureVerifierSigningKey,
    candidate_id: CandidateId,
    request: VerifierRequest,
    chain: bullet_verifier_core::signed_chain::SignedVerificationChainV1,
}

async fn harness() -> (tempfile::TempDir, Harness) {
    let dir = tempfile::tempdir().unwrap();
    let (base, head, tree) = source_repo(dir.path());
    let request = request(dir.path(), base, head, tree);
    let intent_signing =
        VerificationIntentSigningKey::generate("bullet-kernel", "intent-fixture-1").unwrap();
    let verifier_signing =
        FixtureVerifierSigningKey::generate("bullet-verifier", "verifier-fixture-1").unwrap();
    let input = input(request.clone(), "verifier-fixture-1");
    let candidate_id = input.candidate_id.clone();
    let intent = intent_signing.issue(input).unwrap();
    let chain = verifier_signing
        .execute_chain(intent, &intent_signing.verification_key(), NOW, false)
        .await
        .unwrap();
    (
        dir,
        Harness {
            intent_signing,
            verifier_signing,
            candidate_id,
            request,
            chain,
        },
    )
}

#[tokio::test]
async fn signed_chain_roundtrip_binds_exact_candidate_request_and_roles() {
    let (_dir, harness) = harness().await;
    let bytes = canonical_chain_bytes(&harness.chain).unwrap();
    let verified = decode_and_verify_fixture_chain(
        &bytes,
        &harness.intent_signing.verification_key(),
        &harness.verifier_signing.verification_key(),
        &harness.candidate_id,
        &harness.request,
        NOW,
    )
    .unwrap();

    assert_eq!(verified.evidence.record.record.outcome, GateOutcome::Pass);
    assert_eq!(verified.evidence.record.candidate_id, harness.candidate_id);
    assert_eq!(verified.proof_bundle.record.outcome, GateOutcome::Pass);
    assert!(!verified.evidence.record.independent_evidence_eligible);
    assert!(!verified.evidence.record.transaction_gate_eligible);
    assert_eq!(verified.evidence.record.signing_trust, "FIXTURE_KEY_ONLY");
    assert_eq!(bytes, canonical_chain_bytes(&verified).unwrap());

    let intent_public = harness.intent_signing.verification_key();
    let verifier_public = harness.verifier_signing.verification_key();
    let retained_intent = bullet_verifier_core::VerificationIntentVerificationKey::from_public_hex(
        intent_public.issuer(),
        intent_public.key_id(),
        intent_public.public_hex(),
    )
    .unwrap();
    let retained_verifier = bullet_verifier_core::FixtureVerifierVerificationKey::from_public_hex(
        verifier_public.issuer(),
        verifier_public.key_id(),
        verifier_public.public_hex(),
    )
    .unwrap();
    decode_and_verify_fixture_chain(
        &bytes,
        &retained_intent,
        &retained_verifier,
        &harness.candidate_id,
        &harness.request,
        NOW,
    )
    .expect("retained public subjects verify the diagnostic chain");
}

#[tokio::test]
async fn failed_gate_emits_authenticated_non_green_evidence_and_proof() {
    let dir = tempfile::tempdir().unwrap();
    let (base, prior, _tree) = source_repo(dir.path());
    sh(
        dir.path(),
        "echo 'NOT PONG' > PONG.txt && git add PONG.txt && git commit -qm failing-gate",
    );
    let head = git(dir.path(), &["rev-parse", "HEAD"]);
    let tree = git(dir.path(), &["rev-parse", "HEAD^{tree}"]);
    let request = request(dir.path(), base, head, tree);
    assert_ne!(request.head_sha, prior);
    let intent_signing =
        VerificationIntentSigningKey::generate("bullet-kernel", "intent-fixture-1").unwrap();
    let verifier_signing =
        FixtureVerifierSigningKey::generate("bullet-verifier", "verifier-fixture-1").unwrap();
    let input = input(request.clone(), "verifier-fixture-1");
    let candidate_id = input.candidate_id.clone();
    let intent = intent_signing.issue(input).unwrap();
    let chain = verifier_signing
        .execute_chain(intent, &intent_signing.verification_key(), NOW, false)
        .await
        .expect("negative evidence remains signed truth");
    let bytes = canonical_chain_bytes(&chain).unwrap();
    let verified = decode_and_verify_fixture_chain(
        &bytes,
        &intent_signing.verification_key(),
        &verifier_signing.verification_key(),
        &candidate_id,
        &request,
        NOW,
    )
    .unwrap();
    assert_eq!(verified.evidence.record.record.outcome, GateOutcome::Fail);
    assert_eq!(verified.proof_bundle.record.outcome, GateOutcome::Fail);
    assert!(!verified
        .evidence
        .record
        .record
        .outcome
        .satisfies_requirement());
    assert!(!verified.evidence.record.independent_evidence_eligible);
    assert!(!verified.proof_bundle.record.transaction_gate_eligible);
}

#[tokio::test]
async fn unknown_nested_fields_and_noncanonical_bytes_are_refused() {
    let (_dir, harness) = harness().await;
    let bytes = canonical_chain_bytes(&harness.chain).unwrap();
    let verify = |raw: &[u8]| {
        decode_and_verify_fixture_chain(
            raw,
            &harness.intent_signing.verification_key(),
            &harness.verifier_signing.verification_key(),
            &harness.candidate_id,
            &harness.request,
            NOW,
        )
    };

    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["intent"]["record"]["request"]["unknown"] = serde_json::json!(true);
    assert_eq!(
        verify(&canonical_json(&value).unwrap())
            .unwrap_err()
            .reason_code(),
        "SIGNED_VERIFICATION_RECORD_INVALID"
    );

    let pretty = serde_json::to_vec_pretty(&harness.chain).unwrap();
    assert_eq!(
        verify(&pretty).unwrap_err().reason_code(),
        "SIGNED_VERIFICATION_RECORD_INVALID"
    );
}

#[tokio::test]
async fn tamper_and_wrong_role_keys_are_refused() {
    let (_dir, mut tampered) = harness().await;
    tampered.chain.evidence.record.request_digest = format!("req_{}", "9".repeat(64));
    let bytes = canonical_chain_bytes(&tampered.chain).unwrap();
    let error = decode_and_verify_fixture_chain(
        &bytes,
        &tampered.intent_signing.verification_key(),
        &tampered.verifier_signing.verification_key(),
        &tampered.candidate_id,
        &tampered.request,
        NOW,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "SIGNED_VERIFICATION_SIGNATURE_INVALID");

    let (_dir, harness) = harness().await;
    let bytes = canonical_chain_bytes(&harness.chain).unwrap();
    let wrong_intent =
        VerificationIntentSigningKey::generate("bullet-kernel", "wrong-intent").unwrap();
    let wrong_verifier =
        FixtureVerifierSigningKey::generate("bullet-verifier", "wrong-verifier").unwrap();
    for (intent_key, verifier_key) in [
        (
            wrong_intent.verification_key(),
            harness.verifier_signing.verification_key(),
        ),
        (
            harness.intent_signing.verification_key(),
            wrong_verifier.verification_key(),
        ),
    ] {
        assert_eq!(
            decode_and_verify_fixture_chain(
                &bytes,
                &intent_key,
                &verifier_key,
                &harness.candidate_id,
                &harness.request,
                NOW,
            )
            .unwrap_err()
            .reason_code(),
            "SIGNED_VERIFICATION_KEY_MISMATCH"
        );
    }
}

#[tokio::test]
async fn wrong_subject_expiry_and_author_overlap_refuse() {
    let (_dir, harness) = harness().await;
    let bytes = canonical_chain_bytes(&harness.chain).unwrap();
    let wrong_candidate = CandidateId::from_seed("other-candidate");
    let error = decode_and_verify_fixture_chain(
        &bytes,
        &harness.intent_signing.verification_key(),
        &harness.verifier_signing.verification_key(),
        &wrong_candidate,
        &harness.request,
        NOW,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "VERIFICATION_SUBJECT_MISMATCH");

    let error = decode_and_verify_fixture_chain(
        &bytes,
        &harness.intent_signing.verification_key(),
        &harness.verifier_signing.verification_key(),
        &harness.candidate_id,
        &harness.request,
        20_000,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "VERIFICATION_INTENT_TIME_INVALID");

    let intent = harness
        .intent_signing
        .issue(input(harness.request, "verifier-fixture-1"))
        .unwrap();
    let error = harness
        .verifier_signing
        .execute_chain(
            intent,
            &harness.intent_signing.verification_key(),
            NOW,
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), "VERIFIER_IS_AUTHOR");
}

#[test]
fn retained_public_key_decoder_refuses_wrong_length_nonhex_and_uppercase() {
    for hostile in ["0".repeat(62), "z".repeat(64), "A".repeat(64)] {
        assert_eq!(
            bullet_verifier_core::VerificationIntentVerificationKey::from_public_hex(
                "bullet-kernel",
                "intent-fixture-1",
                &hostile,
            )
            .unwrap_err()
            .reason_code(),
            "SIGNED_VERIFICATION_RECORD_INVALID"
        );
        assert_eq!(
            bullet_verifier_core::FixtureVerifierVerificationKey::from_public_hex(
                "bullet-verifier",
                "verifier-fixture-1",
                &hostile,
            )
            .unwrap_err()
            .reason_code(),
            "SIGNED_VERIFICATION_RECORD_INVALID"
        );
    }
}
