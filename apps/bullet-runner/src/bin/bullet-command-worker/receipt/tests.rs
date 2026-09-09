//! Hostile retained-receipt admission tests.

use super::*;
use bullet_application::{CommandDispatchDisposition, CommandRequest};
use bullet_domain::{CandidateId, CommandId, GateId, RunnerId};
use bullet_effects_core::{
    canonical_observation_bytes, CheckPublication, FixtureObserverSigningKey, ForgeEffects,
    ForgeIntegration, IntegrationSubjectRequest, LocalBareForge, ObservationInputV1,
    ObservationSubjectV1, ProtectedIntegrationRequest, PushRequest, ZERO_OID,
};
use bullet_harness_core::launch_grant::canonical_json;
use bullet_verifier_core::signed_chain::{
    canonical_chain_bytes, FixtureVerifierSigningKey, VerificationIntentInputV1,
    VerificationIntentSigningKey,
};
use bullet_verifier_core::VerifierRequest;
use serde_json::{json, Value};
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[path = "tests/candidate_identity.rs"]
mod candidate_identity;
#[path = "tests/ledger.rs"]
mod ledger;
#[path = "tests/ledger_fixture.rs"]
mod ledger_fixture;
#[path = "tests/preservation_fixture.rs"]
mod preservation_fixture;
#[path = "tests/provider.rs"]
mod provider_fixture;

const MANIFEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CHECK: &str = "bullet/offline-component-proof";
const RECEIPT: &str = "COMPONENT_PROOF.receipt.json";

struct Fixture {
    _temp: tempfile::TempDir,
    run: PathBuf,
    receipt: PathBuf,
    claim: CommandDispatchClaim,
    value: Value,
    source: PathBuf,
    candidate: PathBuf,
    forge: PathBuf,
}

impl Fixture {
    async fn new(stale: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        private_dir(&run);
        let artifacts = run.join("artifacts");
        let data = run.join("data");
        private_dir(&artifacts);
        private_dir(&data);
        let source = artifacts.join("source");
        private_dir(&source);
        git_ok(&source, &["init", "-q", "-b", "main", "."]);
        git_ok(&source, &["config", "user.name", "bullet"]);
        git_ok(&source, &["config", "user.email", "bullet@test"]);
        std::fs::write(source.join("PONG.txt"), b"PONG\n").unwrap();
        std::fs::write(source.join("f"), b"base\n").unwrap();
        git_ok(&source, &["add", "."]);
        git_ok(&source, &["commit", "-qm", "base"]);
        let base = git_value(&source, &["rev-parse", "HEAD"]);

        let candidate = artifacts.join("preserve/generation/repo");
        std::fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        git_ok(
            temp.path(),
            &[
                "clone",
                "-q",
                source.to_str().unwrap(),
                candidate.to_str().unwrap(),
            ],
        );
        git_ok(&candidate, &["config", "user.name", "bullet"]);
        git_ok(&candidate, &["config", "user.email", "bullet@test"]);
        std::fs::write(candidate.join("f"), b"head\n").unwrap();
        git_ok(&candidate, &["add", "."]);
        git_ok(&candidate, &["commit", "-qm", "head"]);
        let head = git_value(&candidate, &["rev-parse", "HEAD"]);
        let tree = git_value(&candidate, &["rev-parse", "HEAD^{tree}"]);

        let candidate_id = CandidateId::from_seed("receipt-candidate");
        let attempt_first = format!("atm_{}", "1".repeat(64));
        let attempt_second = format!("atm_{}", "5".repeat(64));
        let scope_paths_digest = "7".repeat(64);
        let product_runner_preservation = preservation_fixture::fixture(
            &artifacts,
            &run,
            &candidate,
            &candidate_id,
            &attempt_first,
            &base,
            &head,
            &tree,
        );
        let request = VerifierRequest {
            workspace_repo_path: candidate.display().to_string(),
            base_sha: base.clone(),
            head_sha: head.clone(),
            tree_sha: tree.clone(),
            gate_id: GateId::parse(REPOSITORY_GATE_ID).unwrap(),
            author_attempt_id: attempt_first.clone(),
        };
        let current = artifacts::now_unix_ms().unwrap();
        let signed_at = if stale { current - 120_000 } else { current };
        let intent_signer =
            VerificationIntentSigningKey::generate("bullet-kernel", "intent-fixture-1").unwrap();
        let verifier_signer =
            FixtureVerifierSigningKey::generate("bullet-verifier", "verifier-fixture-1").unwrap();
        let intent_public = intent_signer.verification_key();
        let verifier_public = verifier_signer.verification_key();
        let intent = intent_signer
            .issue(VerificationIntentInputV1 {
                candidate_id: candidate_id.clone(),
                request: request.clone(),
                verifier_service_id: "bullet-verifier".into(),
                verifier_key_id: "verifier-fixture-1".into(),
                intent_nonce: format!("non_{}", "2".repeat(64)),
                policy_digest: "3".repeat(64),
                gate_spec_digest: "4".repeat(64),
                issued_at_unix_ms: signed_at,
                expires_at_unix_ms: signed_at + 60_000,
            })
            .unwrap();
        let chain = verifier_signer
            .execute_chain(intent, &intent_public, signed_at, false)
            .await
            .unwrap();
        let chain_bytes = canonical_chain_bytes(&chain).unwrap();
        let proof = chain.proof_bundle.record.clone();

        let forge = artifacts.join("effects/target.git");
        std::fs::create_dir_all(forge.parent().unwrap()).unwrap();
        let mut local = LocalBareForge::init(&forge).unwrap();
        git_ok(
            &candidate,
            &[
                "push",
                "-q",
                forge.to_str().unwrap(),
                &format!("{base}:{TARGET}"),
            ],
        );
        let candidate_ref = format!("refs/heads/bullet/candidate/{candidate_id}");
        local
            .push_candidate_ref(&PushRequest {
                workspace_repo: candidate.clone(),
                ref_name: candidate_ref,
                expected_old_oid: ZERO_OID.into(),
                new_oid: head.clone(),
            })
            .unwrap();
        local.protect_target(TARGET, &proof.proof_root).unwrap();
        local
            .publish_check(&CheckPublication {
                sha: head.clone(),
                name: CHECK.into(),
                proof_root: proof.proof_root.clone(),
            })
            .unwrap();
        let integration = local
            .ensure_integration_subject(&IntegrationSubjectRequest {
                base: base.clone(),
                head: head.clone(),
                target: TARGET.into(),
            })
            .unwrap();
        let integrated = local
            .integrate_protected(&ProtectedIntegrationRequest {
                subject: integration.clone(),
                expected_old_oid: base.clone(),
                check_name: CHECK.into(),
                proof_root: proof.proof_root.clone(),
            })
            .unwrap();
        let observation_subject = ObservationSubjectV1::from_integration(
            candidate_id.clone(),
            &proof.proof_bundle_id,
            &proof.proof_root,
            &integrated,
        )
        .unwrap();
        let observer =
            FixtureObserverSigningKey::generate("bullet-observer", "observer-fixture-1").unwrap();
        let observer_public = observer.verification_key();
        let observation = observer
            .observe(
                &local,
                ObservationInputV1 {
                    subject: observation_subject,
                    freshness_window_ms: 60_000,
                },
                signed_at,
            )
            .unwrap();
        let observation_bytes = canonical_observation_bytes(&observation).unwrap();

        ledger_fixture::write(
            &data.join("ledger.sqlite"),
            &attempt_first,
            &attempt_second,
            1,
            2,
            &candidate_id,
            &head,
            2,
            &scope_paths_digest,
        );
        let claim = claim("public-command");
        let claim_bytes = canonical_json(&claim).unwrap();
        let children = json!({
            "farmd":"bullet-farmd","runner":"bullet-runner",
            "gitd":"bullet-gitd","verifier":"bullet-verifier-fixture"
        });
        let command_dispatch = json!({
            "source":"SEALED_CLAIM","claim_id":claim.claim_id,
            "command_id":claim.command_id,"request_digest":claim.request_digest,
            "runner_id":claim.runner_id,"runner_epoch":claim.runner_epoch,
            "canonical_claim_blake3":artifacts::blake3_label(&claim_bytes),
            "binary_manifest_sha256":MANIFEST,"transaction_gate_eligible":false,
            "independent_evidence_eligible":false
        });
        let provider_execution = provider_fixture::fixture(&artifacts, &attempt_first);
        let artifact_custody = json!({
            "retained":true,"artifact_root_relative":"artifacts",
            "source_repository_relative":"artifacts/source",
            "candidate_repository_relative":"artifacts/preserve/generation/repo",
            "local_forge_relative":"artifacts/effects/target.git",
            "ledger_relative":"data/ledger.sqlite","candidate_id":candidate_id,
            "base_oid":base,"head_oid":head,"tree_oid":tree,
            "target_ref":TARGET,"target_oid":head
        });
        let signed_verification = json!({
            "verifier_outcome":"PASS","writer_proof_refused":true,
            "signing_trust":"FIXTURE_KEY_ONLY","independent_evidence_eligible":false,
            "transaction_gate_eligible":false,"chain_reverified":true,
            "canonical_chain_blake3":artifacts::blake3_label(&chain_bytes),
            "intent_key":{"issuer":intent_public.issuer(),"key_id":intent_public.key_id(),
                "public_hex":intent_public.public_hex()},
            "verifier_key":{"issuer":verifier_public.issuer(),"key_id":verifier_public.key_id(),
                "public_hex":verifier_public.public_hex()},
            "chain":chain
        });
        let local_forge = json!({
            "delivered_oid":head,"effect_candidate_bound":true,
            "proof_root":proof.proof_root,"check_name":CHECK,"check_sha":head,
            "check_readback_matches":true,"integration_subject_id":integration.id,
            "integration_previous_oid":base,"integration_oid":head,
            "observation_target_oid":head,"restart_readback_matches":true,
            "signed_observation":{"signing_trust":"FIXTURE_KEY_ONLY",
                "independent_evidence_eligible":false,"transaction_gate_eligible":false,
                "release_gate_eligible":false,"chain_reverified":true,
                "canonical_observation_blake3":artifacts::blake3_label(&observation_bytes),
                "observer_key":{"issuer":"bullet-observer","key_id":"observer-fixture-1",
                    "public_hex":observer_public.public_hex()},"signed":observation}
        });
        let value = json!({
            "schema_version":"v1alpha1","evidence_class":"COMPONENT_PROOF",
            "signing_trust":"UNSIGNED_FIXTURE","transaction_gate_eligible":false,
            "independent_evidence_eligible":false,"gitd_fixture":false,"unknown_then_adopt":true,
            "fence_first":1,"fence_second":2,"attempt_first":attempt_first,
            "attempt_second":attempt_second,"candidate_id":candidate_id,
            "base_oid":base,"head_oid":head,"tree_oid":tree,
            "verifier_outcome":"PASS","writer_proof_refused":true,
            "effect_unknown":"OUTCOME_UNKNOWN","effect_settled":"COMMITTED",
            "effect_delivered_oid":head,"effect_candidate_bound":true,
            "stale_refused":true,"scope_grant_id":format!("sgr_{}", "6".repeat(64)),
            "scope_paths_digest":scope_paths_digest,"scope_authority_epoch":2,
            "command_id":CommandId::from_seed("txn-proof-demo"),"command_phase":"pending",
            "product_runner_gate_passed":true,"product_runner_outcome":"CANDIDATE_PRESERVED",
            "product_runner_candidate_id":candidate_id,
            "product_runner_preservation":product_runner_preservation,
            "children":children,"command_dispatch":command_dispatch,
            "provider_execution":provider_execution,
            "artifact_custody":artifact_custody,"signed_verification":signed_verification,
            "local_forge":local_forge
        });
        let receipt = run.join(RECEIPT);
        write_receipt(&receipt, &value, true);
        Self {
            _temp: temp,
            run,
            receipt,
            claim,
            value,
            source,
            candidate,
            forge,
        }
    }

    fn rewrite(&self, value: &Value) {
        write_receipt(&self.receipt, value, false);
    }
    fn admit(&self) -> Result<AdmittedReceipt, WorkerError> {
        admit_receipt(&self.receipt, &self.run, &self.claim, MANIFEST)
    }
}

#[tokio::test]
async fn exact_current_receipt_returns_raw_and_typed_digests() {
    let fixture = Fixture::new(false).await;
    let admitted = fixture.admit().unwrap();
    let bytes = std::fs::read(&fixture.receipt).unwrap();
    assert_eq!(admitted.raw_sha256(), hex::encode(Sha256::digest(&bytes)));
    assert_eq!(admitted.receipt_digest(), Digest::of(&bytes));
    assert_ne!(
        fixture.value["command_id"],
        fixture.value["command_dispatch"]["command_id"]
    );
}

#[tokio::test]
async fn painted_recursive_unknown_and_signature_tamper_refuse() {
    let fixture = Fixture::new(false).await;
    for mutate in ["paint", "unknown", "verifier", "observer"] {
        let mut value = fixture.value.clone();
        match mutate {
            "paint" => value["transaction_gate_eligible"] = json!(true),
            "unknown" => {
                value["signed_verification"]["chain"]["intent"]["record"]["request"]["unknown"] =
                    json!(true)
            }
            "verifier" => {
                value["signed_verification"]["chain"]["evidence"]["paseto"] =
                    json!("v4.public.tampered")
            }
            _ => {
                value["local_forge"]["signed_observation"]["observer_key"]["public_hex"] =
                    json!("0".repeat(64))
            }
        }
        fixture.rewrite(&value);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID"
        );
    }
}

#[tokio::test]
async fn only_nested_exact_public_claim_can_settle() {
    let fixture = Fixture::new(false).await;
    let other = claim("another-public-command");
    assert_eq!(
        admit_receipt(&fixture.receipt, &fixture.run, &other, MANIFEST)
            .unwrap_err()
            .code(),
        "COMMAND_RECEIPT_INVALID"
    );
}

#[tokio::test]
async fn expired_first_admission_refuses_but_exact_retained_readback_survives() {
    let fixture = Fixture::new(true).await;
    assert!(fixture.admit().is_err());
    let bytes = std::fs::read(&fixture.receipt).unwrap();
    let raw = hex::encode(Sha256::digest(&bytes));
    let digest = Digest::of(&bytes);
    readback_retained_receipt(
        &fixture.receipt,
        &fixture.run,
        &fixture.claim,
        MANIFEST,
        &raw,
        digest,
    )
    .unwrap();
    assert!(readback_retained_receipt(
        &fixture.receipt,
        &fixture.run,
        &fixture.claim,
        MANIFEST,
        &"0".repeat(64),
        digest
    )
    .is_err());
}

#[tokio::test]
async fn candidate_and_ledger_drift_or_weak_permissions_refuse() {
    let fixture = Fixture::new(false).await;
    git_ok(&fixture.candidate, &["reset", "--hard", "HEAD~1"]);
    assert!(fixture.admit().is_err());
    let fixture = Fixture::new(false).await;
    std::fs::set_permissions(
        fixture.run.join("data/ledger.sqlite"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(fixture.admit().is_err());
    let fixture = Fixture::new(false).await;
    let ledger = fixture.run.join("data/ledger.sqlite");
    let replacement = fixture.run.join("data/replacement.sqlite");
    ledger_fixture::write_header(&replacement);
    std::fs::remove_file(&ledger).unwrap();
    std::os::unix::fs::symlink(&replacement, &ledger).unwrap();
    assert!(fixture.admit().is_err());
}

#[tokio::test]
async fn missing_integration_record_refuses_without_target_mutation() {
    let fixture = Fixture::new(false).await;
    let subject = fixture.value["local_forge"]["integration_subject_id"]
        .as_str()
        .unwrap();
    let state = fixture
        .forge
        .join("bullet-effects-v1/integrations")
        .join(format!("{subject}.json"));
    std::fs::remove_file(state).unwrap();
    let before = git_value(&fixture.forge, &["rev-parse", TARGET]);
    assert!(fixture.admit().is_err());
    assert_eq!(git_value(&fixture.forge, &["rev-parse", TARGET]), before);
}

#[tokio::test]
async fn hostile_git_read_is_deadline_bounded() {
    let fixture = Fixture::new(false).await;
    let head = fixture.source.join(".git/HEAD");
    std::fs::remove_file(&head).unwrap();
    assert!(Command::new("/usr/bin/mkfifo")
        .arg(&head)
        .status()
        .unwrap()
        .success());
    let started = Instant::now();
    assert!(fixture.admit().is_err());
    assert!(started.elapsed() < Duration::from_secs(4));
}

fn claim(seed: &str) -> CommandDispatchClaim {
    let request = CommandRequest::new(seed, "run_demo", &json!({})).unwrap();
    CommandDispatchClaim {
        schema_version: "bullet.command-dispatch-claim.v1".into(),
        claim_id: format!("dcl_{}", Digest::of(seed.as_bytes()).to_hex()),
        command_id: request.id(),
        outbox_sequence: 1,
        request_digest: request.digest(),
        request,
        runner_id: RunnerId::from_seed("worker"),
        runner_epoch: 1,
        authority_epoch: 1,
        freeze_generation: 0,
        restore_epoch: 0,
        disposition: CommandDispatchDisposition::Claimed,
        completion_digest: None,
        claimed_at: "2026-08-27T14:00:00.000Z".into(),
        updated_at: "2026-08-27T14:00:00.000Z".into(),
    }
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn git_ok(repo: &Path, args: &[&str]) {
    assert!(Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .unwrap()
        .success());
}
fn git_value(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn write_receipt(path: &Path, value: &Value, create: bool) {
    let mut options = OpenOptions::new();
    options.write(true).truncate(true).mode(0o600);
    if create {
        options.create_new(true);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}
