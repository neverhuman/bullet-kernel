use super::*;
use crate::candidate_authority::{tests::acquire_grant, CandidatePreparationAdmission};
use crate::gitd::ActiveGenerationBinding;
use crate::lease::{AcquireRequest, DirectLeaseClient, HeartbeatCall, ReadyView, ReleaseCall};
use crate::signed_lease_rpc::{CandidatePreparationGrant, CandidatePreparationRpcClient};
use async_trait::async_trait;
use bullet_application::MemoryLedger;
use bullet_domain::{AttemptId, AttemptState};
use bullet_harness_core::{CandidatePreparationSigningKey, SignedCandidatePreparationGrantV1};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct DriftClient {
    prepared: CandidatePreparationGrant,
    readback: CandidatePreparationGrant,
}

fn opaque_grant(attempt_id: &AttemptId, seed: char) -> CandidatePreparationGrant {
    let signed = SignedCandidatePreparationGrantV1 {
        schema_version: "v1alpha1".into(),
        issuer: "kernel-local".into(),
        key_id: "candidate-preparation-1".into(),
        paseto: format!("v4.public.test-{seed}"),
    };
    CandidatePreparationGrant::test_only(
        attempt_id.clone(),
        "a".repeat(64),
        format!("cpg_{}", seed.to_string().repeat(64)),
        serde_json::to_string(&signed).unwrap(),
        signed,
        seed.to_string().repeat(64),
    )
}

#[async_trait]
impl CandidatePreparationRpcClient for DriftClient {
    async fn candidate_prepare(
        &self,
        _attempt_id: &AttemptId,
        _request_digest: &str,
    ) -> Result<CandidatePreparationGrant, RunnerError> {
        Ok(self.prepared.clone())
    }

    async fn candidate_readback(
        &self,
        _expected: &CandidatePreparationGrant,
    ) -> Result<CandidatePreparationGrant, RunnerError> {
        Ok(self.readback.clone())
    }
}

#[async_trait]
impl LeaseClient for DriftClient {
    fn candidate_preparation_rpc(&self) -> Option<&dyn CandidatePreparationRpcClient> {
        Some(self)
    }

    async fn acquire(&self, _request: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
        Err(RunnerError::Protocol("not exercised".into()))
    }

    async fn heartbeat(&self, _call: &HeartbeatCall) -> Result<(), RunnerError> {
        Err(RunnerError::Protocol("not exercised".into()))
    }

    async fn advance(
        &self,
        _attempt_id: &AttemptId,
        _state: AttemptState,
    ) -> Result<(), RunnerError> {
        Err(RunnerError::Protocol("not exercised".into()))
    }

    async fn release(&self, _call: &ReleaseCall) -> Result<(), RunnerError> {
        Err(RunnerError::Protocol("not exercised".into()))
    }

    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
        Err(RunnerError::Protocol("not exercised".into()))
    }
}

fn subjects(grant: &AcquireGrant) -> (WorkspaceInfo, CheckpointBinding) {
    let active = ActiveGenerationBinding::test_only(
        &grant.authority_token,
        0,
        None,
        "candidate-drive",
        "sha1:1111111111111111111111111111111111111111",
    );
    let checkpoint = CheckpointBinding {
        id: active.checkpoint.id.clone(),
        digest: active.checkpoint.digest.clone(),
    };
    (
        WorkspaceInfo {
            repo_dir: PathBuf::from("/not-observed/repository"),
            runtime_dir: PathBuf::from("/not-observed/runtime"),
            branch: "bullet/test/candidate".into(),
            base_sha: "sha1:1111111111111111111111111111111111111111".into(),
            base_checkpoint_id: checkpoint.id.clone(),
            base_checkpoint_digest: checkpoint.digest.clone(),
            active_generation: active,
        },
        checkpoint,
    )
}

fn config() -> AttemptConfig {
    AttemptConfig::new(
        PathBuf::from("/not-observed/source"),
        "1111111111111111111111111111111111111111".into(),
        PathBuf::from("/not-observed/workspace"),
        "candidate drive refusal".into(),
        vec!["src".into()],
        vec!["gate".into()],
    )
}

#[tokio::test]
async fn missing_candidate_admission_refuses_before_rpc() {
    let grant = acquire_grant();
    let (mut workspace, checkpoint) = subjects(&grant);
    workspace.base_checkpoint_id = "ckp_stale_initial_subject".into();
    workspace.base_checkpoint_digest = "stale_initial_subject".into();
    assert_eq!(current_checkpoint(&workspace), checkpoint);
    let client = DirectLeaseClient::new(Arc::new(Mutex::new(MemoryLedger::new())));
    let error = prepare_request(&client, &grant, &config(), &workspace, &checkpoint)
        .await
        .expect_err("missing Candidate admission");
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    assert!(error.to_string().contains("not admitted"));
}

#[tokio::test]
async fn admitted_key_never_falls_back_to_a_non_candidate_transport() {
    let grant = acquire_grant();
    let (workspace, checkpoint) = subjects(&grant);
    let client = DirectLeaseClient::new(Arc::new(Mutex::new(MemoryLedger::new())));
    let signer =
        CandidatePreparationSigningKey::generate("kernel-local", "candidate-preparation-1")
            .unwrap();
    let admission = CandidatePreparationAdmission::from_verification_key(
        "a".repeat(64),
        signer.verification_key().unwrap(),
    )
    .unwrap();
    let error = prepare_request(
        &client,
        &grant,
        &config().with_candidate_preparation(admission),
        &workspace,
        &checkpoint,
    )
    .await
    .expect_err("non-Candidate transport");
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    assert!(error.to_string().contains("no peer-authenticated"));

    let drift = DriftClient {
        prepared: opaque_grant(&grant.attempt.id, '1'),
        readback: opaque_grant(&grant.attempt.id, '2'),
    };
    let signer =
        CandidatePreparationSigningKey::generate("kernel-local", "candidate-preparation-1")
            .unwrap();
    let admission = CandidatePreparationAdmission::from_verification_key(
        "a".repeat(64),
        signer.verification_key().unwrap(),
    )
    .unwrap();
    let error = prepare_request(
        &drift,
        &grant,
        &config().with_candidate_preparation(admission),
        &workspace,
        &checkpoint,
    )
    .await
    .expect_err("drifted Candidate readback");
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    assert!(error.to_string().contains("readback differs"));
}
