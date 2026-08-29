//! Test-only signed Candidate authority for Runner loop simulations.

use super::super::AttemptConfig;
use crate::signed_lease_rpc::{CandidatePreparationGrant, CandidatePreparationRpcClient};
use crate::{
    AcquireGrant, AcquireRequest, CandidatePreparationAdmission, DirectLeaseClient, HeartbeatCall,
    LeaseClient, ReadyView, ReleaseCall, RunnerError,
};
use async_trait::async_trait;
use bullet_application::MemoryLedger;
use bullet_domain::{AttemptId, AttemptState, Digest};
use bullet_harness_core::candidate_preparation::{
    candidate_preparation_envelope_digest, candidate_preparation_scope_paths_digest,
    canonical_candidate_preparation_json, CandidatePreparationGrantV1,
    CandidatePreparationSigningKey,
};
use std::sync::{Arc, Mutex};

pub(super) struct TestCandidateClient {
    inner: DirectLeaseClient<MemoryLedger>,
    signer: CandidatePreparationSigningKey,
    request_digest: String,
    grant: Mutex<Option<AcquireGrant>>,
    prepared: Mutex<Option<CandidatePreparationGrant>>,
    scope_digest: Mutex<Option<String>>,
}

impl TestCandidateClient {
    pub(super) fn new(ledger: Arc<Mutex<MemoryLedger>>) -> Self {
        Self {
            inner: DirectLeaseClient::new(ledger),
            signer: CandidatePreparationSigningKey::generate(
                "kernel-local",
                "candidate-preparation-1",
            )
            .expect("test Candidate signing key"),
            request_digest: Digest::of(b"TEST_ONLY:CandidatePreparationSource").to_hex(),
            grant: Mutex::new(None),
            prepared: Mutex::new(None),
            scope_digest: Mutex::new(None),
        }
    }

    pub(super) fn admit_config(&self, config: AttemptConfig) -> AttemptConfig {
        *self.scope_digest.lock().expect("test Candidate scope lock") = Some(
            candidate_preparation_scope_paths_digest(&config.scope_prefixes)
                .expect("test Candidate scope digest"),
        );
        let admission = CandidatePreparationAdmission::from_verification_key(
            self.request_digest.clone(),
            self.signer
                .verification_key()
                .expect("test Candidate public key"),
        )
        .expect("test Candidate admission");
        config.with_candidate_preparation(admission)
    }

    fn current_grant(&self, attempt_id: &AttemptId) -> Result<AcquireGrant, RunnerError> {
        let grant = self
            .grant
            .lock()
            .map_err(|_| RunnerError::Protocol("test Candidate grant lock poisoned".into()))?
            .clone()
            .ok_or_else(|| RunnerError::Protocol("test Candidate grant absent".into()))?;
        if grant.attempt.id != *attempt_id {
            return Err(RunnerError::Protocol(
                "test Candidate Attempt differs from acquire".into(),
            ));
        }
        Ok(grant)
    }
}

#[async_trait]
impl CandidatePreparationRpcClient for TestCandidateClient {
    async fn candidate_prepare(
        &self,
        attempt_id: &AttemptId,
        request_digest: &str,
    ) -> Result<CandidatePreparationGrant, RunnerError> {
        if request_digest != self.request_digest {
            return Err(RunnerError::Protocol(
                "test Candidate source digest mismatch".into(),
            ));
        }
        if let Some(prepared) = self
            .prepared
            .lock()
            .map_err(|_| RunnerError::Protocol("test Candidate response lock poisoned".into()))?
            .as_ref()
        {
            return Ok(prepared.clone());
        }
        let grant = self.current_grant(attempt_id)?;
        let token = &grant.authority_token;
        let seed = Digest::of(grant.attempt.id.as_str().as_bytes()).to_hex();
        let scope_grant_digest = self
            .scope_digest
            .lock()
            .map_err(|_| RunnerError::Protocol("test Candidate scope lock poisoned".into()))?
            .clone()
            .ok_or_else(|| RunnerError::Protocol("test Candidate scope absent".into()))?;
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
        let claims = CandidatePreparationGrantV1 {
            schema_version: "v1alpha1".into(),
            candidate_preparation_grant_id: format!("cpg_{seed}"),
            issuer: "kernel-local".into(),
            key_id: "candidate-preparation-1".into(),
            signing_purpose: "candidate-preparation-grant-signing".into(),
            claims_domain: "candidate-preparation.grant.v1alpha1".into(),
            envelope_domain: "candidate-preparation.envelope.v1alpha1".into(),
            request_digest: self.request_digest.clone(),
            authority_token_digest: token
                .digest()
                .map_err(|error| RunnerError::Protocol(format!("test authority digest: {error}")))?
                .to_hex(),
            grant_nonce: Digest::of(format!("nonce:{seed}").as_bytes()).to_hex(),
            repository_id: token.repository_id.to_string(),
            mission_id: token.mission_id.to_string(),
            plan_revision_id: token.plan_revision_id.to_string(),
            work_package_id: token.work_package_id.to_string(),
            variant_id: token.variant_id.to_string(),
            attempt_id: token.attempt_id.to_string(),
            attempt_fence: token.attempt_fence,
            runner_id: token.runner_id.to_string(),
            runner_epoch: token.runner_epoch,
            workspace_id: token.workspace_id.to_string(),
            scope_grant_digest,
            scope_revision: token.scope_revision,
            context_revision: token.context_revision,
            change_id: format!("chg_{seed}"),
            graph_revision_id: format!("grf_{seed}"),
            parent_candidate_ids: vec![],
            context_capsule_id: format!("cnt_{seed}"),
            execution_envelope_id: format!("exe_{seed}"),
            environment_digest: Digest::of(format!("environment:{seed}").as_bytes()).to_hex(),
            toolchain_digest: Digest::of(format!("toolchain:{seed}").as_bytes()).to_hex(),
            authority_epoch: 1,
            freeze_generation: 0,
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 10_000,
        };
        let signed = self.signer.sign(&claims)?;
        let canonical = canonical_candidate_preparation_json(&signed)?;
        let canonical = String::from_utf8(canonical)
            .map_err(|error| RunnerError::Protocol(error.to_string()))?;
        let envelope_digest = candidate_preparation_envelope_digest(&signed)?;
        let prepared = CandidatePreparationGrant::test_only(
            attempt_id.clone(),
            self.request_digest.clone(),
            claims.candidate_preparation_grant_id,
            canonical,
            signed,
            envelope_digest,
        );
        *self
            .prepared
            .lock()
            .map_err(|_| RunnerError::Protocol("test Candidate response lock poisoned".into()))? =
            Some(prepared.clone());
        Ok(prepared)
    }

    async fn candidate_readback(
        &self,
        expected: &CandidatePreparationGrant,
    ) -> Result<CandidatePreparationGrant, RunnerError> {
        let prepared = self
            .prepared
            .lock()
            .map_err(|_| RunnerError::Protocol("test Candidate response lock poisoned".into()))?
            .clone()
            .ok_or_else(|| RunnerError::Protocol("test Candidate response absent".into()))?;
        if &prepared != expected {
            return Err(RunnerError::Protocol(
                "test Candidate read-back subject drift".into(),
            ));
        }
        Ok(prepared)
    }
}

#[async_trait]
impl LeaseClient for TestCandidateClient {
    fn candidate_preparation_rpc(&self) -> Option<&dyn CandidatePreparationRpcClient> {
        Some(self)
    }

    async fn acquire(&self, request: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
        let grant = self.inner.acquire(request).await?;
        *self
            .grant
            .lock()
            .map_err(|_| RunnerError::Protocol("test Candidate grant lock poisoned".into()))? =
            Some(grant.clone());
        *self
            .prepared
            .lock()
            .map_err(|_| RunnerError::Protocol("test Candidate response lock poisoned".into()))? =
            None;
        Ok(grant)
    }

    async fn heartbeat(&self, call: &HeartbeatCall) -> Result<(), RunnerError> {
        self.inner.heartbeat(call).await
    }

    async fn advance(
        &self,
        attempt_id: &AttemptId,
        state: AttemptState,
    ) -> Result<(), RunnerError> {
        self.inner.advance(attempt_id, state).await
    }

    async fn release(&self, call: &ReleaseCall) -> Result<(), RunnerError> {
        self.inner.release(call).await
    }

    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
        self.inner.next_ready().await
    }
}
