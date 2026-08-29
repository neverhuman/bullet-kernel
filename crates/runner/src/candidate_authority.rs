//! Independent Candidate-preparation key admission and exact Attempt binding.

mod keyfile;

use crate::error::RunnerError;
use crate::lease::AcquireGrant;
use crate::signed_lease_rpc::CandidatePreparationGrant;
use bullet_harness_core::{
    authenticate_candidate_preparation_grant, candidate_preparation_scope_paths_digest,
    CandidatePreparationGrantV1, CandidatePreparationVerificationKey, HarnessError,
    SignedCandidatePreparationGrantV1,
};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Exact source digest and independently pinned verification key for one Attempt run.
#[derive(Clone, Debug)]
pub struct CandidatePreparationAdmission {
    request_digest: String,
    verification_key: CandidatePreparationVerificationKey,
    consumed_nonces: Arc<Mutex<BTreeSet<String>>>,
}

impl CandidatePreparationAdmission {
    /// Load the frozen public-key record from protected local custody.
    pub fn from_key_file(
        request_digest: impl Into<String>,
        path: &Path,
    ) -> Result<Self, RunnerError> {
        let request_digest = request_digest.into();
        require_hex("candidate request digest", &request_digest)?;
        Ok(Self {
            request_digest,
            verification_key: keyfile::load(path)?,
            consumed_nonces: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_verification_key(
        request_digest: impl Into<String>,
        verification_key: CandidatePreparationVerificationKey,
    ) -> Result<Self, RunnerError> {
        let request_digest = request_digest.into();
        require_hex("candidate request digest", &request_digest)?;
        Ok(Self {
            request_digest,
            verification_key,
            consumed_nonces: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    /// Exact registered source digest sent to Kernel authority.
    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub(crate) fn verify(
        &self,
        response: &CandidatePreparationGrant,
        grant: &AcquireGrant,
        granted_scope: &[String],
    ) -> Result<VerifiedCandidatePreparation, RunnerError> {
        self.verify_at(response, grant, granted_scope, now_unix_ms()?)
    }

    fn verify_at(
        &self,
        response: &CandidatePreparationGrant,
        grant: &AcquireGrant,
        granted_scope: &[String],
        now_unix_ms: u64,
    ) -> Result<VerifiedCandidatePreparation, RunnerError> {
        let claims = authenticate_candidate_preparation_grant(
            response.signed_grant(),
            &self.verification_key,
        )?;
        require_subject(
            &claims,
            response,
            grant,
            &self.request_digest,
            granted_scope,
        )?;
        if now_unix_ms < claims.not_before_unix_ms {
            return Err(HarnessError::CandidatePreparationNotYetValid {
                not_before_unix_ms: claims.not_before_unix_ms,
            }
            .into());
        }
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(HarnessError::CandidatePreparationExpired {
                expires_at_unix_ms: claims.expires_at_unix_ms,
            }
            .into());
        }
        let mut consumed = self.consumed_nonces.lock().map_err(|_| RunnerError::Io {
            context: "Candidate-preparation replay ledger".into(),
            reason: "poisoned".into(),
        })?;
        if !consumed.insert(claims.grant_nonce.clone()) {
            return Err(HarnessError::CandidatePreparationReplayed {
                grant_id: claims.candidate_preparation_grant_id,
            }
            .into());
        }
        Ok(VerifiedCandidatePreparation {
            claims,
            signed: response.signed_grant().clone(),
        })
    }
}

/// Authenticated claims and their exact signed carrier.
#[derive(Debug)]
pub(crate) struct VerifiedCandidatePreparation {
    claims: CandidatePreparationGrantV1,
    signed: SignedCandidatePreparationGrantV1,
}

impl VerifiedCandidatePreparation {
    pub(crate) fn claims(&self) -> &CandidatePreparationGrantV1 {
        &self.claims
    }

    pub(crate) fn signed(&self) -> &SignedCandidatePreparationGrantV1 {
        &self.signed
    }
}

fn require_subject(
    claims: &CandidatePreparationGrantV1,
    response: &CandidatePreparationGrant,
    grant: &AcquireGrant,
    expected_request_digest: &str,
    granted_scope: &[String],
) -> Result<(), RunnerError> {
    let attempt = &grant.attempt;
    let token = &grant.authority_token;
    let lease = &grant.lease;
    let authority_token_digest = token
        .digest()
        .map_err(|error| RunnerError::Protocol(format!("authority token digest: {error}")))?
        .to_hex();
    let scope_grant_digest = candidate_preparation_scope_paths_digest(granted_scope)?;
    let coherent = token.verify(&attempt.id, attempt.fence).is_ok()
        && response.attempt_id() == &attempt.id
        && response.request_digest() == expected_request_digest
        && response.candidate_preparation_grant_id() == claims.candidate_preparation_grant_id
        && claims.request_digest == expected_request_digest
        && claims.authority_token_digest == authority_token_digest
        && claims.scope_grant_digest == scope_grant_digest
        && claims.repository_id == token.repository_id.as_str()
        && claims.mission_id == token.mission_id.as_str()
        && claims.plan_revision_id == token.plan_revision_id.as_str()
        && claims.work_package_id == attempt.work_package_id.as_str()
        && claims.work_package_id == token.work_package_id.as_str()
        && claims.variant_id == attempt.variant_id.as_str()
        && claims.variant_id == token.variant_id.as_str()
        && claims.variant_id == lease.variant_id.as_str()
        && claims.attempt_id == attempt.id.as_str()
        && claims.attempt_id == token.attempt_id.as_str()
        && claims.attempt_id == lease.attempt_id.as_str()
        && claims.attempt_fence == attempt.fence
        && claims.attempt_fence == token.attempt_fence
        && claims.attempt_fence == lease.fence
        && claims.runner_id == attempt.runner_id.as_str()
        && claims.runner_id == token.runner_id.as_str()
        && claims.runner_id == lease.runner_id.as_str()
        && claims.runner_epoch == attempt.runner_epoch
        && claims.runner_epoch == token.runner_epoch
        && claims.runner_epoch == lease.runner_epoch
        && claims.workspace_id == attempt.workspace_id.as_str()
        && claims.workspace_id == token.workspace_id.as_str()
        && attempt.workspace_nonce == token.workspace_nonce
        && attempt.workspace_nonce == lease.workspace_nonce
        && claims.scope_revision == attempt.scope_revision
        && claims.scope_revision == token.scope_revision
        && claims.context_revision == attempt.context_revision
        && claims.context_revision == token.context_revision;
    if coherent {
        Ok(())
    } else {
        Err(HarnessError::CandidatePreparationSubjectMismatch.into())
    }
}

fn require_hex(field: &str, value: &str) -> Result<(), RunnerError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid(format!("{field} must be 64 lowercase hex")))
    }
}

fn now_unix_ms() -> Result<u64, RunnerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| invalid(format!("system clock precedes Unix epoch: {error}")))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| invalid("system clock exceeds the supported millisecond range"))
}

fn invalid(reason: impl Into<String>) -> RunnerError {
    HarnessError::CandidatePreparationInvalid {
        reason: reason.into(),
    }
    .into()
}

#[cfg(test)]
pub(crate) mod tests;
