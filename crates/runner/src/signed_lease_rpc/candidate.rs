use super::SignedLeaseRpcClient;
use crate::error::RunnerError;
use async_trait::async_trait;
use bullet_application::candidate_preparation::CandidatePreparationSource;
use bullet_domain::AttemptId;
use bullet_harness_core::candidate_preparation::{
    candidate_preparation_envelope_digest, decode_signed_candidate_preparation_grant,
    SignedCandidatePreparationGrantV1,
};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "v1alpha1";
const SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

/// Current durable authority needed to construct one execution envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidatePreparationAuthority {
    authority_epoch: u64,
    freeze_generation: u64,
    now_unix_ms: u64,
    lease_expires_at_unix_ms: u64,
}

impl CandidatePreparationAuthority {
    /// Current Kernel authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Current freeze generation.
    #[must_use]
    pub const fn freeze_generation(&self) -> u64 {
        self.freeze_generation
    }

    /// Kernel database time at observation.
    #[must_use]
    pub const fn now_unix_ms(&self) -> u64 {
        self.now_unix_ms
    }

    /// Current lease expiry at observation.
    #[must_use]
    pub const fn lease_expires_at_unix_ms(&self) -> u64 {
        self.lease_expires_at_unix_ms
    }
}

/// One exact Candidate-preparation grant returned by Kernel authority.
#[derive(Clone, Debug, PartialEq)]
pub struct CandidatePreparationGrant {
    attempt_id: AttemptId,
    request_digest: String,
    candidate_preparation_grant_id: String,
    signed_grant_canonical_json: String,
    signed_grant: SignedCandidatePreparationGrantV1,
    envelope_digest: String,
}

impl CandidatePreparationGrant {
    #[cfg(test)]
    pub(crate) fn test_only(
        attempt_id: AttemptId,
        request_digest: String,
        candidate_preparation_grant_id: String,
        signed_grant_canonical_json: String,
        signed_grant: SignedCandidatePreparationGrantV1,
        envelope_digest: String,
    ) -> Self {
        Self {
            attempt_id,
            request_digest,
            candidate_preparation_grant_id,
            signed_grant_canonical_json,
            signed_grant,
            envelope_digest,
        }
    }

    /// Attempt incarnation bound by the authenticated Kernel response.
    #[must_use]
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }

    /// Digest of the pre-registered Candidate-preparation source.
    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Kernel-minted, full-width Candidate-preparation grant ID.
    #[must_use]
    pub fn candidate_preparation_grant_id(&self) -> &str {
        &self.candidate_preparation_grant_id
    }

    /// Canonical signed grant bytes exactly as returned by Kernel.
    #[must_use]
    pub fn signed_grant_canonical_json(&self) -> &str {
        &self.signed_grant_canonical_json
    }

    /// Strictly decoded signed grant carrier. This is not signature admission.
    #[must_use]
    pub fn signed_grant(&self) -> &SignedCandidatePreparationGrantV1 {
        &self.signed_grant
    }

    /// Domain-separated digest of the signed grant carrier.
    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

/// Candidate-preparation calls available on the admitted Runner workload RPC.
#[async_trait]
pub trait CandidatePreparationRpcClient: Send + Sync {
    /// Mint or replay the grant for one exact registered source subject.
    async fn candidate_prepare(
        &self,
        attempt_id: &AttemptId,
        request_digest: &str,
    ) -> Result<CandidatePreparationGrant, RunnerError>;

    /// Read back and compare every field of an already prepared grant.
    async fn candidate_readback(
        &self,
        expected: &CandidatePreparationGrant,
    ) -> Result<CandidatePreparationGrant, RunnerError>;
}

#[async_trait]
impl CandidatePreparationRpcClient for SignedLeaseRpcClient {
    async fn candidate_prepare(
        &self,
        attempt_id: &AttemptId,
        request_digest: &str,
    ) -> Result<CandidatePreparationGrant, RunnerError> {
        require_digest("request_digest", request_digest)?;
        let request = CandidateRequest {
            attempt_id: attempt_id.as_str(),
            request_digest,
        };
        let value: serde_json::Value = self.call("candidate_prepare", &request).await?;
        decode_response(value, attempt_id, request_digest)
    }

    async fn candidate_readback(
        &self,
        expected: &CandidatePreparationGrant,
    ) -> Result<CandidatePreparationGrant, RunnerError> {
        let request = CandidateRequest {
            attempt_id: expected.attempt_id.as_str(),
            request_digest: &expected.request_digest,
        };
        let value: serde_json::Value = self.call("candidate_readback", &request).await?;
        let observed = decode_response(value, &expected.attempt_id, &expected.request_digest)?;
        if observed != *expected {
            return Err(protocol(
                "Candidate-preparation readback differs from the prepared grant",
            ));
        }
        Ok(observed)
    }
}

impl SignedLeaseRpcClient {
    /// Read the active Attempt's current authority through the authenticated
    /// workload socket. This is observation only and grants no mutation.
    pub async fn candidate_preparation_authority(
        &self,
        attempt_id: &AttemptId,
    ) -> Result<CandidatePreparationAuthority, RunnerError> {
        let request = CandidateAuthorityRequest {
            attempt_id: attempt_id.as_str(),
        };
        let value: serde_json::Value = self.call("candidate_authority", &request).await?;
        let response: CandidateAuthorityResponse = serde_json::from_value(value)
            .map_err(|error| protocol(format!("strict Candidate authority response: {error}")))?;
        if response.schema_version != SCHEMA_VERSION || response.attempt_id != attempt_id.as_str() {
            return Err(protocol(
                "Candidate authority response differs from the requested Attempt",
            ));
        }
        let values = [
            response.authority_epoch,
            response.freeze_generation,
            response.now_unix_ms,
            response.lease_expires_at_unix_ms,
        ];
        if values.into_iter().any(|value| value > SAFE_INTEGER_MAX)
            || response.lease_expires_at_unix_ms <= response.now_unix_ms
        {
            return Err(protocol("Candidate authority response has invalid bounds"));
        }
        Ok(CandidatePreparationAuthority {
            authority_epoch: response.authority_epoch,
            freeze_generation: response.freeze_generation,
            now_unix_ms: response.now_unix_ms,
            lease_expires_at_unix_ms: response.lease_expires_at_unix_ms,
        })
    }

    /// Register exact canonical Candidate source bytes through farmd's sole
    /// SQLite writer connection.
    pub async fn register_candidate_preparation_source(
        &self,
        source: &CandidatePreparationSource,
    ) -> Result<String, RunnerError> {
        let expected = source
            .request_digest()
            .map_err(|error| protocol(format!("invalid Candidate source: {error}")))?;
        let request = CandidateRegisterRequest { source };
        let value: serde_json::Value = self.call("candidate_register", &request).await?;
        let response: CandidateRegisterResponse = serde_json::from_value(value)
            .map_err(|error| protocol(format!("strict Candidate register response: {error}")))?;
        if response.schema_version != SCHEMA_VERSION
            || response.attempt_id != source.attempt_id.as_str()
            || response.request_digest != expected
        {
            return Err(protocol(
                "Candidate register response differs from the canonical source",
            ));
        }
        Ok(response.request_digest)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateRequest<'a> {
    attempt_id: &'a str,
    request_digest: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateAuthorityRequest<'a> {
    attempt_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateAuthorityResponse {
    schema_version: String,
    attempt_id: String,
    authority_epoch: u64,
    freeze_generation: u64,
    now_unix_ms: u64,
    lease_expires_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateRegisterRequest<'a> {
    source: &'a CandidatePreparationSource,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRegisterResponse {
    schema_version: String,
    attempt_id: String,
    request_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateResponse {
    schema_version: String,
    request_digest: String,
    attempt_id: String,
    candidate_preparation_grant_id: String,
    signed_grant_canonical_json: String,
    envelope_digest: String,
}

fn decode_response(
    value: serde_json::Value,
    expected_attempt: &AttemptId,
    expected_digest: &str,
) -> Result<CandidatePreparationGrant, RunnerError> {
    let response: CandidateResponse = serde_json::from_value(value)
        .map_err(|error| protocol(format!("strict Candidate response: {error}")))?;
    if response.schema_version != SCHEMA_VERSION {
        return Err(protocol("Candidate response schema is not v1alpha1"));
    }
    require_digest("response request_digest", &response.request_digest)?;
    require_digest("response envelope_digest", &response.envelope_digest)?;
    require_id(
        "candidate_preparation_grant_id",
        &response.candidate_preparation_grant_id,
        "cpg",
    )?;
    if response.attempt_id != expected_attempt.as_str()
        || response.request_digest != expected_digest
    {
        return Err(protocol(
            "Candidate response differs from the requested Attempt/digest subject",
        ));
    }
    let signed_grant =
        decode_signed_candidate_preparation_grant(response.signed_grant_canonical_json.as_bytes())
            .map_err(|error| protocol(format!("invalid signed Candidate grant: {error}")))?;
    let computed_digest = candidate_preparation_envelope_digest(&signed_grant)
        .map_err(|error| protocol(format!("invalid Candidate envelope digest: {error}")))?;
    if computed_digest != response.envelope_digest {
        return Err(protocol(
            "Candidate response envelope digest does not bind the signed grant",
        ));
    }
    Ok(CandidatePreparationGrant {
        attempt_id: expected_attempt.clone(),
        request_digest: response.request_digest,
        candidate_preparation_grant_id: response.candidate_preparation_grant_id,
        signed_grant_canonical_json: response.signed_grant_canonical_json,
        signed_grant,
        envelope_digest: response.envelope_digest,
    })
}

fn require_id(name: &str, value: &str, prefix: &str) -> Result<(), RunnerError> {
    let Some(hex) = value.strip_prefix(&format!("{prefix}_")) else {
        return Err(protocol(format!("{name} has the wrong prefix")));
    };
    require_digest(name, hex)
}

fn require_digest(name: &str, value: &str) -> Result<(), RunnerError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(protocol(format!("{name} is not 64 lowercase hex")))
    }
}

fn protocol(reason: impl Into<String>) -> RunnerError {
    RunnerError::Protocol(reason.into())
}

#[cfg(test)]
mod tests;
