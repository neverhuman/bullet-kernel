use super::claims::candidate_preparation_envelope_digest;
use super::keys::CandidatePreparationVerificationKey;
use super::nonce::{CandidateNonceConsumption, CandidatePreparationNonceLedger};
use super::{CandidatePreparationGrantV1, SignedCandidatePreparationGrantV1};
use crate::error::HarnessError;

#[derive(Clone, Debug)]
pub struct CandidatePreparationExpectation {
    pub now_unix_ms: u64,
    pub expected_grant: CandidatePreparationGrantV1,
}

#[derive(Debug)]
#[must_use = "a verified Candidate-preparation grant must be consumed or dropped"]
pub struct VerifiedCandidatePreparationGrant {
    claims: CandidatePreparationGrantV1,
    envelope_digest: String,
}

impl VerifiedCandidatePreparationGrant {
    #[must_use]
    pub fn claims(&self) -> &CandidatePreparationGrantV1 {
        &self.claims
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub fn verify_candidate_preparation_grant(
    signed: &SignedCandidatePreparationGrantV1,
    key: &CandidatePreparationVerificationKey,
    expectation: &CandidatePreparationExpectation,
    nonces: &mut dyn CandidatePreparationNonceLedger,
) -> Result<VerifiedCandidatePreparationGrant, HarnessError> {
    let envelope_digest = candidate_preparation_envelope_digest(signed)?;
    let claims = key.authenticate(signed)?;
    if claims != expectation.expected_grant {
        return Err(HarnessError::CandidatePreparationSubjectMismatch);
    }
    if expectation.now_unix_ms < claims.not_before_unix_ms {
        return Err(HarnessError::CandidatePreparationNotYetValid {
            not_before_unix_ms: claims.not_before_unix_ms,
        });
    }
    if expectation.now_unix_ms >= claims.expires_at_unix_ms {
        return Err(HarnessError::CandidatePreparationExpired {
            expires_at_unix_ms: claims.expires_at_unix_ms,
        });
    }
    match nonces.consume_candidate_preparation_nonce(
        &claims.grant_nonce,
        &claims.attempt_id,
        expectation.now_unix_ms,
    )? {
        CandidateNonceConsumption::Consumed => Ok(VerifiedCandidatePreparationGrant {
            claims,
            envelope_digest,
        }),
        CandidateNonceConsumption::Replayed => Err(HarnessError::CandidatePreparationReplayed {
            grant_id: claims.candidate_preparation_grant_id,
        }),
        CandidateNonceConsumption::Expired => Err(HarnessError::CandidatePreparationExpired {
            expires_at_unix_ms: claims.expires_at_unix_ms,
        }),
        CandidateNonceConsumption::Unknown => Err(HarnessError::CandidatePreparationInvalid {
            reason: "grant nonce was never registered for this Attempt".to_owned(),
        }),
    }
}
