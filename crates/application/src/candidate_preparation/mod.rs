//! Durable Candidate-preparation preregistration, issuance, and nonce ports.
//!
//! No public transport is wired to the preregistration port. Until immutable
//! Change, parent, and execution-envelope producers exist, this remains a
//! component substrate and Runner preparation must refuse.

mod issuer;
mod model;
mod nonce;
mod store;

pub use bullet_harness_core::candidate_preparation::{
    canonical_candidate_preparation_json, execution_toolchain_digest,
    verify_candidate_preparation_grant, CandidateNonceConsumption, CandidatePreparationExpectation,
    CandidatePreparationGrantV1, CandidatePreparationSigningKey,
    CandidatePreparationVerificationKey, ExecutionEnvelopeV1, ExecutionToolV1,
    SignedCandidatePreparationGrantV1,
};
pub use issuer::{CandidatePreparationIssuer, LedgerCandidatePreparationIssuer};
pub use model::{
    CandidatePreparationAuthoritySnapshot, CandidatePreparationSource,
    PreparedCandidatePreparationGrant, RegisteredCandidatePreparationSource,
    StoredCandidatePreparationGrant,
};
pub use nonce::{
    CandidatePreparationFinalCheckStore, CandidatePreparationNonceStore,
    StoreCandidatePreparationNonceLedger,
};
pub use store::{CandidatePreparationStore, CandidatePreparationTransaction};

use crate::LedgerError;
use bullet_harness_core::HarnessError;

#[derive(Debug, thiserror::Error)]
pub enum CandidatePreparationError {
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Harness(#[from] HarnessError),
    #[error("Candidate-preparation source is absent")]
    SourceMissing,
    #[error("Candidate-preparation conflict: {0}")]
    Conflict(String),
    #[error("Candidate-preparation refused: {0}")]
    Refused(String),
}

impl CandidatePreparationError {
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Ledger(error) => error.reason_code(),
            Self::Harness(error) => error.reason_code(),
            Self::SourceMissing => "CANDIDATE_PREPARATION_SOURCE_MISSING",
            Self::Conflict(_) => "CANDIDATE_PREPARATION_CONFLICT",
            Self::Refused(_) => "CANDIDATE_PREPARATION_REFUSED",
        }
    }
}
