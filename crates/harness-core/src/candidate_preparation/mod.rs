//! Purpose-separated PASETO v4.public custody for Candidate-preparation grants.
//!
//! This module authenticates one exact generated wire record against durable
//! expected truth. It does not derive Change, parent, or execution-envelope
//! authority and cannot mint those missing product subjects.

mod canonical;
mod claims;
mod execution;
mod keys;
mod nonce;
mod scope;
mod verify;

pub use bullet_domain::schema_bundle::{
    CandidatePreparationGrantV1, ExecutionEnvelopeV1, ExecutionToolV1,
    SignedCandidatePreparationGrantV1,
};
pub use canonical::canonical_candidate_preparation_json;
pub use claims::{
    candidate_preparation_envelope_digest, decode_signed_candidate_preparation_grant,
    validate_candidate_preparation_grant, CANDIDATE_PREPARATION_CLAIMS_DOMAIN,
    CANDIDATE_PREPARATION_ENVELOPE_DOMAIN, CANDIDATE_PREPARATION_IMPLICIT_ASSERTION,
    CANDIDATE_PREPARATION_SIGNING_PURPOSE,
};
pub use execution::{
    execution_envelope_digest, execution_toolchain_digest, validate_candidate_preparation_binding,
    validate_execution_envelope,
};
pub use keys::{
    authenticate_candidate_preparation_grant, CandidatePreparationSigningKey,
    CandidatePreparationVerificationKey,
};
pub use nonce::{
    CandidateNonceConsumption, CandidatePreparationNonceLedger,
    MemoryCandidatePreparationNonceLedger,
};
pub use scope::candidate_preparation_scope_paths_digest;
pub use verify::{
    verify_candidate_preparation_grant, CandidatePreparationExpectation,
    VerifiedCandidatePreparationGrant,
};
