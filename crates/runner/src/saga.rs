//! Named production saga stages. A missing grant or unavailable authority
//! contract cannot become PASS.

use crate::error::RunnerError;

/// Ordered saga stages from acquire through exact Candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SagaStage {
    /// Writer lease acquire.
    Acquire,
    /// Read-only provider turn.
    ReadOnlyProvider,
    /// Checkpoint-bound patch proposal.
    PatchProposal,
    /// gitd apply.
    GitdApply,
    /// Admitted gates.
    AdmittedGates,
    /// At most two repairs.
    Repair,
    /// Workspace checkpoint.
    Checkpoint,
    /// Exact Candidate.
    ExactCandidate,
}

/// Drive the saga only after a grant exists and gitd authority is available.
///
/// # Errors
///
/// `LEASE_REFUSED` when `granted` is false.
/// `AUTHORITY_CONTRACT_UNAVAILABLE` when production gitd cannot validate a
/// frozen contract.
pub fn require_saga_admission(granted: bool, authority_available: bool) -> Result<(), RunnerError> {
    if !granted {
        return Err(RunnerError::Lease {
            code: "LEASE_REFUSED".into(),
            message: "saga requires a signed grant".into(),
        });
    }
    if !authority_available {
        return Err(RunnerError::AuthorityContractUnavailable {
            method: "saga".into(),
            message: "production gitd has no frozen authority contract".into(),
        });
    }
    Ok(())
}

/// Stages in ADR 0001 order.
#[must_use]
pub fn stages() -> [SagaStage; 8] {
    [
        SagaStage::Acquire,
        SagaStage::ReadOnlyProvider,
        SagaStage::PatchProposal,
        SagaStage::GitdApply,
        SagaStage::AdmittedGates,
        SagaStage::Repair,
        SagaStage::Checkpoint,
        SagaStage::ExactCandidate,
    ]
}
