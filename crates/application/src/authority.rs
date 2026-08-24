//! Durable lease checks used as a prerequisite to online authority issuance.
//! A successful check is only an observation; it never grants mutation authority.

use bullet_domain::{
    Attempt, AttemptId, DomainError, RunnerId, VariantId, WorkPackageId, WorkspaceId,
};
use chrono::DateTime;

use crate::{ActiveLease, LedgerError};

/// Exact durable subject that must still own the active writer lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveLeaseSubject {
    /// Variant whose single writer is being checked.
    pub variant_id: VariantId,
    /// Attempt incarnation expected to own the lease.
    pub attempt_id: AttemptId,
    /// Work package whose writer the Attempt represents.
    pub work_package_id: WorkPackageId,
    /// Permanent fence expected on both Attempt and lease.
    pub fence: u64,
    /// Runner expected to own the lease.
    pub runner_id: RunnerId,
    /// Runner incarnation expected to own the lease.
    pub runner_epoch: u64,
    /// Private workspace bound to the Attempt.
    pub workspace_id: WorkspaceId,
    /// Workspace nonce bound to both Attempt and lease.
    pub workspace_nonce: [u8; 32],
    /// Scope revision bound to the Attempt.
    pub scope_revision: u64,
    /// Context revision bound to the Attempt.
    pub context_revision: u64,
}

impl ActiveLeaseSubject {
    /// Build the exact subject persisted for an Attempt incarnation.
    #[must_use]
    pub fn from_attempt(attempt: &Attempt) -> Self {
        Self {
            variant_id: attempt.variant_id.clone(),
            attempt_id: attempt.id.clone(),
            work_package_id: attempt.work_package_id.clone(),
            fence: attempt.fence,
            runner_id: attempt.runner_id.clone(),
            runner_epoch: attempt.runner_epoch,
            workspace_id: attempt.workspace_id.clone(),
            workspace_nonce: attempt.workspace_nonce,
            scope_revision: attempt.scope_revision,
            context_revision: attempt.context_revision,
        }
    }
}

/// Validate one coherent persisted lease/Attempt snapshot at authoritative time.
///
/// This function is public for durable adapters that must invoke it inside the
/// same transaction that will later reserve a mutation. `Ok(())` is deliberately
/// not a capability and must never be carried across a transaction boundary as
/// authorization.
pub fn check_active_lease_snapshot(
    lease: &ActiveLease,
    attempt: &Attempt,
    subject: &ActiveLeaseSubject,
    authoritative_now: &str,
) -> Result<(), LedgerError> {
    let heartbeat = DateTime::parse_from_rfc3339(&lease.heartbeat_at)
        .map_err(|_| LedgerError::Store("corrupt active lease heartbeat".into()))?;
    let expires = DateTime::parse_from_rfc3339(&lease.expires_at)
        .map_err(|_| LedgerError::Store("corrupt active lease expiry".into()))?;
    let now = DateTime::parse_from_rfc3339(authoritative_now)
        .map_err(|_| LedgerError::Store("invalid authority-store time".into()))?;
    if heartbeat > now || heartbeat >= expires {
        return Err(LedgerError::Store(
            "corrupt active lease time window".into(),
        ));
    }
    if expires <= now
        || !attempt.state.permits_online_lease_check()
        || lease.variant_id != subject.variant_id
        || lease.attempt_id != subject.attempt_id
        || lease.fence != subject.fence
        || lease.runner_id != subject.runner_id
        || lease.runner_epoch != subject.runner_epoch
        || lease.workspace_nonce != subject.workspace_nonce
        || attempt.variant_id != subject.variant_id
        || attempt.id != subject.attempt_id
        || attempt.work_package_id != subject.work_package_id
        || attempt.fence != subject.fence
        || attempt.runner_id != subject.runner_id
        || attempt.runner_epoch != subject.runner_epoch
        || attempt.workspace_id != subject.workspace_id
        || attempt.workspace_nonce != subject.workspace_nonce
        || attempt.scope_revision != subject.scope_revision
        || attempt.context_revision != subject.context_revision
    {
        return Err(DomainError::StaleAuthority(format!(
            "active lease does not match Attempt {} fence {}",
            subject.attempt_id, subject.fence
        ))
        .into());
    }
    Ok(())
}
