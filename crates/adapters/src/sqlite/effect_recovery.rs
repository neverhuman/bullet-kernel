//! Durable restart recovery for local-bare create-only Candidate refs.

mod read;
mod storage;
mod transitions;

use crate::sqlite::SqliteLedger;
use bullet_application::{
    EffectRecoveryAuthority, EffectRecoveryClaim, EffectRecoveryContainmentReason,
    EffectRecoveryDisposition, EffectRecoveryError, EffectRecoveryStore, EffectRecoveryTransition,
    LedgerError,
};
use bullet_domain::{DomainError, EffectId, EffectReceiptId, WorkPackageId};

pub(super) const OUTBOX_KIND: &str = "effect_recovery";
pub(super) const CLAIMED_EVENT: &str = "effect_recovery_claimed";
pub(super) const TRANSITION_EVENT: &str = "effect_recovery_transition";
pub(super) const NORMALIZED_EVENT: &str = "effect_recovery_normalized";
pub(super) const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug)]
pub(super) struct CurrentAuthority {
    pub graph_revision: u64,
    pub workspace_generation: u64,
    pub scope_digest: String,
    pub policy_generation: u64,
    pub routing_generation: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
    pub restore_epoch: u64,
}

#[derive(Clone, Debug)]
pub(super) struct StoredClaim {
    pub claim: EffectRecoveryClaim,
    pub receipt_id: Option<EffectReceiptId>,
    pub containment_reason: Option<EffectRecoveryContainmentReason>,
    pub work_package_id: WorkPackageId,
    pub graph_revision: u64,
    pub workspace_generation: u64,
    pub scope_digest: String,
    pub policy_generation: u64,
    pub routing_generation: u64,
}

impl EffectRecoveryStore for SqliteLedger {
    fn claim_effect_recovery(
        &mut self,
        intent_id: &EffectId,
        authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
        read::claim(
            &mut self.conn,
            &mut self.effect_recovery_claim_fail_after,
            intent_id,
            authority,
        )
    }

    fn readback_effect_recovery(
        &self,
        intent_id: &EffectId,
        authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
        read::readback(&self.conn, intent_id, authority)
    }

    fn apply_effect_recovery(
        &mut self,
        request: &EffectRecoveryTransition,
        authority: &EffectRecoveryAuthority,
    ) -> Result<EffectRecoveryClaim, EffectRecoveryError> {
        transitions::apply(
            &mut self.conn,
            &mut self.effect_recovery_apply_fail_after,
            request,
            authority,
        )
    }
}

pub(super) fn owner_matches(
    claim: &EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
) -> Result<bool, EffectRecoveryError> {
    Ok(claim.recovery_runner_id == authority.runner_id
        && claim.recovery_runner_epoch == authority.runner_epoch
        && claim.recovery_attempt_id == authority.attempt_id
        && claim.recovery_attempt_fence == authority.attempt_fence
        && claim.recovery_variant_id == authority.variant_id
        && claim.recovery_workspace_id == authority.workspace_id
        && claim.recovery_workspace_nonce == authority.workspace_nonce
        && claim.successor_authority_digest == authority.successor_authority_digest
        && claim.authority_epoch == authority.authority_epoch
        && claim.freeze_generation == authority.freeze_generation
        && claim.restore_epoch == authority.restore_epoch
        && claim.successor_authority_fingerprint == authority.fingerprint()?)
}

pub(super) fn disposition_from(
    text: &str,
) -> Result<EffectRecoveryDisposition, EffectRecoveryError> {
    use EffectRecoveryDisposition as D;
    match text {
        "CLAIMED" => Ok(D::Claimed),
        "RETRY_RESERVED" => Ok(D::RetryReserved),
        "READBACK_UNKNOWN" => Ok(D::ReadbackUnknown),
        "ADOPTED" => Ok(D::Adopted),
        "ORPHANED" => Ok(D::Orphaned),
        "QUARANTINED" => Ok(D::Quarantined),
        "INVALIDATED" => Ok(D::Invalidated),
        other => Err(recovery_store(format!(
            "unknown recovery disposition {other}"
        ))),
    }
}

pub(super) fn reason_from(
    text: &str,
) -> Result<EffectRecoveryContainmentReason, EffectRecoveryError> {
    use EffectRecoveryContainmentReason as R;
    match text {
        "RETRY_SPENT_AFTER_ABSENCE" => Ok(R::RetrySpentAfterAbsence),
        "READBACK_UNAVAILABLE" => Ok(R::ReadbackUnavailable),
        other => Err(recovery_store(format!("unknown recovery reason {other}"))),
    }
}

pub(super) fn reason_str(reason: EffectRecoveryContainmentReason) -> &'static str {
    use EffectRecoveryContainmentReason as R;
    match reason {
        R::RetrySpentAfterAbsence => "RETRY_SPENT_AFTER_ABSENCE",
        R::ReadbackUnavailable => "READBACK_UNAVAILABLE",
    }
}

pub(super) fn to_i64(value: u64) -> Result<i64, EffectRecoveryError> {
    if value > MAX_SAFE {
        return Err(EffectRecoveryError::InvalidClaim(
            "safe integer exceeded".into(),
        ));
    }
    i64::try_from(value).map_err(recovery_store)
}

pub(super) fn u64_from(value: i64) -> Result<u64, EffectRecoveryError> {
    u64::try_from(value).map_err(recovery_store)
}

pub(super) fn require_one(changed: usize, detail: &str) -> Result<(), EffectRecoveryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(recovery_store(detail))
    }
}

pub(super) fn fail_boundary(
    fail_after: &mut Option<u8>,
    label: &str,
) -> Result<(), EffectRecoveryError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(recovery_store(format!(
                "injected effect recovery {label} boundary"
            )))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

pub(super) fn recovery_ledger(error: LedgerError) -> EffectRecoveryError {
    match error {
        LedgerError::Domain(DomainError::StaleAuthority(message)) => {
            EffectRecoveryError::StaleAuthority(message)
        }
        LedgerError::Domain(DomainError::InvalidTransition { from, to }) => {
            EffectRecoveryError::InvalidTransition { from, to }
        }
        LedgerError::Domain(DomainError::Encoding(message)) => {
            EffectRecoveryError::Encoding(message)
        }
        other => recovery_store(other),
    }
}

pub(super) fn recovery_domain(error: DomainError) -> EffectRecoveryError {
    recovery_ledger(LedgerError::Domain(error))
}

pub(super) fn recovery_store(error: impl ToString) -> EffectRecoveryError {
    EffectRecoveryError::Store(error.to_string())
}
