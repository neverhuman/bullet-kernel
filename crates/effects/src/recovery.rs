//! Restart-safe reconciliation for local-bare create-only candidate delivery.
//!
//! The application store owns claims, retry accounting, receipts, and all
//! durable transitions. This executor only turns authoritative forge
//! readbacks into those closed application transitions.

use crate::forge::{ForgeEffects, PushRequest};
use bullet_application::{
    EffectRecoveryAuthority, EffectRecoveryClaim, EffectRecoveryContainmentReason,
    EffectRecoveryDisposition, EffectRecoveryError, EffectRecoveryObservation, EffectRecoveryStore,
    EffectRecoveryTransition, ReceiptVerdict, LOCAL_BARE_RECOVERY_PROVIDER,
};
use bullet_domain::EffectId;
use std::path::Path;
use thiserror::Error;

/// Result of one restart reconciliation pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartReconcileOutcome {
    /// The store had no recoverable active claim for this authority.
    NoWork,
    /// A readback proved the desired candidate ref exists.
    Adopted,
    /// A readback proved a different candidate ref value exists.
    OrphanedRemote,
    /// Readback or the reserved retry response was ambiguous.
    ReadbackUnknown,
    /// The sole retry was spent, or a second readback was unavailable.
    Quarantined,
}

/// Refusal before a recovery pass can prove a terminal outcome.
#[derive(Debug, Error)]
pub enum RestartRecoveryError {
    /// The application contract rejected a claim, transition, or store call.
    #[error(transparent)]
    Recovery(#[from] EffectRecoveryError),
    /// The selected forge is not the exact local-bare write capability.
    #[error("restart recovery requires an authenticated local-bare candidate forge: {0}")]
    UnsupportedForge(String),
}

impl RestartRecoveryError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Recovery(error) => error.reason_code(),
            Self::UnsupportedForge(_) => "RECOVERY_FORGE_UNSUPPORTED",
        }
    }
}

/// Reconcile one durable local-bare recovery claim after process restart.
///
/// A successful reservation never creates a second retry: every invocation
/// reads the ref first, and an existing `RETRY_RESERVED` claim is revalidated
/// immediately before its single create-only push.
pub fn reconcile_local_bare_restart<S, F>(
    store: &mut S,
    forge: &mut F,
    intent_id: &EffectId,
    authority: &EffectRecoveryAuthority,
    workspace_repo: &Path,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
    F: ForgeEffects,
{
    let Some(claim) = store.claim_effect_recovery(intent_id, authority)? else {
        return Ok(RestartReconcileOutcome::NoWork);
    };
    claim.validate_readback(intent_id, authority)?;
    require_local_bare_forge(forge)?;
    match forge.read_ref(&claim.intent.target_identity) {
        Ok(observed) => resolve_readback(store, forge, claim, authority, workspace_repo, observed),
        Err(_error) => record_unavailable_readback(store, claim, authority),
    }
}

fn resolve_readback<S, F>(
    store: &mut S,
    forge: &mut F,
    claim: EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
    workspace_repo: &Path,
    observed: Option<String>,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
    F: ForgeEffects,
{
    match observed {
        Some(oid) => settle_observed(store, claim, authority, Some(oid)),
        None => resolve_absence(store, forge, claim, authority, workspace_repo),
    }
}

fn resolve_absence<S, F>(
    store: &mut S,
    forge: &mut F,
    claim: EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
    workspace_repo: &Path,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
    F: ForgeEffects,
{
    match claim.disposition {
        EffectRecoveryDisposition::Claimed => {
            let reserved = transition(
                store,
                &claim,
                authority,
                EffectRecoveryDisposition::RetryReserved,
                Some(observation(&claim, None)),
                None,
            )?;
            execute_reserved_retry(store, forge, reserved, authority, workspace_repo)
        }
        EffectRecoveryDisposition::RetryReserved => {
            execute_reserved_retry(store, forge, claim, authority, workspace_repo)
        }
        EffectRecoveryDisposition::ReadbackUnknown if claim.intent.unknown_retries == 0 => {
            let reserved = transition(
                store,
                &claim,
                authority,
                EffectRecoveryDisposition::RetryReserved,
                Some(observation(&claim, None)),
                None,
            )?;
            execute_reserved_retry(store, forge, reserved, authority, workspace_repo)
        }
        EffectRecoveryDisposition::ReadbackUnknown => {
            let absent = observation(&claim, None);
            settle_quarantine(
                store,
                claim,
                authority,
                Some(absent),
                EffectRecoveryContainmentReason::RetrySpentAfterAbsence,
            )
        }
        disposition => Err(EffectRecoveryError::InvalidClaim(format!(
            "active recovery readback has unsupported disposition {}",
            disposition.as_str()
        ))
        .into()),
    }
}

fn execute_reserved_retry<S, F>(
    store: &mut S,
    forge: &mut F,
    reserved: EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
    workspace_repo: &Path,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
    F: ForgeEffects,
{
    let absent = observation(&reserved, None);
    reserved.validate_reserved_retry(authority, &absent)?;
    let current = store
        .readback_effect_recovery(&reserved.intent.id, authority)?
        .ok_or(EffectRecoveryError::UnknownClaim)?;
    if current.claim_id != reserved.claim_id
        || current.claim_generation != reserved.claim_generation
    {
        return Err(EffectRecoveryError::ClaimConflict(
            "recovery claim changed before reserved retry".into(),
        )
        .into());
    }
    current.validate_reserved_retry(authority, &absent)?;
    require_local_bare_forge(forge)?;
    let request = PushRequest {
        workspace_repo: workspace_repo.to_path_buf(),
        ref_name: current.intent.target_identity.clone(),
        expected_old_oid: current.intent.expected_old_oid.clone(),
        new_oid: current.intent.desired_state_hash.clone(),
    };
    // A rejected-push observation is explicitly best-effort, not a receipt;
    // preserve ambiguity until a later authoritative `read_ref` resolves it.
    if forge.push_candidate_ref(&request).is_err() {
        return record_unknown(store, current, authority);
    }
    let unknown = transition(
        store,
        &current,
        authority,
        EffectRecoveryDisposition::ReadbackUnknown,
        None,
        None,
    )?;
    match forge.read_ref(&request.ref_name) {
        Ok(observed) => {
            resolve_readback(store, forge, unknown, authority, workspace_repo, observed)
        }
        Err(_error) => record_unavailable_readback(store, unknown, authority),
    }
}

fn require_local_bare_forge<F: ForgeEffects>(forge: &F) -> Result<(), RestartRecoveryError> {
    let descriptor = forge.descriptor();
    if descriptor.provider != LOCAL_BARE_RECOVERY_PROVIDER
        || !descriptor.authenticated
        || !descriptor.can_push_candidate_ref
    {
        return Err(RestartRecoveryError::UnsupportedForge(descriptor.notes));
    }
    Ok(())
}

fn settle_observed<S>(
    store: &mut S,
    claim: EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
    observed: Option<String>,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
{
    let observation = observation(&claim, observed);
    let outcome = match observation.verdict {
        ReceiptVerdict::Match => RestartReconcileOutcome::Adopted,
        ReceiptVerdict::Mismatch => RestartReconcileOutcome::OrphanedRemote,
        ReceiptVerdict::Absent => unreachable!("absence is dispatched separately"),
    };
    let disposition = match outcome {
        RestartReconcileOutcome::Adopted => EffectRecoveryDisposition::Adopted,
        RestartReconcileOutcome::OrphanedRemote => EffectRecoveryDisposition::Orphaned,
        _ => unreachable!("only terminal observed outcomes reach this branch"),
    };
    let terminal = transition(
        store,
        &claim,
        authority,
        disposition,
        Some(observation),
        None,
    )?;
    terminal.validate()?;
    Ok(outcome)
}

fn record_unavailable_readback<S>(
    store: &mut S,
    claim: EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
{
    if claim.disposition == EffectRecoveryDisposition::ReadbackUnknown {
        return settle_quarantine(
            store,
            claim,
            authority,
            None,
            EffectRecoveryContainmentReason::ReadbackUnavailable,
        );
    }
    record_unknown(store, claim, authority)
}

fn record_unknown<S>(
    store: &mut S,
    claim: EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
{
    transition(
        store,
        &claim,
        authority,
        EffectRecoveryDisposition::ReadbackUnknown,
        None,
        None,
    )?;
    Ok(RestartReconcileOutcome::ReadbackUnknown)
}

fn settle_quarantine<S>(
    store: &mut S,
    claim: EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
    observation: Option<EffectRecoveryObservation>,
    reason: EffectRecoveryContainmentReason,
) -> Result<RestartReconcileOutcome, RestartRecoveryError>
where
    S: EffectRecoveryStore,
{
    let terminal = transition(
        store,
        &claim,
        authority,
        EffectRecoveryDisposition::Quarantined,
        observation,
        Some(reason),
    )?;
    terminal.validate()?;
    Ok(RestartReconcileOutcome::Quarantined)
}

fn transition<S>(
    store: &mut S,
    claim: &EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
    disposition: EffectRecoveryDisposition,
    observation: Option<EffectRecoveryObservation>,
    reason: Option<EffectRecoveryContainmentReason>,
) -> Result<EffectRecoveryClaim, RestartRecoveryError>
where
    S: EffectRecoveryStore,
{
    let request =
        EffectRecoveryTransition::new(claim, authority, disposition, observation, reason)?;
    Ok(store.apply_effect_recovery(&request, authority)?)
}

fn observation(claim: &EffectRecoveryClaim, observed: Option<String>) -> EffectRecoveryObservation {
    let verdict = match observed.as_deref() {
        Some(oid) if oid == claim.intent.desired_state_hash => ReceiptVerdict::Match,
        Some(_) => ReceiptVerdict::Mismatch,
        None => ReceiptVerdict::Absent,
    };
    EffectRecoveryObservation {
        provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
        remote_identity: claim.intent.target_identity.clone(),
        observed_state_hash: observed,
        verification_method: EffectRecoveryObservation::METHOD.into(),
        verdict,
    }
}
