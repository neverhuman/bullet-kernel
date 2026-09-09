//! The effect broker: PROPOSED -> AUTHORIZED -> DISPATCHING ->
//! RECEIPT_PENDING -> VERIFIED -> COMMITTED, with the outbox row settled by
//! the read-back. A lost response lands in OUTCOME_UNKNOWN, and the only
//! way forward from there is [`reconcile`]: adopt what happened, retry once
//! when non-execution is proven, quarantine otherwise. No public API can
//! retry without reconciling first.

use crate::error::EffectsError;
use crate::forge::{is_create, require_candidate_ref, require_oid, ForgeEffects, PushRequest};
use bullet_application::{
    receipt_id, EffectIntentRecord, EffectReceiptRecord, EffectState, Ledger, ReceiptVerdict,
};
use bullet_domain::{AttemptId, AuthorityToken, CommandPhase, DomainError, EffectId};
use std::path::Path;

/// Verification method stamped on read-back receipts.
pub const READ_BACK_METHOD: &str = "git-ls-remote-read-back";

/// Input for a new effect proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentInput {
    /// Provider label, e.g. `local-bare` or `jeryu`.
    pub provider: String,
    /// Idempotency key, unique per provider.
    pub logical_effect_key: String,
    /// Target candidate ref.
    pub target_ref: String,
    /// New OID the ref must point at.
    pub new_oid: String,
    /// Expected current remote OID (`ZERO_OID` for create).
    pub expected_old_oid: String,
    /// Proposing attempt.
    pub attempt_id: AttemptId,
    /// Fence of that attempt.
    pub fence: u64,
    /// Policy snapshot label.
    pub policy_version: String,
    /// Provider-side idempotency key, when one exists.
    pub provider_idempotency_key: Option<String>,
}

/// Result of one reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The original effect happened; it was adopted as verified.
    Adopted,
    /// Non-execution was proven; the single permitted retry ran and landed
    /// in the contained state.
    Retried(EffectState),
    /// Remote truth contradicts the intent; the effect is quarantined.
    Quarantined,
}

fn load<L: Ledger>(ledger: &L, id: &EffectId) -> Result<EffectIntentRecord, EffectsError> {
    ledger.get_effect_intent_by_id(id)?.ok_or_else(|| {
        EffectsError::Ledger(bullet_application::LedgerError::Store(format!(
            "unknown effect intent {id}"
        )))
    })
}

fn mark<L: Ledger>(
    ledger: &mut L,
    seq: Option<u64>,
    phase: CommandPhase,
    now: &str,
) -> Result<(), EffectsError> {
    if let Some(seq) = seq {
        ledger.outbox_mark(seq, phase, now)?;
    }
    Ok(())
}

/// Record a `PROPOSED` intent. Replaying the same identity returns the
/// stored row; the ref namespace and OIDs are guarded before any row lands.
///
/// # Errors
///
/// `REF_DENIED`, `BAD_OID`, idempotency conflict, or store failure.
pub fn propose<L: Ledger>(
    ledger: &mut L,
    input: &IntentInput,
    now: &str,
) -> Result<(EffectIntentRecord, bool), EffectsError> {
    require_candidate_ref(&input.target_ref)?;
    require_oid("new_oid", &input.new_oid)?;
    require_oid("expected_old_oid", &input.expected_old_oid)?;
    let record = EffectIntentRecord {
        id: EffectId::from_seed(&format!("{}:{}", input.provider, input.logical_effect_key)),
        logical_effect_key: input.logical_effect_key.clone(),
        provider: input.provider.clone(),
        target_identity: input.target_ref.clone(),
        desired_state_hash: input.new_oid.clone(),
        expected_old_oid: input.expected_old_oid.clone(),
        attempt_id: input.attempt_id.clone(),
        fence: input.fence,
        policy_version: input.policy_version.clone(),
        payload_hash: String::new(),
        provider_idempotency_key: input.provider_idempotency_key.clone(),
        state: EffectState::Proposed,
        unknown_retries: 0,
        created_at: now.to_string(),
    };
    Ok(ledger.record_effect_intent(&record)?)
}

/// Authorize a proposed intent against a current fence: the token must name
/// the intent's attempt and fence, and the ledger's active lease must still
/// be held by exactly that attempt at that fence. Enqueues the dispatch
/// outbox row and returns its sequence.
///
/// # Errors
///
/// `STALE_AUTHORITY`, `INVALID_TRANSITION`, or store failure.
pub fn authorize<L: Ledger>(
    ledger: &mut L,
    id: &EffectId,
    token: &AuthorityToken,
    now: &str,
) -> Result<(EffectIntentRecord, u64), EffectsError> {
    let row = load(ledger, id)?;
    token
        .verify(&row.attempt_id, row.fence)
        .map_err(bullet_application::LedgerError::Domain)?;
    let lease = ledger.get_lease(&token.variant_id)?.ok_or_else(|| {
        EffectsError::Ledger(
            DomainError::StaleAuthority(format!(
                "no active lease for variant {}",
                token.variant_id
            ))
            .into(),
        )
    })?;
    if lease.attempt_id != token.attempt_id || lease.fence != token.attempt_fence {
        return Err(EffectsError::Ledger(
            DomainError::StaleAuthority(format!(
                "lease held by {} at fence {}, not {} at fence {}",
                lease.attempt_id, lease.fence, token.attempt_id, token.attempt_fence
            ))
            .into(),
        ));
    }
    let updated = ledger.transition_effect(id, EffectState::Authorized)?;
    let payload = serde_json::to_string(&updated)
        .map_err(|err| EffectsError::Io(format!("encode outbox payload: {err}")))?;
    let seq = ledger.outbox_enqueue("effect_dispatch", &payload)?;
    let _ = now;
    Ok((updated, seq))
}

fn settle_read_back<L: Ledger>(
    ledger: &mut L,
    row: &EffectIntentRecord,
    observed: Option<String>,
    adopted_after_unknown: bool,
    outbox_seq: Option<u64>,
    now: &str,
) -> Result<EffectState, EffectsError> {
    let verdict = match observed.as_deref() {
        Some(value) if value == row.desired_state_hash => ReceiptVerdict::Match,
        Some(_) => ReceiptVerdict::Mismatch,
        None => ReceiptVerdict::Absent,
    };
    let receipt = EffectReceiptRecord {
        id: receipt_id(&format!(
            "{}:{}:{}:{now}",
            row.id,
            verdict.as_str(),
            adopted_after_unknown
        )),
        effect_intent_id: row.id.clone(),
        observed_remote_identity: row.target_identity.clone(),
        observed_state_hash: observed,
        verification_method: READ_BACK_METHOD.into(),
        verification_result: verdict,
        adopted_after_unknown,
        recorded_at: now.to_string(),
    };
    ledger.record_effect_receipt(&receipt)?;
    if verdict == ReceiptVerdict::Match {
        ledger.transition_effect(&row.id, EffectState::Verified)?;
        let updated = ledger.transition_effect(&row.id, EffectState::Committed)?;
        mark(ledger, outbox_seq, CommandPhase::Verified, now)?;
        Ok(updated.state)
    } else {
        let updated = ledger.transition_effect(&row.id, EffectState::Quarantined)?;
        mark(ledger, outbox_seq, CommandPhase::Unknown, now)?;
        Ok(updated.state)
    }
}

fn push_and_settle<L: Ledger, F: ForgeEffects>(
    ledger: &mut L,
    forge: &mut F,
    row: &EffectIntentRecord,
    workspace_repo: &Path,
    outbox_seq: Option<u64>,
    now: &str,
) -> Result<EffectState, EffectsError> {
    let request = PushRequest {
        workspace_repo: workspace_repo.to_path_buf(),
        ref_name: row.target_identity.clone(),
        expected_old_oid: row.expected_old_oid.clone(),
        new_oid: row.desired_state_hash.clone(),
    };
    match forge.push_candidate_ref(&request) {
        Ok(()) => {
            ledger.transition_effect(&row.id, EffectState::ReceiptPending)?;
            let observed = forge.read_ref(&row.target_identity)?;
            settle_read_back(ledger, row, observed, false, outbox_seq, now)
        }
        Err(EffectsError::ResponseLost(_)) => {
            let updated = ledger.transition_effect(&row.id, EffectState::OutcomeUnknown)?;
            mark(ledger, outbox_seq, CommandPhase::Unknown, now)?;
            Ok(updated.state)
        }
        Err(EffectsError::PushRejected { observed, .. }) => {
            let receipt = EffectReceiptRecord {
                id: receipt_id(&format!("{}:rejected:{now}", row.id)),
                effect_intent_id: row.id.clone(),
                observed_remote_identity: row.target_identity.clone(),
                observed_state_hash: observed.clone(),
                verification_method: READ_BACK_METHOD.into(),
                verification_result: if observed.is_some() {
                    ReceiptVerdict::Mismatch
                } else {
                    ReceiptVerdict::Absent
                },
                adopted_after_unknown: false,
                recorded_at: now.to_string(),
            };
            ledger.record_effect_receipt(&receipt)?;
            let updated = ledger.transition_effect(&row.id, EffectState::Quarantined)?;
            mark(ledger, outbox_seq, CommandPhase::Unknown, now)?;
            Ok(updated.state)
        }
        Err(other) => Err(other),
    }
}

/// Dispatch an `AUTHORIZED` intent: push, then verify by read-back. An
/// `OUTCOME_UNKNOWN` intent is refused with `RETRY_WITHOUT_RECONCILE` —
/// [`reconcile`] is the only path forward from unknown.
///
/// # Errors
///
/// Typed phase refusals, forge failures, or store failure.
pub fn dispatch<L: Ledger, F: ForgeEffects>(
    ledger: &mut L,
    forge: &mut F,
    id: &EffectId,
    workspace_repo: &Path,
    outbox_seq: Option<u64>,
    now: &str,
) -> Result<EffectState, EffectsError> {
    let row = load(ledger, id)?;
    if row.state == EffectState::OutcomeUnknown {
        return Err(EffectsError::RetryWithoutReconcile(id.to_string()));
    }
    if row.state != EffectState::Authorized {
        return Err(EffectsError::IllegalPhase {
            found: row.state.as_str().into(),
            wanted: EffectState::Authorized.as_str().into(),
        });
    }
    let row = ledger.transition_effect(id, EffectState::Dispatching)?;
    mark(ledger, outbox_seq, CommandPhase::Applied, now)?;
    push_and_settle(ledger, forge, &row, workspace_repo, outbox_seq, now)
}

/// Reconcile an `OUTCOME_UNKNOWN` intent by reading authoritative remote
/// state (spec section 23.2): adopt the original effect if it occurred,
/// retry exactly once when non-execution is proven, quarantine otherwise.
///
/// # Errors
///
/// Typed phase refusals, forge failures, or store failure.
pub fn reconcile<L: Ledger, F: ForgeEffects>(
    ledger: &mut L,
    forge: &mut F,
    id: &EffectId,
    workspace_repo: &Path,
    outbox_seq: Option<u64>,
    now: &str,
) -> Result<ReconcileOutcome, EffectsError> {
    let row = load(ledger, id)?;
    if row.state != EffectState::OutcomeUnknown {
        return Err(EffectsError::IllegalPhase {
            found: row.state.as_str().into(),
            wanted: EffectState::OutcomeUnknown.as_str().into(),
        });
    }
    let observed = forge.read_ref(&row.target_identity)?;
    if observed.as_deref() == Some(row.desired_state_hash.as_str()) {
        settle_read_back(ledger, &row, observed, true, outbox_seq, now)?;
        return Ok(ReconcileOutcome::Adopted);
    }
    let non_execution = if is_create(&row.expected_old_oid) {
        observed.is_none()
    } else {
        observed.as_deref() == Some(row.expected_old_oid.as_str())
    };
    if non_execution && row.unknown_retries == 0 {
        let retried = ledger.transition_effect(id, EffectState::Dispatching)?;
        let state = push_and_settle(ledger, forge, &retried, workspace_repo, outbox_seq, now)?;
        return Ok(ReconcileOutcome::Retried(state));
    }
    // Either the remote moved to a third value, or the single permitted
    // retry is already spent: contain it.
    settle_read_back(ledger, &row, observed, false, outbox_seq, now)?;
    Ok(ReconcileOutcome::Quarantined)
}
