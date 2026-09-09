//! Restart reconciliation contract for local-bare create-only Candidate refs.
//!
//! This module defines application state and a persistence port. It performs
//! no Git, filesystem, clock, or SQL work.

use crate::effects::{recovery_receipt_id, EffectIntentRecord, ReceiptVerdict, ZERO_OID};
use bullet_domain::{
    AttemptId, Digest, EffectId, EffectReceiptId, RunnerId, VariantId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod validation;

/// Exact recovery-authority wire discriminator.
pub const EFFECT_RECOVERY_AUTHORITY_SCHEMA: &str = "bullet.effect-recovery-authority.v1";
/// Exact durable recovery-claim wire discriminator.
pub const EFFECT_RECOVERY_CLAIM_SCHEMA: &str = "bullet.effect-recovery-claim.v1";
/// Exact recovery-transition wire discriminator.
pub const EFFECT_RECOVERY_TRANSITION_SCHEMA: &str = "bullet.effect-recovery-transition.v1";
/// The only provider admitted by this restart packet.
pub const LOCAL_BARE_RECOVERY_PROVIDER: &str = "local-bare";
/// The only destination namespace admitted by this restart packet.
pub const CANDIDATE_REF_PREFIX: &str = "refs/heads/bullet/candidate/";
/// One create retry after authoritative absence; never a blind retry.
pub const MAX_CREATE_RECOVERY_RETRIES: u32 = 1;

/// Durable recovery position. `UNRESOLVED` is the pre-claim normalized state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectRecoveryDisposition {
    /// An unresolved effect has been normalized but not claimed.
    Unresolved,
    /// One exact successor authority owns readback.
    Claimed,
    /// Authoritative absence reserved the sole create-only retry.
    RetryReserved,
    /// Authoritative readback itself did not return a verdict.
    ReadbackUnknown,
    /// The desired ref was observed and adopted.
    Adopted,
    /// A different remote value was observed and left untouched.
    Orphaned,
    /// Recovery was contained without another external mutation.
    Quarantined,
    /// The owning successor authority ceased to be current.
    Invalidated,
}

/// Closed reason for containment without an authoritative terminal verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectRecoveryContainmentReason {
    /// The reserved retry was spent and a later readback still saw absence.
    RetrySpentAfterAbsence,
    /// Authoritative readback remained unavailable, so no retry is allowed.
    ReadbackUnavailable,
}

impl EffectRecoveryDisposition {
    /// Apply one legal recovery edge.
    pub fn transition(self, to: Self) -> Result<Self, EffectRecoveryError> {
        use EffectRecoveryDisposition::{
            Adopted, Claimed, Invalidated, Orphaned, Quarantined, ReadbackUnknown, RetryReserved,
            Unresolved,
        };
        match (self, to) {
            (Unresolved, Claimed)
            | (
                Claimed | RetryReserved | ReadbackUnknown,
                Adopted | Orphaned | Quarantined | Invalidated,
            )
            | (Claimed | RetryReserved, ReadbackUnknown)
            | (Claimed | ReadbackUnknown, RetryReserved) => Ok(to),
            _ => Err(EffectRecoveryError::InvalidTransition {
                from: self.as_str().into(),
                to: to.as_str().into(),
            }),
        }
    }

    /// Whether one claim still excludes all other owners for its intent.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Claimed | Self::RetryReserved | Self::ReadbackUnknown
        )
    }

    /// Stable storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unresolved => "UNRESOLVED",
            Self::Claimed => "CLAIMED",
            Self::RetryReserved => "RETRY_RESERVED",
            Self::ReadbackUnknown => "READBACK_UNKNOWN",
            Self::Adopted => "ADOPTED",
            Self::Orphaned => "ORPHANED",
            Self::Quarantined => "QUARANTINED",
            Self::Invalidated => "INVALIDATED",
        }
    }

    /// Complete catalog for exhaustive edge tests.
    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::Unresolved,
            Self::Claimed,
            Self::RetryReserved,
            Self::ReadbackUnknown,
            Self::Adopted,
            Self::Orphaned,
            Self::Quarantined,
            Self::Invalidated,
        ]
    }
}

/// Current successor authority, projected from one exact `AuthorityToken`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecoveryAuthority {
    /// Exact wire discriminator.
    pub schema_version: String,
    /// Digest of the complete successor token.
    pub successor_authority_digest: Digest,
    /// Successor Runner.
    pub runner_id: RunnerId,
    /// Successor Runner incarnation.
    pub runner_epoch: u64,
    /// Successor Attempt.
    pub attempt_id: AttemptId,
    /// Successor permanent fence.
    pub attempt_fence: u64,
    /// Variant whose current active lease grants recovery.
    pub variant_id: VariantId,
    /// Successor private workspace.
    pub workspace_id: WorkspaceId,
    /// Successor workspace incarnation nonce.
    pub workspace_nonce: [u8; 32],
    /// Current Kernel authority epoch.
    pub authority_epoch: u64,
    /// Current freeze generation.
    pub freeze_generation: u64,
    /// Current restore epoch.
    pub restore_epoch: u64,
}

/// One database-authored recovery claim over an exact immutable intent row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecoveryClaim {
    /// Exact wire discriminator.
    pub schema_version: String,
    /// Full-width `ecl_` claim identity.
    pub claim_id: String,
    /// Exact intent snapshot normalized for recovery.
    pub intent: EffectIntentRecord,
    /// Typed digest of the intent's stable payload.
    pub intent_payload_digest: Digest,
    /// Original author Attempt.
    pub original_attempt_id: AttemptId,
    /// Original author fence.
    pub original_fence: u64,
    /// Complete successor token digest.
    pub successor_authority_digest: Digest,
    /// Successor authority-and-epoch fingerprint.
    pub successor_authority_fingerprint: Digest,
    /// Successor Runner.
    pub recovery_runner_id: RunnerId,
    /// Successor Runner incarnation.
    pub recovery_runner_epoch: u64,
    /// Successor Attempt.
    pub recovery_attempt_id: AttemptId,
    /// Successor fence.
    pub recovery_attempt_fence: u64,
    /// Variant shared by the original and recovery Attempts.
    pub recovery_variant_id: VariantId,
    /// Successor private workspace.
    pub recovery_workspace_id: WorkspaceId,
    /// Successor workspace incarnation nonce.
    pub recovery_workspace_nonce: [u8; 32],
    /// Authority epoch at claim.
    pub authority_epoch: u64,
    /// Freeze generation at claim.
    pub freeze_generation: u64,
    /// Restore epoch at claim.
    pub restore_epoch: u64,
    /// Monotonic per-intent claim generation.
    pub claim_generation: u64,
    /// Exact correlated effect outbox sequence.
    pub outbox_sequence: u64,
    /// Current recovery disposition.
    pub disposition: EffectRecoveryDisposition,
    /// Active phase retained when this ownership claim is invalidated.
    pub invalidated_from: Option<EffectRecoveryDisposition>,
    /// First database-owned claim time.
    pub claimed_at: String,
    /// Last database-owned transition time.
    pub updated_at: String,
}

impl EffectRecoveryClaim {
    /// Rebind the embedded snapshot to the exact currently persisted intent.
    pub fn validate_persisted_intent(
        &self,
        persisted: &EffectIntentRecord,
    ) -> Result<(), EffectRecoveryError> {
        self.validate()?;
        if self.intent != *persisted {
            return Err(EffectRecoveryError::SubjectMismatch(
                "claim intent differs from current durable intent".into(),
            ));
        }
        Ok(())
    }

    /// Admit execution of an already-reserved retry after restart readback.
    /// This consumes no second reservation and performs no state transition.
    pub fn validate_reserved_retry(
        &self,
        authority: &EffectRecoveryAuthority,
        observation: &EffectRecoveryObservation,
    ) -> Result<(), EffectRecoveryError> {
        self.validate_readback(&self.intent.id, authority)?;
        observation.validate_for(&self.intent)?;
        if self.disposition != EffectRecoveryDisposition::RetryReserved
            || self.intent.unknown_retries != MAX_CREATE_RECOVERY_RETRIES
            || observation.verdict != ReceiptVerdict::Absent
        {
            return Err(EffectRecoveryError::InvalidTransition {
                from: self.disposition.as_str().into(),
                to: EffectRecoveryDisposition::RetryReserved.as_str().into(),
            });
        }
        Ok(())
    }

    pub(super) fn disposition_state_is_valid(&self) -> bool {
        use crate::EffectState::{
            Committed, Dispatching, OrphanedRemote, OutcomeUnknown, Quarantined,
        };
        use EffectRecoveryDisposition::{
            Adopted, Claimed, Invalidated, Orphaned, Quarantined as RecoveryQuarantined,
            ReadbackUnknown, RetryReserved, Unresolved,
        };
        let active_matches = |phase| match phase {
            Claimed => self.intent.state == OutcomeUnknown && self.intent.unknown_retries == 0,
            RetryReserved => {
                matches!(self.intent.state, Dispatching | OutcomeUnknown)
                    && self.intent.unknown_retries == MAX_CREATE_RECOVERY_RETRIES
            }
            ReadbackUnknown => {
                self.intent.state == OutcomeUnknown
                    && self.intent.unknown_retries <= MAX_CREATE_RECOVERY_RETRIES
            }
            _ => false,
        };
        match self.disposition {
            Claimed | RetryReserved | ReadbackUnknown => {
                self.invalidated_from.is_none() && active_matches(self.disposition)
            }
            Invalidated => self.invalidated_from.is_some_and(active_matches),
            Adopted => self.invalidated_from.is_none() && self.intent.state == Committed,
            Orphaned => self.invalidated_from.is_none() && self.intent.state == OrphanedRemote,
            RecoveryQuarantined => {
                self.invalidated_from.is_none() && self.intent.state == Quarantined
            }
            Unresolved => false,
        }
    }
}

/// Canonical local-bare readback with no caller-controlled timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecoveryObservation {
    /// Provider that performed readback.
    pub provider: String,
    /// Exact ref read back.
    pub remote_identity: String,
    /// Exact observed OID, or authoritative absence.
    pub observed_state_hash: Option<String>,
    /// Closed verification method.
    pub verification_method: String,
    /// Canonical verdict.
    pub verdict: ReceiptVerdict,
}

/// Caller-authored transition proposal; persistence supplies ordering and time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecoveryTransition {
    /// Exact wire discriminator.
    pub schema_version: String,
    /// Exact active claim.
    pub claim_id: String,
    /// Exact optimistic claim generation.
    pub claim_generation: u64,
    /// Exact owning authority fingerprint.
    pub authority_fingerprint: Digest,
    /// Expected current disposition.
    pub from: EffectRecoveryDisposition,
    /// Requested next disposition.
    pub to: EffectRecoveryDisposition,
    /// Canonical readback, absent only when no verdict exists.
    pub observation: Option<EffectRecoveryObservation>,
    /// Closed predicate for a quarantine transition.
    pub containment_reason: Option<EffectRecoveryContainmentReason>,
    /// Deterministic receipt identity when an observation exists.
    pub receipt_id: Option<EffectReceiptId>,
}

/// Persistence boundary for one SQLite-authoritative recovery implementation.
pub trait EffectRecoveryStore {
    /// Atomically normalize and claim one exact unresolved intent.
    ///
    /// The store proves the original Attempt and successor token name the same
    /// Variant and that the successor owns its current active lease. It also
    /// revalidates epochs, payload, provider, create precondition, state, and
    /// budget. It owns claim id/generation, outbox sequence, and timestamps.
    /// The same current owner gets byte-exact replay. A different owner
    /// conflicts while the old owner is current; otherwise the store
    /// atomically invalidates the stale claim and issues the next generation,
    /// inheriting `RetryReserved` or `ReadbackUnknown` exactly. It compares
    /// the loaded intent through `validate_persisted_intent` before replay or
    /// replacement.
    fn claim_effect_recovery(
        &mut self,
        intent_id: &EffectId,
        authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError>;

    /// Read back only this exact active owner/intent claim without mutation.
    fn readback_effect_recovery(
        &self,
        intent_id: &EffectId,
        authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError>;

    /// Atomically apply one validated edge with intent/outbox/event/receipt.
    ///
    /// The store re-reads current authority and exact claim correlation.
    /// Entering `RetryReserved` atomically changes the normalized intent from
    /// `OUTCOME_UNKNOWN` to `DISPATCHING`, increments the retry exactly once,
    /// and marks the exact outbox before any push. Restart normalizes that
    /// in-flight state and reads back first: absence may execute the already
    /// reserved retry without another increment; `ReadbackUnknown` plus spent
    /// budget and absence quarantines and never pushes. Observation receipts
    /// use `request.receipt_id` and a database-owned timestamp. Invalidating
    /// an owner sets `invalidated_from` to its exact active disposition before
    /// issuing any successor claim.
    fn apply_effect_recovery(
        &mut self,
        request: &EffectRecoveryTransition,
        authority: &EffectRecoveryAuthority,
    ) -> Result<EffectRecoveryClaim, EffectRecoveryError>;
}

/// Typed restart-reconciliation refusal.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EffectRecoveryError {
    /// Durable store failed closed.
    #[error("effect recovery store: {0}")]
    Store(String),
    /// Claim bytes or database-owned fields are malformed.
    #[error("invalid effect recovery claim: {0}")]
    InvalidClaim(String),
    /// Successor authority projection is malformed.
    #[error("invalid effect recovery authority: {0}")]
    InvalidAuthority(String),
    /// An immutable subject was substituted.
    #[error("effect recovery subject mismatch: {0}")]
    SubjectMismatch(String),
    /// Intent is outside the local create-only recovery scope.
    #[error("unsupported effect recovery intent: {0}")]
    UnsupportedIntent(String),
    /// Current token, lease, or epoch moved.
    #[error("stale effect recovery authority: {0}")]
    StaleAuthority(String),
    /// Authority fingerprint was painted or corrupted.
    #[error("effect recovery authority fingerprint mismatch")]
    FingerprintMismatch,
    /// Another incarnation already owns the intent.
    #[error("effect recovery claim conflict: {0}")]
    ClaimConflict(String),
    /// No active exact-owner claim exists.
    #[error("unknown effect recovery claim")]
    UnknownClaim,
    /// The sole create retry was already consumed.
    #[error("effect recovery retry budget exhausted")]
    RetryBudgetExhausted,
    /// Recovery state edge is outside the closed table.
    #[error("invalid effect recovery transition {from} -> {to}")]
    InvalidTransition { from: String, to: String },
    /// Readback bytes, method, or verdict are inconsistent.
    #[error("invalid effect recovery observation: {0}")]
    InvalidObservation(String),
    /// Canonical subject encoding failed.
    #[error("effect recovery encoding: {0}")]
    Encoding(String),
}

impl EffectRecoveryError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Store(_) => "EFFECT_RECOVERY_STORE_FAILURE",
            Self::InvalidClaim(_) => "EFFECT_RECOVERY_CLAIM_INVALID",
            Self::InvalidAuthority(_) => "EFFECT_RECOVERY_AUTHORITY_INVALID",
            Self::SubjectMismatch(_) => "EFFECT_RECOVERY_SUBJECT_MISMATCH",
            Self::UnsupportedIntent(_) => "EFFECT_RECOVERY_INTENT_UNSUPPORTED",
            Self::StaleAuthority(_) => "EFFECT_RECOVERY_AUTHORITY_STALE",
            Self::FingerprintMismatch => "EFFECT_RECOVERY_FINGERPRINT_MISMATCH",
            Self::ClaimConflict(_) => "EFFECT_RECOVERY_CLAIM_CONFLICT",
            Self::UnknownClaim => "EFFECT_RECOVERY_CLAIM_UNKNOWN",
            Self::RetryBudgetExhausted => "EFFECT_RECOVERY_RETRY_BUDGET_EXHAUSTED",
            Self::InvalidTransition { .. } => "EFFECT_RECOVERY_TRANSITION_INVALID",
            Self::InvalidObservation(_) => "EFFECT_RECOVERY_OBSERVATION_INVALID",
            Self::Encoding(_) => "EFFECT_RECOVERY_ENCODING_FAILURE",
        }
    }
}
