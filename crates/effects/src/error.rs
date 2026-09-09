//! Typed effect-broker failures with stable reason codes.

use bullet_application::LedgerError;
use thiserror::Error;

/// Fail-closed effect failure.
#[derive(Debug, Error)]
pub enum EffectsError {
    /// The target ref is outside the candidate namespace. Reserved refs and
    /// `HEAD` are never push destinations.
    #[error("ref denied: {0}")]
    RefDenied(String),
    /// An OID was not 40 lowercase hex characters.
    #[error("bad oid: {0}")]
    BadOid(String),
    /// The forge has no operator-authenticated token (ADR 0002).
    #[error("forge unauthenticated: {0}")]
    ForgeUnauthenticated(String),
    /// The forge capability has no probe receipt against the live instance.
    #[error("capability unprobed: {0}")]
    CapabilityUnprobed(String),
    /// Wave-0 quarantine: no signed forge admission validator exists.
    #[error("live forge admission is unavailable: {0}")]
    LiveAdmissionUnavailable(String),
    /// The remote refused the push because the precondition no longer holds.
    #[error("push rejected on {ref_name}: observed {observed:?}")]
    PushRejected {
        /// Target ref.
        ref_name: String,
        /// Best-effort observed remote value.
        observed: Option<String>,
    },
    /// The dispatch response was lost; remote truth is unestablished.
    #[error("response lost: {0}")]
    ResponseLost(String),
    /// A git invocation failed for a reason other than a stale precondition.
    #[error("git failed: {0}")]
    GitFailed(String),
    /// Process spawn or filesystem failure.
    #[error("io failed: {0}")]
    Io(String),
    /// A durable effect-queue record or transition was unsafe or inconsistent.
    #[error("durable queue invalid: {0}")]
    DurableQueueInvalid(String),
    /// The intent is not in the phase this operation requires.
    #[error("illegal effect phase: {found} where {wanted} is required")]
    IllegalPhase {
        /// Current state.
        found: String,
        /// Required state.
        wanted: String,
    },
    /// A dispatch was requested for an `OUTCOME_UNKNOWN` intent. Only
    /// `reconcile` may act on unknown outcomes.
    #[error("retry without reconcile refused for {0}")]
    RetryWithoutReconcile(String),
    /// Ledger failure (typed pass-through).
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Adapter structurally cannot perform the operation.
    #[error("unsupported by adapter: {0}")]
    UnsupportedByAdapter(String),
    /// Observed protection does not match the authorized policy.
    #[error("protection mismatch: {0}")]
    ProtectionMismatch(String),
    /// Read-back check names a different SHA or proof root.
    #[error("check subject mismatch: {0}")]
    CheckSubjectMismatch(String),
    /// More than one open subject matches (base, head, target).
    #[error("integration subject ambiguous: {0}")]
    IntegrationSubjectAmbiguous(String),
    /// A caller-supplied subject differs from the persisted exact subject.
    #[error("integration subject mismatch: {0}")]
    IntegrationSubjectMismatch(String),
    /// The protected target no longer matches the authorized old OID.
    #[error("integration precondition failed: {0}")]
    IntegrationPreconditionFailed(String),
    /// Remote state changed without a matching successful local receipt.
    #[error("orphaned remote state: {0}")]
    OrphanedRemote(String),
    /// Adapter has a merge queue but will not disclose the composed SHA.
    #[error("merge group opaque: {0}")]
    MergeGroupOpaque(String),
    /// Target could not be read after integration.
    #[error("target read-back unavailable: {0}")]
    TargetReadbackUnavailable(String),
}

impl EffectsError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::RefDenied(_) => "REF_DENIED",
            Self::BadOid(_) => "BAD_OID",
            Self::ForgeUnauthenticated(_) => "FORGE_UNAUTHENTICATED",
            Self::CapabilityUnprobed(_) => "CAPABILITY_UNPROBED",
            Self::LiveAdmissionUnavailable(_) => "LIVE_ADMISSION_UNAVAILABLE",
            Self::PushRejected { .. } => "PUSH_REJECTED",
            Self::ResponseLost(_) => "RESPONSE_LOST",
            Self::GitFailed(_) => "GIT_FAILED",
            Self::Io(_) => "IO_FAILED",
            Self::DurableQueueInvalid(_) => "DURABLE_QUEUE_INVALID",
            Self::IllegalPhase { .. } => "ILLEGAL_EFFECT_PHASE",
            Self::RetryWithoutReconcile(_) => "RETRY_WITHOUT_RECONCILE",
            Self::Ledger(err) => err.reason_code(),
            Self::UnsupportedByAdapter(_) => "UNSUPPORTED_BY_ADAPTER",
            Self::ProtectionMismatch(_) => "PROTECTION_MISMATCH",
            Self::CheckSubjectMismatch(_) => "CHECK_SUBJECT_MISMATCH",
            Self::IntegrationSubjectAmbiguous(_) => "INTEGRATION_SUBJECT_AMBIGUOUS",
            Self::IntegrationSubjectMismatch(_) => "INTEGRATION_SUBJECT_MISMATCH",
            Self::IntegrationPreconditionFailed(_) => "INTEGRATION_PRECONDITION_FAILED",
            Self::OrphanedRemote(_) => "ORPHANED_REMOTE",
            Self::MergeGroupOpaque(_) => "MERGE_GROUP_OPAQUE",
            Self::TargetReadbackUnavailable(_) => "TARGET_READBACK_UNAVAILABLE",
        }
    }
}
