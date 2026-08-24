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
            Self::PushRejected { .. } => "PUSH_REJECTED",
            Self::ResponseLost(_) => "RESPONSE_LOST",
            Self::GitFailed(_) => "GIT_FAILED",
            Self::Io(_) => "IO_FAILED",
            Self::IllegalPhase { .. } => "ILLEGAL_EFFECT_PHASE",
            Self::RetryWithoutReconcile(_) => "RETRY_WITHOUT_RECONCILE",
            Self::Ledger(err) => err.reason_code(),
        }
    }
}
