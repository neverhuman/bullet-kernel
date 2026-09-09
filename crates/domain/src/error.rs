//! Domain errors. No I/O. Every variant carries a stable reason code.

use thiserror::Error;

/// Fail-closed domain failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// An identifier was missing its prefix or hex body.
    #[error("invalid id: {0}")]
    InvalidId(String),
    /// A state machine rejected the requested edge.
    #[error("invalid transition: {from} cannot become {to}")]
    InvalidTransition {
        /// Current state label.
        from: String,
        /// Requested state label.
        to: String,
    },
    /// A writer lease TTL was outside the admitted bounded interval.
    #[error("invalid lease TTL {0}; expected Phase-1 range 1..=15 seconds")]
    InvalidLeaseTtl(i64),
    /// The Authority Token did not match the subject.
    #[error("stale or incomplete authority token: {0}")]
    StaleAuthority(String),
    /// A fence epoch was reused or decreased.
    #[error("fence invariant violated: {0}")]
    Fence(String),
    /// A command was not idempotent with its recorded payload.
    #[error("idempotency conflict: {0}")]
    Idempotency(String),
    /// Canonical encoding failed.
    #[error("canonical encoding: {0}")]
    Encoding(String),
    /// Graph parent digest did not match the stored graph.
    #[error("graph conflict: {0}")]
    Conflict(String),
    /// A persisted state label is outside the machine's catalog.
    #[error("unknown state label: {0}")]
    UnknownState(String),
}

impl DomainError {
    /// Stable machine-readable reason code for APIs and logs.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidId(_) => "INVALID_ID",
            Self::InvalidTransition { .. } => "INVALID_TRANSITION",
            Self::InvalidLeaseTtl(_) => "INVALID_LEASE_TTL",
            Self::StaleAuthority(_) => "STALE_AUTHORITY",
            Self::Fence(_) => "FENCE_REUSE",
            Self::Idempotency(_) => "IDEMPOTENCY_CONFLICT",
            Self::Encoding(_) => "ENCODING_FAILURE",
            Self::Conflict(_) => "GRAPH_CONFLICT",
            Self::UnknownState(_) => "UNKNOWN_STATE",
        }
    }
}
