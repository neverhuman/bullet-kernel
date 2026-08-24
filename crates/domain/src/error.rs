//! Domain errors. No I/O.

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
}
