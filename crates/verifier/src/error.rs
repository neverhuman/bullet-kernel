//! Typed verifier failures with stable reason codes.

use thiserror::Error;

/// Fail-closed verifier failure. Gate verdicts are not errors; they are
/// typed outcomes inside the evidence record.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// The caller is the writer identity. Writer evidence cannot satisfy
    /// independent requirements, so the run is refused outright.
    #[error("verifier and author identities overlap: {0}")]
    AuthorOverlap(String),
    /// The request failed validation before any work started.
    #[error("invalid verifier request: {0}")]
    BadInput(String),
    /// Filesystem or process-spawn failure outside git.
    #[error("verifier io: {0}")]
    Io(String),
    /// A git invocation that must succeed did not.
    #[error("git {op}: {detail}")]
    Git {
        /// Verb that failed.
        op: String,
        /// Trimmed stderr.
        detail: String,
    },
}

impl VerifierError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::AuthorOverlap(_) => "VERIFIER_IS_AUTHOR",
            Self::BadInput(_) => "BAD_INPUT",
            Self::Io(_) => "IO_FAILED",
            Self::Git { .. } => "GIT_FAILED",
        }
    }
}

pub(crate) fn io_err(op: &str, err: &impl std::fmt::Display) -> VerifierError {
    VerifierError::Io(format!("{op}: {err}"))
}
