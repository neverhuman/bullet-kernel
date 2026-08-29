//! Typed runner failures with stable reason codes. Fail closed, never panic.

use bullet_harness_core::HarnessError;
use thiserror::Error;

/// Runner failure. Every variant carries a stable reason code.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The ledger no longer recognizes this incarnation's authority.
    #[error("stale authority: {0}")]
    StaleAuthority(String),
    /// The local monotonic self-kill deadline passed without a renewed lease.
    #[error("self-kill deadline passed at {elapsed_ms}ms")]
    SelfKill {
        /// Monotonic milliseconds when the deadline fired.
        elapsed_ms: u64,
    },
    /// A proposed path is outside the granted scope prefixes.
    #[error("scope denied: {path} is outside the granted prefixes")]
    ScopeDenied {
        /// The offending repository-relative path.
        path: String,
    },
    /// The workspace daemon refused a call.
    #[error("gitd refused {method}: {code}: {message}")]
    Gitd {
        /// Method that was refused.
        method: String,
        /// Daemon reason code.
        code: String,
        /// Daemon message.
        message: String,
    },
    /// BulletGit cannot validate a frozen authority contract, so mutation is unavailable.
    #[error("authority contract unavailable during gitd {method}: {message}")]
    AuthorityContractUnavailable {
        /// Method refused before repository mutation.
        method: String,
        /// BulletGit's fail-closed detail.
        message: String,
    },
    /// No immutable BulletGit daemon subject was configured.
    #[error("gitd binary is unprovisioned: {variable} is missing or empty")]
    GitdBinaryUnprovisioned {
        /// Environment-backed configuration field that was absent.
        variable: String,
    },
    /// The configured BulletGit daemon subject failed executable admission.
    #[error("gitd binary admission refused: {reason}")]
    GitdBinaryAdmission {
        /// Stable, operator-actionable refusal detail.
        reason: String,
    },
    /// Provider adapter failure.
    #[error(transparent)]
    Harness(#[from] HarnessError),
    /// The lease API refused a call.
    #[error("lease call refused: {code}: {message}")]
    Lease {
        /// Server reason code.
        code: String,
        /// Server message.
        message: String,
    },
    /// Acquire may have committed, but exact active readback could not prove it.
    #[error("lease acquire outcome unknown: {message}")]
    AcquireOutcomeUnknown {
        /// Reconciliation failure without authority-sensitive payloads.
        message: String,
    },
    /// Advance may have committed, but exact settlement readback could not prove it.
    #[error("lease advance outcome unknown: {message}")]
    AdvanceOutcomeUnknown {
        /// Reconciliation failure without authority-sensitive payloads.
        message: String,
    },
    /// Release may have committed, but exact settlement readback could not prove it.
    #[error("lease release outcome unknown: {message}")]
    ReleaseOutcomeUnknown {
        /// Reconciliation failure without authority-sensitive payloads.
        message: String,
    },
    /// The gate command could not be executed at all.
    #[error("gate `{command}` failed to run: {reason}")]
    Gate {
        /// Registry-owned gate identifier.
        command: String,
        /// OS failure text.
        reason: String,
    },
    /// Gate selection was malformed, unknown, or differed from policy.
    #[error("gate selection refused: {reason}")]
    GateSelection {
        /// Fail-closed policy detail.
        reason: String,
    },
    /// The bounded repair loop is spent without a passing candidate.
    #[error("caps exhausted after {rounds} repair rounds")]
    CapsExhausted {
        /// Repair rounds consumed.
        rounds: u32,
    },
    /// The turn closed without a usable `PatchProposal`.
    #[error("turn produced no patch proposal: {0}")]
    NoProposal(String),
    /// Filesystem, socket, or pipe failure.
    #[error("io failure in {context}: {reason}")]
    Io {
        /// What was being attempted.
        context: String,
        /// OS error text.
        reason: String,
    },
    /// A wire response violated its protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),
}

impl RunnerError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::StaleAuthority(_) => "STALE_AUTHORITY",
            Self::SelfKill { .. } => "SELF_KILL_DEADLINE",
            Self::ScopeDenied { .. } => "SCOPE_DENIED",
            Self::Gitd { .. } => "GITD_REFUSED",
            Self::AuthorityContractUnavailable { .. } => "AUTHORITY_CONTRACT_UNAVAILABLE",
            Self::GitdBinaryUnprovisioned { .. } => "GITD_BINARY_UNPROVISIONED",
            Self::GitdBinaryAdmission { .. } => "GITD_BINARY_ADMISSION_REFUSED",
            Self::Harness(err) => err.reason_code(),
            Self::Lease { .. } => "LEASE_REFUSED",
            Self::AcquireOutcomeUnknown { .. } => "ACQUIRE_OUTCOME_UNKNOWN",
            Self::AdvanceOutcomeUnknown { .. } => "ADVANCE_OUTCOME_UNKNOWN",
            Self::ReleaseOutcomeUnknown { .. } => "RELEASE_OUTCOME_UNKNOWN",
            Self::Gate { .. } => "GATE_FAILED",
            Self::GateSelection { .. } => "GATE_SELECTION_REFUSED",
            Self::CapsExhausted { .. } => "CAPS_EXHAUSTED",
            Self::NoProposal(_) => "NO_PROPOSAL",
            Self::Io { .. } => "IO_FAILED",
            Self::Protocol(_) => "PROTOCOL_ERROR",
        }
    }

    /// True when the failure means this incarnation's authority is gone.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::StaleAuthority(_))
    }

    /// The daemon detail when this is the repairable `PATH_ABSENT` refusal
    /// (a delete target that is not an existing regular file).
    #[must_use]
    pub fn path_absent_detail(&self) -> Option<&str> {
        match self {
            Self::Gitd { code, message, .. } if code == "PATH_ABSENT" => Some(message),
            _ => None,
        }
    }

    /// True for the freeze class: stale authority or the self-kill deadline.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        matches!(self, Self::StaleAuthority(_) | Self::SelfKill { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_codes_are_stable() {
        assert_eq!(
            RunnerError::StaleAuthority("x".into()).reason_code(),
            "STALE_AUTHORITY"
        );
        assert_eq!(
            RunnerError::ScopeDenied { path: "a".into() }.reason_code(),
            "SCOPE_DENIED"
        );
        assert_eq!(
            RunnerError::SelfKill { elapsed_ms: 1 }.reason_code(),
            "SELF_KILL_DEADLINE"
        );
        assert!(RunnerError::StaleAuthority("x".into()).is_frozen());
        assert!(RunnerError::SelfKill { elapsed_ms: 1 }.is_frozen());
        assert!(!RunnerError::CapsExhausted { rounds: 2 }.is_frozen());
        assert_eq!(
            RunnerError::AuthorityContractUnavailable {
                method: "clone".into(),
                message: "frozen source unavailable".into(),
            }
            .reason_code(),
            "AUTHORITY_CONTRACT_UNAVAILABLE"
        );
        assert_eq!(
            RunnerError::GitdBinaryUnprovisioned {
                variable: "BULLET_GITD_BIN".into(),
            }
            .reason_code(),
            "GITD_BINARY_UNPROVISIONED"
        );
        assert_eq!(
            RunnerError::GitdBinaryAdmission { reason: "x".into() }.reason_code(),
            "GITD_BINARY_ADMISSION_REFUSED"
        );
        assert_eq!(
            RunnerError::GateSelection { reason: "x".into() }.reason_code(),
            "GATE_SELECTION_REFUSED"
        );
        assert_eq!(
            RunnerError::AcquireOutcomeUnknown {
                message: "readback unavailable".into(),
            }
            .reason_code(),
            "ACQUIRE_OUTCOME_UNKNOWN"
        );
        assert_eq!(
            RunnerError::AdvanceOutcomeUnknown {
                message: "readback unavailable".into(),
            }
            .reason_code(),
            "ADVANCE_OUTCOME_UNKNOWN"
        );
        assert_eq!(
            RunnerError::ReleaseOutcomeUnknown {
                message: "readback unavailable".into(),
            }
            .reason_code(),
            "RELEASE_OUTCOME_UNKNOWN"
        );
    }

    #[test]
    fn path_absent_detail_is_extracted() {
        let refused = RunnerError::Gitd {
            method: "apply_proposal".into(),
            code: "PATH_ABSENT".into(),
            message: "no regular file to delete at: z".into(),
        };
        assert_eq!(
            refused.path_absent_detail(),
            Some("no regular file to delete at: z")
        );
        assert!(RunnerError::Protocol("x".into())
            .path_absent_detail()
            .is_none());
    }
}
