//! Typed harness failures with stable reason codes. Fail closed, never panic.

use thiserror::Error;

/// Harness failure. Every variant carries a stable reason code.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HarnessError {
    /// The adapter does not implement this method for this provider.
    #[error("{provider} does not support {method}")]
    Unsupported {
        /// Provider name.
        provider: String,
        /// Trait method name.
        method: &'static str,
    },
    /// Probed identity differs from the authorized profile.
    #[error("profile mismatch: expected {expected}, probed {actual}")]
    ProfileMismatch {
        /// Expectation description.
        expected: String,
        /// Probed identity description.
        actual: String,
    },
    /// The probe could not establish a verified identity. Fails closed.
    #[error("profile unverified for {provider}: {reason}")]
    ProfileUnverified {
        /// Provider name.
        provider: String,
        /// Why verification failed.
        reason: String,
    },
    /// A worktree or tmux flag reached an argv builder.
    #[error("denied argv token: {token}")]
    WorktreeFlagDenied {
        /// The offending token.
        token: String,
    },
    /// `BULLET_PROVIDER_KILL=1` is set; refusing to spawn.
    #[error("provider kill switch active")]
    KillSwitch,
    /// Wave-0 quarantine: live execution has no signed admission validator.
    #[error("live provider admission is unavailable for {provider}")]
    LiveAdmissionUnavailable {
        /// Known provider executable that was refused.
        provider: String,
    },
    /// Provider admission input or filesystem identity was invalid.
    #[error("provider admission refused: {reason}")]
    AdmissionRefused {
        /// Non-secret refusal detail.
        reason: String,
    },
    /// A local receipt cannot authorize dispatch while a blocker remains.
    #[error("provider admission blocked: {blocker}")]
    AdmissionBlocked {
        /// Stable blocker code.
        blocker: String,
    },
    /// A canary secret reached a forbidden provider-facing surface.
    #[error("secret canary detected on {surface}")]
    SecretCanaryExposure {
        /// Surface name only; the secret is never logged.
        surface: &'static str,
    },
    /// The per-run invocation budget is spent.
    #[error("invocation budget exhausted: max {max}")]
    InvocationBudgetExhausted {
        /// Configured maximum.
        max: u32,
    },
    /// A required capability is Unknown; dispatch refuses.
    #[error("capability {capability} is unknown; dispatch refused")]
    CapabilityUnknown {
        /// Capability wire name.
        capability: String,
    },
    /// A required capability is Unsupported; dispatch refuses.
    #[error("capability {capability} is unsupported; dispatch refused")]
    CapabilityUnsupported {
        /// Capability wire name.
        capability: String,
    },
    /// Spawning the provider process failed.
    #[error("spawn failed for {program}: {reason}")]
    Spawn {
        /// Program that failed to start.
        program: String,
        /// OS error text.
        reason: String,
    },
    /// Wall-clock timeout; the process group was killed.
    #[error("wall clock timeout after {seconds}s")]
    Timeout {
        /// Configured bound in seconds.
        seconds: u64,
    },
    /// The provider stream violated its protocol.
    #[error("protocol error from {provider}: {reason}")]
    Protocol {
        /// Provider name.
        provider: String,
        /// Violation description.
        reason: String,
    },
    /// Structured output did not parse as a `PatchProposal`.
    #[error("proposal parse failed: {reason}")]
    ProposalParse {
        /// Parse or validation failure.
        reason: String,
    },
    /// The session state machine rejected an edge.
    #[error("illegal session transition: {from} -> {to}")]
    IllegalTransition {
        /// Current state label.
        from: String,
        /// Requested state label.
        to: String,
    },
    /// Unknown session handle.
    #[error("unknown session: {session}")]
    SessionUnknown {
        /// Session id.
        session: String,
    },
    /// Filesystem or pipe failure.
    #[error("io failure in {context}: {reason}")]
    Io {
        /// What was being attempted.
        context: String,
        /// OS error text.
        reason: String,
    },
    /// The provider process exited unsuccessfully.
    #[error("provider {provider} failed (exit {exit:?}): {reason}")]
    ProviderFailure {
        /// Provider name.
        provider: String,
        /// Exit code when observed.
        exit: Option<i32>,
        /// Failure description.
        reason: String,
    },
    /// The provider demands re-authentication.
    #[error("auth required for {provider}: {reason}")]
    AuthRequired {
        /// Provider name.
        provider: String,
        /// Challenge description.
        reason: String,
    },
}

impl HarnessError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "UNSUPPORTED",
            Self::ProfileMismatch { .. } => "PROFILE_MISMATCH",
            Self::ProfileUnverified { .. } => "PROFILE_UNVERIFIED",
            Self::WorktreeFlagDenied { .. } => "WORKTREE_FLAG_DENIED",
            Self::KillSwitch => "PROVIDER_KILL_ACTIVE",
            Self::LiveAdmissionUnavailable { .. } => "LIVE_ADMISSION_UNAVAILABLE",
            Self::AdmissionRefused { .. } => "ADMISSION_REFUSED",
            Self::AdmissionBlocked { .. } => "PROVIDER_ADMISSION_BLOCKED",
            Self::SecretCanaryExposure { .. } => "SECRET_CANARY_EXPOSURE",
            Self::InvocationBudgetExhausted { .. } => "INVOCATION_BUDGET_EXHAUSTED",
            Self::CapabilityUnknown { .. } => "CAPABILITY_UNKNOWN",
            Self::CapabilityUnsupported { .. } => "CAPABILITY_UNSUPPORTED",
            Self::Spawn { .. } => "SPAWN_FAILED",
            Self::Timeout { .. } => "WALL_CLOCK_TIMEOUT",
            Self::Protocol { .. } => "PROTOCOL_ERROR",
            Self::ProposalParse { .. } => "PROPOSAL_PARSE_FAILED",
            Self::IllegalTransition { .. } => "ILLEGAL_STATE_EDGE",
            Self::SessionUnknown { .. } => "SESSION_UNKNOWN",
            Self::Io { .. } => "IO_FAILED",
            Self::ProviderFailure { .. } => "PROVIDER_FAILURE",
            Self::AuthRequired { .. } => "AUTH_REQUIRED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_codes_are_stable() {
        assert_eq!(
            HarnessError::KillSwitch.reason_code(),
            "PROVIDER_KILL_ACTIVE"
        );
        let err = HarnessError::WorktreeFlagDenied {
            token: "--worktree".into(),
        };
        assert_eq!(err.reason_code(), "WORKTREE_FLAG_DENIED");
    }
}
