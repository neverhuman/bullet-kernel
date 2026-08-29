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
    /// No independently observed runtime-conformance subject is available.
    #[error("runtime probe unavailable for {provider}")]
    RuntimeProbeUnavailable {
        /// Provider whose production adapter cannot yet produce the observation.
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
    /// A launch grant, its envelope, key, or a policy key is malformed.
    #[error("launch grant invalid: {reason}")]
    LaunchGrantInvalid {
        /// Non-secret refusal detail.
        reason: String,
    },
    /// The verification instant is at or after the grant expiry.
    #[error("launch grant expired at {expires_at_unix_ms}")]
    LaunchGrantExpired {
        /// Exclusive expiry instant.
        expires_at_unix_ms: u64,
    },
    /// The verification instant precedes the grant validity start.
    #[error("launch grant not valid before {not_before_unix_ms}")]
    LaunchGrantNotYetValid {
        /// Inclusive validity start.
        not_before_unix_ms: u64,
    },
    /// The grant window exceeds the frozen 15 s maximum.
    #[error("launch grant ttl {ttl_ms} ms exceeds the 15000 ms maximum")]
    LaunchGrantTtlExceeded {
        /// Claimed window length.
        ttl_ms: u64,
    },
    /// No admitted policy key matches the grant issuer, key id, and audience.
    #[error("launch grant key unknown: {issuer}/{key_id}: {reason}")]
    LaunchGrantKeyUnknown {
        /// Issuer label from the envelope.
        issuer: String,
        /// Key label from the envelope.
        key_id: String,
        /// Why the key is not admitted.
        reason: String,
    },
    /// The grant names an audience other than `provider-runner`.
    #[error("launch grant audience mismatch: {audience}")]
    LaunchGrantAudienceMismatch {
        /// Printable claimed audience.
        audience: String,
    },
    /// One bound field differs from the durable lease, admission, or policy.
    #[error("launch grant subject mismatch on {field}")]
    LaunchGrantSubjectMismatch {
        /// Name of the first mismatching field.
        field: String,
    },
    /// The single-use grant nonce was already consumed.
    #[error("launch grant {grant_id} replayed")]
    LaunchGrantReplayed {
        /// Replayed grant identifier.
        grant_id: String,
    },
    /// A Candidate-preparation grant, carrier, key, or claim is malformed.
    #[error("candidate preparation grant invalid: {reason}")]
    CandidatePreparationInvalid {
        /// Non-secret refusal detail.
        reason: String,
    },
    /// No admitted key matches the Candidate-preparation carrier.
    #[error("candidate preparation key unknown: {issuer}/{key_id}")]
    CandidatePreparationKeyUnknown {
        /// Issuer label from the carrier.
        issuer: String,
        /// Key label from the carrier.
        key_id: String,
    },
    /// The authenticated grant differs from durable expected truth.
    #[error("candidate preparation subject mismatch")]
    CandidatePreparationSubjectMismatch,
    /// Candidate-preparation verification precedes the validity window.
    #[error("candidate preparation grant not valid before {not_before_unix_ms}")]
    CandidatePreparationNotYetValid {
        /// Inclusive validity start.
        not_before_unix_ms: u64,
    },
    /// Candidate-preparation verification is at or after expiry.
    #[error("candidate preparation grant expired at {expires_at_unix_ms}")]
    CandidatePreparationExpired {
        /// Exclusive expiry instant.
        expires_at_unix_ms: u64,
    },
    /// The one-use Candidate-preparation nonce was already consumed.
    #[error("candidate preparation grant {grant_id} replayed")]
    CandidatePreparationReplayed {
        /// Replayed grant identifier.
        grant_id: String,
    },
    /// No policy snapshot could be loaded.
    #[error("policy unavailable: {reason}")]
    PolicyUnavailable {
        /// Where and why loading failed.
        reason: String,
    },
    /// The policy snapshot is malformed or unsafe.
    #[error("policy invalid: {reason}")]
    PolicyInvalid {
        /// Non-secret validation detail.
        reason: String,
    },
    /// The loaded policy generation keeps live admission disabled.
    #[error("policy generation {generation} keeps {field} = false; live admission refused")]
    PolicyLiveAdmissionDisabled {
        /// Loaded policy generation.
        generation: u64,
        /// Exact policy field that refuses live admission.
        field: String,
    },
    /// A signed mutation permit was missing, expired, replayed, or unbound.
    #[error("mutation permit refused: {reason}")]
    MutationPermitRefused {
        /// Stable machine-readable code from the wire permit contract.
        code: &'static str,
        /// Non-secret refusal detail.
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
            Self::RuntimeProbeUnavailable { .. } => "RUNTIME_PROBE_UNAVAILABLE",
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
            Self::LaunchGrantInvalid { .. } => "LAUNCH_GRANT_INVALID",
            Self::LaunchGrantExpired { .. } => "LAUNCH_GRANT_EXPIRED",
            Self::LaunchGrantNotYetValid { .. } => "LAUNCH_GRANT_NOT_YET_VALID",
            Self::LaunchGrantTtlExceeded { .. } => "LAUNCH_GRANT_TTL_EXCEEDED",
            Self::LaunchGrantKeyUnknown { .. } => "LAUNCH_GRANT_KEY_UNKNOWN",
            Self::LaunchGrantAudienceMismatch { .. } => "LAUNCH_GRANT_AUDIENCE_MISMATCH",
            Self::LaunchGrantSubjectMismatch { .. } => "LAUNCH_GRANT_SUBJECT_MISMATCH",
            Self::LaunchGrantReplayed { .. } => "LAUNCH_GRANT_REPLAYED",
            Self::CandidatePreparationInvalid { .. } => "CANDIDATE_PREPARATION_GRANT_INVALID",
            Self::CandidatePreparationKeyUnknown { .. } => "CANDIDATE_PREPARATION_KEY_UNKNOWN",
            Self::CandidatePreparationSubjectMismatch => "CANDIDATE_PREPARATION_SUBJECT_MISMATCH",
            Self::CandidatePreparationNotYetValid { .. } => "CANDIDATE_PREPARATION_NOT_YET_VALID",
            Self::CandidatePreparationExpired { .. } => "CANDIDATE_PREPARATION_EXPIRED",
            Self::CandidatePreparationReplayed { .. } => "CANDIDATE_PREPARATION_REPLAYED",
            Self::PolicyUnavailable { .. } => "POLICY_UNAVAILABLE",
            Self::PolicyInvalid { .. } => "POLICY_INVALID",
            Self::PolicyLiveAdmissionDisabled { .. } => "POLICY_LIVE_ADMISSION_DISABLED",
            Self::MutationPermitRefused { code, .. } => code,
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
        let disabled = HarnessError::PolicyLiveAdmissionDisabled {
            generation: 1,
            field: "sandbox_policy.live_admission_enabled".into(),
        };
        assert_eq!(disabled.reason_code(), "POLICY_LIVE_ADMISSION_DISABLED");
        assert!(disabled.to_string().contains("generation 1"));
        let unavailable = HarnessError::RuntimeProbeUnavailable {
            provider: "claude".into(),
        };
        assert_eq!(unavailable.reason_code(), "RUNTIME_PROBE_UNAVAILABLE");
        let permit = HarnessError::MutationPermitRefused {
            code: "MUTATION_PERMIT_MISSING",
            reason: "apply has no signed permit".into(),
        };
        assert_eq!(permit.reason_code(), "MUTATION_PERMIT_MISSING");
    }
}
