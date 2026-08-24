//! Spec §22.3 gate outcomes. Only PASS satisfies readiness.

/// Typed gate result. A free string is never a gate outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateOutcome {
    /// Acceptable. The only value that satisfies readiness.
    Pass,
    /// Deterministic failure of the subject.
    Fail,
    /// Non-deterministic failure. Not PASS.
    Flaky,
    /// Runner or infrastructure fault. Not PASS.
    InfraError,
    /// Operator or policy cancelled the gate.
    Cancelled,
    /// Gate did not finish in budget. Not PASS.
    TimedOut,
    /// Gate was never started.
    NotRun,
    /// Gate cannot run in this environment.
    Unsupported,
    /// Probe did not establish a result.
    Unknown,
    /// A successor subject superseded this run.
    Superseded,
    /// Input closure or Candidate changed after the run.
    Invalidated,
}

impl GateOutcome {
    /// Stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Flaky => "FLAKY",
            Self::InfraError => "INFRA_ERROR",
            Self::Cancelled => "CANCELLED",
            Self::TimedOut => "TIMED_OUT",
            Self::NotRun => "NOT_RUN",
            Self::Unsupported => "UNSUPPORTED",
            Self::Unknown => "UNKNOWN",
            Self::Superseded => "SUPERSEDED",
            Self::Invalidated => "INVALIDATED",
        }
    }

    /// Parse a wire name. Unknown spellings stay unknown, never PASS.
    #[must_use]
    pub fn parse(name: &str) -> Self {
        match name {
            "PASS" => Self::Pass,
            "FAIL" => Self::Fail,
            "FLAKY" => Self::Flaky,
            "INFRA_ERROR" => Self::InfraError,
            "CANCELLED" => Self::Cancelled,
            "TIMED_OUT" => Self::TimedOut,
            "NOT_RUN" => Self::NotRun,
            "UNSUPPORTED" => Self::Unsupported,
            "SUPERSEDED" => Self::Superseded,
            "INVALIDATED" => Self::Invalidated,
            _ => Self::Unknown,
        }
    }

    /// Only an acceptable PASS satisfies readiness.
    #[must_use]
    pub fn satisfies_readiness(self) -> bool {
        matches!(self, Self::Pass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pass_is_ready() {
        for outcome in [
            GateOutcome::Fail,
            GateOutcome::Flaky,
            GateOutcome::InfraError,
            GateOutcome::Cancelled,
            GateOutcome::TimedOut,
            GateOutcome::NotRun,
            GateOutcome::Unsupported,
            GateOutcome::Unknown,
            GateOutcome::Superseded,
            GateOutcome::Invalidated,
        ] {
            assert!(!outcome.satisfies_readiness(), "{}", outcome.as_str());
        }
        assert!(GateOutcome::Pass.satisfies_readiness());
    }

    #[test]
    fn garbage_string_is_unknown_not_pass() {
        assert_eq!(GateOutcome::parse("pass"), GateOutcome::Unknown);
        assert_eq!(GateOutcome::parse("PASS"), GateOutcome::Pass);
    }
}
