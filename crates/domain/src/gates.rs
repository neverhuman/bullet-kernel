//! Spec section 22 gate outcomes and evidence tiers. Only a typed `PASS`
//! satisfies a blocking requirement; a gate that executed zero tests is
//! reported as `NOT_RUN` with reason [`REASON_ZERO_TESTS`], never `PASS`.

use crate::entities::Evidence;
use crate::error::DomainError;
use crate::ids::{CandidateId, EvidenceId};
use serde::{Deserialize, Serialize};

/// Stable reason code attached to a `NOT_RUN` outcome whose gate executed
/// zero tests. Distinct from an ordinary never-started `NOT_RUN`.
pub const REASON_ZERO_TESTS: &str = "ZERO_TESTS";

/// Spec section 22.3 gate outcome. A free string is never a gate outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateOutcome {
    /// Acceptable result. The only value that satisfies a requirement.
    Pass,
    /// Deterministic failure of the subject.
    Fail,
    /// Non-deterministic failure.
    Flaky,
    /// Runner or infrastructure fault, not a subject verdict.
    InfraError,
    /// Operator or policy cancelled the gate.
    Cancelled,
    /// The gate did not finish inside its budget.
    TimedOut,
    /// The gate never ran, or ran and executed zero tests.
    NotRun,
    /// The gate cannot run in this environment.
    Unsupported,
    /// The probe did not establish a result.
    Unknown,
    /// A successor subject superseded this run.
    Superseded,
    /// The subject or its input closure changed after the run.
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

    /// Parse a wire name. Any spelling outside the catalog is `Unknown`,
    /// never `Pass`.
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

    /// Whether this outcome satisfies a blocking requirement. True only for
    /// `Pass` (spec section 22.3, invariant E4).
    #[must_use]
    pub fn satisfies_requirement(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Spec section 22.1 evidence tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceTier {
    /// Model or author assertion.
    E0,
    /// Deterministic writer-sandbox result.
    E1,
    /// Clean independent verifier.
    E2,
    /// Protected hidden evaluator, merge-group CI, external system.
    E3,
    /// Authorized human or domain approval.
    E4,
}

impl EvidenceTier {
    /// Stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::E0 => "E0",
            Self::E1 => "E1",
            Self::E2 => "E2",
            Self::E3 => "E3",
            Self::E4 => "E4",
        }
    }

    /// Parse a stable wire name.
    ///
    /// # Errors
    ///
    /// Returns `UnknownState` for any label outside the catalog.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "E0" => Ok(Self::E0),
            "E1" => Ok(Self::E1),
            "E2" => Ok(Self::E2),
            "E3" => Ok(Self::E3),
            "E4" => Ok(Self::E4),
            other => Err(DomainError::UnknownState(format!("evidence tier {other}"))),
        }
    }
}

impl Evidence {
    /// Build an evidence row from typed tier and outcome. The stored string
    /// fields carry exactly the stable wire names.
    #[must_use]
    pub fn typed(
        id: EvidenceId,
        candidate_id: CandidateId,
        tier: EvidenceTier,
        gate: impl Into<String>,
        outcome: GateOutcome,
    ) -> Self {
        Self {
            id,
            candidate_id,
            tier: tier.as_str().to_string(),
            gate: gate.into(),
            result: outcome.as_str().to_string(),
        }
    }

    /// Typed outcome of the stored result string. Garbage stays `Unknown`.
    #[must_use]
    pub fn outcome(&self) -> GateOutcome {
        GateOutcome::parse(&self.result)
    }

    /// Typed tier of the stored tier string.
    ///
    /// # Errors
    ///
    /// Returns `UnknownState` when the stored label is outside `E0`..=`E4`.
    pub fn tier_typed(&self) -> Result<EvidenceTier, DomainError> {
        EvidenceTier::parse(&self.tier)
    }

    /// Whether this row satisfies a blocking requirement (typed `PASS` only).
    #[must_use]
    pub fn satisfies_requirement(&self) -> bool {
        self.outcome().satisfies_requirement()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [GateOutcome; 11] = [
        GateOutcome::Pass,
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
    ];

    #[test]
    fn eleven_outcomes_round_trip_and_only_pass_satisfies() {
        for outcome in ALL {
            assert_eq!(GateOutcome::parse(outcome.as_str()), outcome);
            let json = serde_json::to_string(&outcome).expect("encode");
            assert_eq!(json, format!("\"{}\"", outcome.as_str()));
            assert_eq!(
                outcome.satisfies_requirement(),
                outcome == GateOutcome::Pass
            );
        }
    }

    #[test]
    fn garbage_and_case_variants_parse_unknown_never_pass() {
        for garbage in ["pass", "Pass", "OK", "", "ZERO_TESTS", "passed"] {
            assert_eq!(GateOutcome::parse(garbage), GateOutcome::Unknown);
        }
    }

    #[test]
    fn tiers_round_trip_and_order() {
        for tier in [
            EvidenceTier::E0,
            EvidenceTier::E1,
            EvidenceTier::E2,
            EvidenceTier::E3,
            EvidenceTier::E4,
        ] {
            assert_eq!(EvidenceTier::parse(tier.as_str()).expect("parse"), tier);
        }
        assert!(EvidenceTier::E2 < EvidenceTier::E3);
        assert_eq!(
            EvidenceTier::parse("E5")
                .expect_err("bad tier")
                .reason_code(),
            "UNKNOWN_STATE"
        );
    }

    #[test]
    fn typed_evidence_round_trips_and_pass_only_satisfies() {
        let pass = Evidence::typed(
            EvidenceId::from_seed("g-pass"),
            CandidateId::from_seed("g-cand"),
            EvidenceTier::E2,
            "bullet-farm/proof-complete",
            GateOutcome::Pass,
        );
        assert_eq!(pass.tier, "E2");
        assert_eq!(pass.result, "PASS");
        assert!(pass.satisfies_requirement());
        assert_eq!(pass.tier_typed().expect("tier"), EvidenceTier::E2);
        let zero = Evidence::typed(
            EvidenceId::from_seed("g-zero"),
            CandidateId::from_seed("g-cand"),
            EvidenceTier::E2,
            "bullet-farm/proof-complete",
            GateOutcome::NotRun,
        );
        assert_eq!(zero.outcome(), GateOutcome::NotRun);
        assert!(!zero.satisfies_requirement());
    }
}
