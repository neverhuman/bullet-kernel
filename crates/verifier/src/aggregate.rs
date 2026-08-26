//! Per-gate executable digest, multi-gate aggregation, and oracle-modifying
//! classification. `ZERO_TESTS`, `INFRA_ERROR`, and `TIMED_OUT` never PASS.

use crate::gate::GateRun;
use bullet_domain::{Digest, GateOutcome, REASON_ZERO_TESTS};
use serde::{Deserialize, Serialize};

/// How a gate result may relate to a writer-modified oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OracleClass {
    /// Gate did not observe a writer-modified oracle.
    Independent,
    /// Gate compared against a writer-modified expected value.
    OracleModifyingDiff,
}

/// One aggregated gate after digest binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatedGate {
    /// Catalog executable digest.
    pub executable_digest: Digest,
    /// Typed outcome. Never rewritten to PASS.
    pub outcome: GateOutcome,
    /// Oracle classification.
    pub oracle_class: OracleClass,
}

/// Digest the exact catalog argv for one gate.
#[must_use]
pub fn executable_digest(argv: &[String]) -> Digest {
    Digest::of(argv.join("\0").as_bytes())
}

/// Aggregate many gate runs. Non-PASS outcomes stay non-PASS.
///
/// # Errors
///
/// This function does not fail. The `Result` shape is reserved for a later
/// bound on empty aggregation; today an empty set is `NotRun`.
pub fn aggregate(runs: &[(&str, &[String], &GateRun, OracleClass)]) -> Vec<AggregatedGate> {
    if runs.is_empty() {
        return Vec::new();
    }
    runs.iter()
        .map(|(reason_hint, argv, run, class)| {
            let mut outcome = run.outcome;
            if outcome == GateOutcome::Pass {
                if run.reason.as_deref() == Some(REASON_ZERO_TESTS)
                    || *reason_hint == REASON_ZERO_TESTS
                {
                    outcome = GateOutcome::NotRun;
                }
                if matches!(
                    outcome,
                    GateOutcome::InfraError | GateOutcome::TimedOut | GateOutcome::NotRun
                ) {
                    outcome = GateOutcome::NotRun;
                }
            }
            if matches!(
                run.outcome,
                GateOutcome::InfraError | GateOutcome::TimedOut | GateOutcome::NotRun
            ) {
                outcome = run.outcome;
            }
            AggregatedGate {
                executable_digest: executable_digest(argv),
                outcome,
                oracle_class: *class,
            }
        })
        .collect()
}

/// True when any aggregated gate is PASS.
#[must_use]
pub fn any_pass(gates: &[AggregatedGate]) -> bool {
    gates.iter().any(|gate| gate.outcome == GateOutcome::Pass)
}
