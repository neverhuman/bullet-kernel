//! Per-gate executable digest, multi-gate aggregation, and oracle-modifying
//! classification. This component does not admit evidence: custody, GateSpec
//! closure, and policy selection remain verifier-owned predecessors.

use crate::gate::GateRun;
use bullet_domain::{Digest, GateOutcome, REASON_ZERO_TESTS};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    /// Digest of the catalog-owned, length-framed argv.
    catalog_argv_digest: Digest,
    /// Independently measured digest of the admitted executable bytes.
    executable_bytes_digest: Digest,
    /// Typed outcome. Never rewritten to PASS.
    outcome: GateOutcome,
    /// Oracle classification.
    oracle_class: OracleClass,
}

impl AggregatedGate {
    /// Digest of the catalog-owned, length-framed argv.
    #[must_use]
    pub const fn catalog_argv_digest(&self) -> Digest {
        self.catalog_argv_digest
    }

    /// Independently supplied digest of the observed executable bytes.
    #[must_use]
    pub const fn executable_bytes_digest(&self) -> Digest {
        self.executable_bytes_digest
    }

    /// Classified gate outcome. This is not evidence admission.
    #[must_use]
    pub const fn outcome(&self) -> GateOutcome {
        self.outcome
    }

    /// Caller-supplied oracle classification. This is not custody proof.
    #[must_use]
    pub const fn oracle_class(&self) -> OracleClass {
        self.oracle_class
    }
}

/// Fail-closed gate aggregation input error.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AggregationError {
    /// A required gate set cannot be empty.
    #[error("required gate set is empty")]
    EmptyGateSet,
}

impl AggregationError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::EmptyGateSet => "BAD_INPUT",
        }
    }
}

/// Digest the exact catalog argv for one gate.
#[must_use]
pub fn catalog_argv_digest(argv: &[String]) -> Digest {
    let mut framed = Vec::new();
    frame(&mut framed, b"bullet.verifier.executable.v1");
    let argc = u64::try_from(argv.len()).expect("argv length fits u64");
    framed.extend_from_slice(&argc.to_le_bytes());
    for argument in argv {
        frame(&mut framed, argument.as_bytes());
    }
    Digest::of(&framed)
}

fn frame(target: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("argument length fits u64");
    target.extend_from_slice(&length.to_le_bytes());
    target.extend_from_slice(value);
}

/// Aggregate many gate runs. Non-PASS outcomes stay non-PASS.
///
/// # Errors
///
/// Returns [`AggregationError::EmptyGateSet`] when no required gate was
/// supplied. An empty set can never satisfy release admission.
pub fn aggregate(
    runs: &[(&str, &[String], Digest, &GateRun, OracleClass)],
) -> Result<Vec<AggregatedGate>, AggregationError> {
    if runs.is_empty() {
        return Err(AggregationError::EmptyGateSet);
    }
    Ok(runs
        .iter()
        .map(|(reason_hint, argv, executable_bytes_digest, run, class)| {
            let mut outcome = run.outcome;
            if outcome == GateOutcome::Pass
                && (run.reason.as_deref() == Some(REASON_ZERO_TESTS)
                    || *reason_hint == REASON_ZERO_TESTS)
            {
                outcome = GateOutcome::NotRun;
            }
            if outcome == GateOutcome::Pass && *class == OracleClass::OracleModifyingDiff {
                outcome = GateOutcome::Invalidated;
            }
            AggregatedGate {
                catalog_argv_digest: catalog_argv_digest(argv),
                executable_bytes_digest: *executable_bytes_digest,
                outcome,
                oracle_class: *class,
            }
        })
        .collect())
}
