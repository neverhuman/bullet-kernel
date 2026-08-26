//! Closed reserve-class vocabulary and validated budget-policy snapshots.
//!
//! Class order is code-owned vocabulary. Floor values are not: reservation
//! admission receives an exact provenance- and generation-bound snapshot.
//! No time, I/O, provider knowledge, or default production policy lives here.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

const MAX_PROVENANCE_BYTES: usize = 256;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Reserve class, spelled as spec §15.7 lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveClass {
    /// Live incident response; may drain a dimension to zero.
    Incident,
    /// Security response.
    Security,
    /// Critical work.
    Critical,
    /// Repair of a broken integration branch.
    IntegrationRepair,
    /// Work whose result is blocking a human.
    HumanInteractive,
    /// Ordinary scheduled work.
    Normal,
    /// Benchmarks and evaluations.
    Benchmark,
    /// Speculative exploration (spec §15.7).
    Speculative,
}

impl ReserveClass {
    /// Ladder from highest priority (lowest floor) to lowest priority.
    pub const LADDER: [Self; 8] = [
        Self::Incident,
        Self::Security,
        Self::Critical,
        Self::IntegrationRepair,
        Self::HumanInteractive,
        Self::Normal,
        Self::Benchmark,
        Self::Speculative,
    ];

    /// Stable name, spec §15.7 spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Incident => "incident",
            Self::Security => "security",
            Self::Critical => "critical",
            Self::IntegrationRepair => "integration_repair",
            Self::HumanInteractive => "human_interactive",
            Self::Normal => "normal",
            Self::Benchmark => "benchmark",
            Self::Speculative => "speculative",
        }
    }

    /// Position in [`ReserveClass::LADDER`]; zero is highest priority.
    #[must_use]
    pub const fn rank(self) -> usize {
        self as usize
    }

    /// True when `self` sits strictly above `other` on the ladder.
    #[must_use]
    pub const fn outranks(self, other: Self) -> bool {
        self.rank() < other.rank()
    }
}

impl fmt::Display for ReserveClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One class floor supplied by policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReserveClassFloor {
    /// Class governed by this row.
    pub class: ReserveClass,
    /// Percentage of opening capacity that must remain untouched.
    pub floor_percent: u16,
}

/// Exact policy subject retained in reservation and settlement records.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BudgetPolicySubject {
    policy_id: String,
    provenance: String,
    generation: u64,
}

impl BudgetPolicySubject {
    /// Content-bound policy identity derived by the validated snapshot.
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Exact upstream registry/configuration subject that supplied the policy.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// Configuration generation under which the policy was admitted.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Validated reserve floors for one exact policy subject and generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetPolicySnapshot {
    subject: BudgetPolicySubject,
    floors: [u8; ReserveClass::LADDER.len()],
}

impl BudgetPolicySnapshot {
    /// Validate one complete policy snapshot. The caller supplies provenance,
    /// never an identity: the identity is derived from provenance and floors.
    pub fn try_new(
        provenance: impl Into<String>,
        generation: u64,
        rules: impl IntoIterator<Item = ReserveClassFloor>,
    ) -> Result<Self, BudgetPolicyError> {
        let provenance = provenance.into();
        if provenance.is_empty()
            || provenance.len() > MAX_PROVENANCE_BYTES
            || !provenance.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(BudgetPolicyError::InvalidSubject(
                "provenance must contain 1..=256 printable ASCII bytes",
            ));
        }
        if generation == 0 || generation > MAX_SAFE_INTEGER {
            return Err(BudgetPolicyError::InvalidSubject(
                "generation must be within 1..=MAX_SAFE_INTEGER",
            ));
        }
        let mut floors = [None; ReserveClass::LADDER.len()];
        for rule in rules {
            if rule.floor_percent > 100 {
                return Err(BudgetPolicyError::OutOfRange {
                    class: rule.class,
                    floor_percent: rule.floor_percent,
                });
            }
            let slot = &mut floors[rule.class.rank()];
            if slot.replace(rule.floor_percent as u8).is_some() {
                return Err(BudgetPolicyError::DuplicateClass(rule.class));
            }
        }
        let mut values = [0; ReserveClass::LADDER.len()];
        for class in ReserveClass::LADDER {
            values[class.rank()] =
                floors[class.rank()].ok_or(BudgetPolicyError::MissingClass(class))?;
        }
        for pair in ReserveClass::LADDER.windows(2) {
            let (higher, lower) = (pair[0], pair[1]);
            if values[higher.rank()] >= values[lower.rank()] {
                return Err(BudgetPolicyError::NonMonotone {
                    higher,
                    higher_floor: values[higher.rank()],
                    lower,
                    lower_floor: values[lower.rank()],
                });
            }
        }
        let policy_id = derive_policy_id(&provenance, &values);
        Ok(Self {
            subject: BudgetPolicySubject {
                policy_id,
                provenance,
                generation,
            },
            floors: values,
        })
    }

    /// Exact subject bound into every admitted record.
    #[must_use]
    pub const fn subject(&self) -> &BudgetPolicySubject {
        &self.subject
    }

    /// Admitted floor percentage for `class`.
    #[must_use]
    pub const fn floor_percent(&self, class: ReserveClass) -> u8 {
        self.floors[class.rank()]
    }

    /// Admitted floor units for `class` and one dimension's opening capacity.
    #[must_use]
    pub const fn floor_units(&self, class: ReserveClass, opening: u64) -> u64 {
        floor_units(self.floor_percent(class), opening)
    }

    /// The integration-repair floor is the emergency boundary.
    #[must_use]
    pub const fn emergency_floor_units(&self, opening: u64) -> u64 {
        self.floor_units(ReserveClass::IntegrationRepair, opening)
    }

    /// Whether `class` may spend below the admitted emergency boundary.
    #[must_use]
    pub const fn may_spend_emergency_reserve(&self, class: ReserveClass) -> bool {
        class.outranks(ReserveClass::IntegrationRepair)
    }

    pub(crate) fn require_exact(&self, supplied: Option<&Self>) -> Result<(), BudgetPolicyError> {
        let supplied = supplied.ok_or(BudgetPolicyError::Missing)?;
        if supplied.subject.generation != self.subject.generation {
            return Err(BudgetPolicyError::WrongGeneration {
                expected: self.subject.generation,
                actual: supplied.subject.generation,
            });
        }
        if supplied != self {
            return Err(BudgetPolicyError::SnapshotMismatch);
        }
        Ok(())
    }
}

fn derive_policy_id(provenance: &str, floors: &[u8; ReserveClass::LADDER.len()]) -> String {
    let values = floors.map(|floor| floor.to_string()).join(",");
    format!(
        "budget-policy-v1:{}:{provenance}:{values}",
        provenance.len()
    )
}

/// Fail-closed policy snapshot refusal.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BudgetPolicyError {
    /// Reservation or settlement omitted its policy snapshot.
    #[error("budget policy snapshot missing")]
    Missing,
    /// Provenance or generation is not admissible.
    #[error("invalid budget policy subject: {0}")]
    InvalidSubject(&'static str),
    /// One class has no floor row.
    #[error("budget policy class missing: {0}")]
    MissingClass(ReserveClass),
    /// One class appears more than once.
    #[error("budget policy class duplicated: {0}")]
    DuplicateClass(ReserveClass),
    /// One floor is not a percentage.
    #[error("budget policy floor out of range for {class}: {floor_percent}")]
    OutOfRange {
        /// Class with the invalid floor.
        class: ReserveClass,
        /// Rejected percentage.
        floor_percent: u16,
    },
    /// Lower-priority classes must retain strictly more capacity.
    #[error(
        "budget policy floors are not monotone: {higher}={higher_floor}, {lower}={lower_floor}"
    )]
    NonMonotone {
        /// Higher-priority class.
        higher: ReserveClass,
        /// Higher-priority floor.
        higher_floor: u8,
        /// Adjacent lower-priority class.
        lower: ReserveClass,
        /// Lower-priority floor.
        lower_floor: u8,
    },
    /// Supplied policy belongs to another configuration generation.
    #[error("budget policy generation mismatch: expected {expected}, got {actual}")]
    WrongGeneration {
        /// Ledger's admitted generation.
        expected: u64,
        /// Supplied generation.
        actual: u64,
    },
    /// Supplied provenance or floor content differs from the admitted snapshot.
    #[error("budget policy snapshot does not match the admitted subject")]
    SnapshotMismatch,
}

impl BudgetPolicyError {
    /// Stable refusal code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Missing => "BUDGET_POLICY_MISSING",
            Self::InvalidSubject(_) => "BUDGET_POLICY_SUBJECT_INVALID",
            Self::MissingClass(_) => "BUDGET_POLICY_CLASS_MISSING",
            Self::DuplicateClass(_) => "BUDGET_POLICY_CLASS_DUPLICATE",
            Self::OutOfRange { .. } => "BUDGET_POLICY_FLOOR_OUT_OF_RANGE",
            Self::NonMonotone { .. } => "BUDGET_POLICY_FLOOR_NON_MONOTONE",
            Self::WrongGeneration { .. } => "BUDGET_POLICY_GENERATION_MISMATCH",
            Self::SnapshotMismatch => "BUDGET_POLICY_SNAPSHOT_MISMATCH",
        }
    }
}

/// `ceil(opening * percent / 100)`, never more than `opening`. Rounds up so a
/// non-zero floor on a tiny pot still holds at least one unit.
#[must_use]
pub const fn floor_units(percent: u8, opening: u64) -> u64 {
    let percent = if percent > 100 { 100 } else { percent } as u128;
    let scaled = opening as u128 * percent;
    let ceil = scaled / 100 + if scaled % 100 == 0 { 0 } else { 1 };
    // `ceil <= opening` because `percent <= 100`; the cast cannot truncate.
    ceil as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_and_floor_constants_are_the_recorded_policy() {
        let fixture = [
            (ReserveClass::Incident, "incident", 0),
            (ReserveClass::Security, "security", 2),
            (ReserveClass::Critical, "critical", 5),
            (ReserveClass::IntegrationRepair, "integration_repair", 10),
            (ReserveClass::HumanInteractive, "human_interactive", 15),
            (ReserveClass::Normal, "normal", 20),
            (ReserveClass::Benchmark, "benchmark", 40),
            (ReserveClass::Speculative, "speculative", 50),
        ];
        let policy = BudgetPolicySnapshot::try_new(
            "test-only:recorded-proposal",
            7,
            fixture.map(|(class, _, floor_percent)| ReserveClassFloor {
                class,
                floor_percent,
            }),
        )
        .expect("valid test policy");
        for (rank, (class, name, percent)) in fixture.into_iter().enumerate() {
            assert_eq!(ReserveClass::LADDER[rank], class);
            assert_eq!(class.rank(), rank);
            assert_eq!(class.name(), name);
            assert_eq!(class.to_string(), name);
            let json = serde_json::to_string(&class).expect("serialize");
            assert_eq!(json, format!("\"{name}\""), "serde name drift");
            assert_eq!(policy.floor_percent(class), percent as u8);
        }
        let emergency: Vec<ReserveClass> = ReserveClass::LADDER
            .into_iter()
            .filter(|class| policy.may_spend_emergency_reserve(*class))
            .collect();
        assert_eq!(
            emergency,
            [
                ReserveClass::Incident,
                ReserveClass::Security,
                ReserveClass::Critical
            ]
        );
        assert_eq!(policy.floor_units(ReserveClass::Normal, 100), 20);
        assert_eq!(policy.floor_units(ReserveClass::Normal, 3), 1);
        assert_eq!(policy.floor_units(ReserveClass::Incident, u64::MAX), 0);
        assert_eq!(
            policy.floor_units(ReserveClass::Speculative, u64::MAX),
            1 << 63
        );
        assert_eq!(policy.emergency_floor_units(1000), 100);
        assert_eq!(policy.subject().generation(), 7);
        assert_eq!(policy.subject().provenance(), "test-only:recorded-proposal");
        assert!(policy
            .subject()
            .policy_id()
            .starts_with("budget-policy-v1:"));
        assert!(ReserveClass::Incident.outranks(ReserveClass::Speculative));
        assert!(!ReserveClass::Speculative.outranks(ReserveClass::Normal));
        assert!(!ReserveClass::Normal.outranks(ReserveClass::Normal));
    }
}
