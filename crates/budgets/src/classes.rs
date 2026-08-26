//! Reserve classes (spec §15.7 `normal .. benchmark`) and the emergency floor
//! (spec Q6: emergency reserve floors cannot be consumed by speculative work).
//!
//! Policy proposal, recorded here as constants for the orchestrator to pin:
//!
//! * Each class carries a **floor percentage** of a dimension's opening known
//!   capacity that the class must leave untouched. A reservation is admitted
//!   only if `remaining - requested >= ceil(opening * floor / 100)`.
//! * The **emergency floor** is [`EMERGENCY_FLOOR_PERCENT`]. Classes whose own
//!   floor is *below* it may spend the emergency reserve; every other class has
//!   a floor at or above it and therefore can never cross it, whatever order
//!   reservations arrive in.
//! * The ladder is total: a class with a lower floor outranks one with a
//!   higher floor. Two classes never share a floor.
//!
//! No time, I/O, or provider knowledge lives here; floors are pure arithmetic.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Percent of each dimension's opening capacity held as emergency reserve.
/// Only classes with [`ReserveClass::may_spend_emergency_reserve`] can dig
/// below it.
pub const EMERGENCY_FLOOR_PERCENT: u8 = 10;

/// Reserve class, spelled as spec §15.7 lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveClass {
    /// Live incident response; may drain a dimension to zero.
    Incident,
    /// Security response; may spend the emergency reserve down to 2%.
    Security,
    /// Critical work; may spend the emergency reserve down to 5%.
    Critical,
    /// Repair of a broken integration branch; stops at the emergency floor.
    IntegrationRepair,
    /// A human is waiting on the result; must leave 15%.
    HumanInteractive,
    /// Ordinary scheduled work; must leave 20%.
    Normal,
    /// Benchmarks and evaluations; must leave 40%.
    Benchmark,
    /// Speculative exploration; must leave 50% and can never touch critical
    /// reserve (spec §15.7).
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

    /// Percent of opening capacity this class must leave untouched. Policy.
    #[must_use]
    pub const fn floor_percent(self) -> u8 {
        match self {
            Self::Incident => 0,
            Self::Security => 2,
            Self::Critical => 5,
            Self::IntegrationRepair => EMERGENCY_FLOOR_PERCENT,
            Self::HumanInteractive => 15,
            Self::Normal => 20,
            Self::Benchmark => 40,
            Self::Speculative => 50,
        }
    }

    /// Position in [`ReserveClass::LADDER`]; zero is highest priority.
    #[must_use]
    pub const fn rank(self) -> usize {
        self as usize
    }

    /// True when this class's floor is below the emergency floor, so it may
    /// spend the emergency reserve.
    #[must_use]
    pub const fn may_spend_emergency_reserve(self) -> bool {
        self.floor_percent() < EMERGENCY_FLOOR_PERCENT
    }

    /// True when `self` sits strictly above `other` on the ladder.
    #[must_use]
    pub const fn outranks(self, other: Self) -> bool {
        self.floor_percent() < other.floor_percent()
    }

    /// Units of `opening` this class must leave untouched in one dimension.
    #[must_use]
    pub const fn floor_units(self, opening: u64) -> u64 {
        floor_units(self.floor_percent(), opening)
    }
}

impl fmt::Display for ReserveClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
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

/// Emergency-reserve units for one dimension.
#[must_use]
pub const fn emergency_floor_units(opening: u64) -> u64 {
    floor_units(EMERGENCY_FLOOR_PERCENT, opening)
}

const fn ladder_is_strictly_ascending() -> bool {
    let mut index = 1;
    while index < ReserveClass::LADDER.len() {
        let above = ReserveClass::LADDER[index - 1];
        let below = ReserveClass::LADDER[index];
        if above.floor_percent() >= below.floor_percent() || above.rank() + 1 != below.rank() {
            return false;
        }
        index += 1;
    }
    true
}

const _: () = assert!(
    ladder_is_strictly_ascending(),
    "ladder floors must strictly ascend"
);
const _: () = assert!(
    ReserveClass::Critical.may_spend_emergency_reserve()
        && !ReserveClass::IntegrationRepair.may_spend_emergency_reserve(),
    "emergency reserve is open to incident/security/critical and closed from integration_repair down"
);
const _: () =
    assert!(ReserveClass::Speculative.floor_percent() > ReserveClass::Critical.floor_percent());
const _: () = assert!(EMERGENCY_FLOOR_PERCENT <= 100);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_and_floor_constants_are_the_recorded_policy() {
        assert_eq!(EMERGENCY_FLOOR_PERCENT, 10);
        let expected = [
            (ReserveClass::Incident, "incident", 0),
            (ReserveClass::Security, "security", 2),
            (ReserveClass::Critical, "critical", 5),
            (ReserveClass::IntegrationRepair, "integration_repair", 10),
            (ReserveClass::HumanInteractive, "human_interactive", 15),
            (ReserveClass::Normal, "normal", 20),
            (ReserveClass::Benchmark, "benchmark", 40),
            (ReserveClass::Speculative, "speculative", 50),
        ];
        for (rank, (class, name, percent)) in expected.into_iter().enumerate() {
            assert_eq!(ReserveClass::LADDER[rank], class);
            assert_eq!(class.rank(), rank);
            assert_eq!(class.name(), name);
            assert_eq!(class.to_string(), name);
            let json = serde_json::to_string(&class).expect("serialize");
            assert_eq!(json, format!("\"{name}\""), "serde name drift");
            assert_eq!(class.floor_percent(), percent);
        }
        let emergency: Vec<ReserveClass> = ReserveClass::LADDER
            .into_iter()
            .filter(|class| class.may_spend_emergency_reserve())
            .collect();
        assert_eq!(
            emergency,
            [
                ReserveClass::Incident,
                ReserveClass::Security,
                ReserveClass::Critical
            ]
        );
        assert_eq!(ReserveClass::Normal.floor_units(100), 20);
        assert_eq!(
            ReserveClass::Normal.floor_units(3),
            1,
            "ceil keeps one unit"
        );
        assert_eq!(ReserveClass::Normal.floor_units(0), 0);
        assert_eq!(ReserveClass::Incident.floor_units(u64::MAX), 0);
        assert_eq!(ReserveClass::Speculative.floor_units(u64::MAX), 1 << 63);
        assert_eq!(emergency_floor_units(1000), 100);
        assert!(ReserveClass::Incident.outranks(ReserveClass::Speculative));
        assert!(!ReserveClass::Speculative.outranks(ReserveClass::Normal));
        assert!(!ReserveClass::Normal.outranks(ReserveClass::Normal));
    }
}
