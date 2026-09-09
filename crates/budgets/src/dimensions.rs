//! Closed budget-dimension vocabulary, typed reservation vectors, per-invocation
//! usage, forecast-error settlement records, and the typed refusal vocabulary.
//!
//! The dimension list is the closure-roadmap Wave 2 sentence verbatim ("reserve
//! token, cost, call, wall-time, concurrency, provider quota, invocation, CPU,
//! memory, PIDs, disk, egress, output, artifact, verifier-backlog, effect, probe,
//! and CAS-liability budgets atomically"). Nothing is folded: the spec settles
//! tool `call`s and model `invocation`s as different events (§15.5 vs. the
//! "settle tool calls" step), so both stay distinct dimensions.

use crate::classes::{BudgetPolicyError, BudgetPolicySubject, ReserveClass};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Number of budget dimensions the roadmap names. Closed; adding one is a
/// roadmap change, not a code change.
pub const DIMENSION_COUNT: usize = 18;

/// One budget dimension. Serialized names are the roadmap spelling in
/// lower-case kebab form (`wall-time`, `provider-quota`, `cas-liability`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dimension {
    /// Model input/output/cache/reasoning tokens.
    Token,
    /// Monetary cost in the ledger's smallest currency unit.
    Cost,
    /// Tool calls issued by a harness session.
    Call,
    /// Wall-clock time in the ledger's tick unit.
    WallTime,
    /// Simultaneous in-flight invocations.
    Concurrency,
    /// Provider-quota units (requests, windows, credits) as one observed vector.
    ProviderQuota,
    /// Model invocations (spec §15.5 "before every invocation").
    Invocation,
    /// CPU time granted to the sandbox (cgroup v2 `cpu`).
    Cpu,
    /// Memory bytes granted to the sandbox (cgroup v2 `memory`).
    Memory,
    /// Process identifiers granted to the sandbox (cgroup v2 `pids`).
    Pids,
    /// Disk bytes for workspace and scratch.
    Disk,
    /// Network egress bytes.
    Egress,
    /// Captured stdout/stderr/log bytes.
    Output,
    /// Artifact bytes retained past the attempt.
    Artifact,
    /// Verifier queue depth this writer may add to (potential C10 backpressure).
    VerifierBacklog,
    /// External effects (mutations outside the workspace) the attempt may perform.
    Effect,
    /// Probes (read-only observations of external state) the attempt may issue.
    Probe,
    /// CAS bytes the attempt may leave as un-collected liability.
    CasLiability,
}

impl Dimension {
    /// Every dimension in canonical (roadmap) order. Refusals name the first
    /// failing dimension in this order.
    pub const ALL: [Self; DIMENSION_COUNT] = [
        Self::Token,
        Self::Cost,
        Self::Call,
        Self::WallTime,
        Self::Concurrency,
        Self::ProviderQuota,
        Self::Invocation,
        Self::Cpu,
        Self::Memory,
        Self::Pids,
        Self::Disk,
        Self::Egress,
        Self::Output,
        Self::Artifact,
        Self::VerifierBacklog,
        Self::Effect,
        Self::Probe,
        Self::CasLiability,
    ];

    /// Stable name (roadmap spelling, lower-case kebab).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Cost => "cost",
            Self::Call => "call",
            Self::WallTime => "wall-time",
            Self::Concurrency => "concurrency",
            Self::ProviderQuota => "provider-quota",
            Self::Invocation => "invocation",
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Pids => "pids",
            Self::Disk => "disk",
            Self::Egress => "egress",
            Self::Output => "output",
            Self::Artifact => "artifact",
            Self::VerifierBacklog => "verifier-backlog",
            Self::Effect => "effect",
            Self::Probe => "probe",
            Self::CasLiability => "cas-liability",
        }
    }

    /// Position in [`Dimension::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Dimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Typed per-dimension unit vector. Zero in a dimension means "not requested".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReservationVector {
    units: [u64; DIMENSION_COUNT],
}

impl ReservationVector {
    /// The empty vector.
    pub const ZERO: Self = Self {
        units: [0; DIMENSION_COUNT],
    };

    /// Builder: set one dimension.
    #[must_use]
    pub const fn with(mut self, dimension: Dimension, units: u64) -> Self {
        self.units[dimension.index()] = units;
        self
    }

    /// Build from a per-dimension function.
    pub fn from_fn(mut f: impl FnMut(Dimension) -> u64) -> Self {
        let mut vector = Self::ZERO;
        for dimension in Dimension::ALL {
            vector.units[dimension.index()] = f(dimension);
        }
        vector
    }

    /// Units in one dimension.
    #[must_use]
    pub const fn get(&self, dimension: Dimension) -> u64 {
        self.units[dimension.index()]
    }

    /// Set one dimension in place.
    pub fn set(&mut self, dimension: Dimension, units: u64) {
        self.units[dimension.index()] = units;
    }

    /// True when no dimension is requested.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.units.iter().all(|units| *units == 0)
    }

    /// Every dimension with its units, canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (Dimension, u64)> + '_ {
        Dimension::ALL
            .into_iter()
            .map(move |dimension| (dimension, self.get(dimension)))
    }

    /// Only requested (non-zero) dimensions, canonical order.
    pub fn nonzero(&self) -> impl Iterator<Item = (Dimension, u64)> + '_ {
        self.iter().filter(|(_, units)| *units > 0)
    }
}

/// Observed usage in one dimension. `Unknown` is the fail-closed default: the
/// forecast stays retained and is never returned to headroom.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Usage {
    /// Usage could not be observed; the reservation is retained, not released.
    #[default]
    Unknown,
    /// Usage was observed exactly.
    Known(u64),
}

/// Per-dimension usage vector. Defaults to `Unknown` everywhere.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UsageVector {
    usage: [Usage; DIMENSION_COUNT],
}

impl UsageVector {
    /// Nothing observed: every reserved dimension stays retained.
    pub const UNKNOWN: Self = Self {
        usage: [Usage::Unknown; DIMENSION_COUNT],
    };

    /// Every dimension known exactly as `vector` says (zero where absent).
    #[must_use]
    pub fn known(vector: &ReservationVector) -> Self {
        let mut usage = Self::UNKNOWN;
        for (dimension, units) in vector.iter() {
            usage.usage[dimension.index()] = Usage::Known(units);
        }
        usage
    }

    /// Builder: mark one dimension as observed.
    #[must_use]
    pub const fn with_known(mut self, dimension: Dimension, units: u64) -> Self {
        self.usage[dimension.index()] = Usage::Known(units);
        self
    }

    /// Builder: mark one dimension as unobserved.
    #[must_use]
    pub const fn with_unknown(mut self, dimension: Dimension) -> Self {
        self.usage[dimension.index()] = Usage::Unknown;
        self
    }

    /// Usage in one dimension.
    #[must_use]
    pub const fn get(&self, dimension: Dimension) -> Usage {
        self.usage[dimension.index()]
    }
}

/// How observed usage compared with the forecast in one dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForecastOutcome {
    /// Usage equalled the forecast.
    Exact,
    /// Usage fell short; `residual` returned to headroom.
    Under {
        /// Units returned to remaining.
        residual: u64,
    },
    /// Usage exceeded the forecast; `overrun` is unknown liability (spec §15.5
    /// "overrun creates a forecast-error event").
    Over {
        /// Units spent beyond the forecast.
        overrun: u64,
    },
    /// Usage was not observed; `retained` stays held and is never headroom.
    Unknown {
        /// Units kept reserved.
        retained: u64,
    },
    /// Usage exceeded a zero forecast; `overrun` is liability outside the pot.
    UnforecastOverrun {
        /// Units spent with no forecast at all.
        overrun: u64,
    },
    /// Usage of unknown size on a dimension that was never reserved. Liability
    /// of unknown size: the pot counts the event, it cannot size it.
    UnforecastUnknown,
}

impl ForecastOutcome {
    /// True for outcomes that leave liability behind (`Over`, `Unknown`, and
    /// both `Unforecast*` rows); `Under` is a forecast error too but is safe.
    #[must_use]
    pub const fn is_liability(self) -> bool {
        matches!(
            self,
            Self::Over { .. }
                | Self::Unknown { .. }
                | Self::UnforecastOverrun { .. }
                | Self::UnforecastUnknown
        )
    }
}

/// One dimension's forecast-versus-usage row (spec Q4: estimation error updates
/// the forecaster).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ForecastError {
    /// Dimension this row settles.
    pub dimension: Dimension,
    /// Units forecast at reservation.
    pub forecast: u64,
    /// Usage observed at settlement.
    pub usage: Usage,
    /// Comparison outcome.
    pub outcome: ForecastOutcome,
}

/// Settlement record: the whole forecast, the whole observation, and one row
/// per dimension that was forecast or used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    /// Reservation identity.
    pub id: String,
    /// Reserve class the reservation was admitted under.
    pub class: ReserveClass,
    /// Exact policy identity and generation used for admission.
    pub policy: BudgetPolicySubject,
    /// Forecast vector at reservation.
    pub forecast: ReservationVector,
    /// Observed usage at settlement.
    pub usage: UsageVector,
    /// Per-dimension rows, canonical order.
    pub errors: Vec<ForecastError>,
}

impl SettlementRecord {
    /// True when any dimension overran or was unobserved.
    #[must_use]
    pub fn is_forecast_error_event(&self) -> bool {
        self.errors.iter().any(|row| row.outcome.is_liability())
    }

    /// Row for one dimension, if that dimension was forecast or used.
    #[must_use]
    pub fn row(&self, dimension: Dimension) -> Option<&ForecastError> {
        self.errors.iter().find(|row| row.dimension == dimension)
    }

    /// Dimensions consumed in unknown amount without ever being reserved:
    /// liability of unknown size, surfaced rather than silenced.
    pub fn unforecast_unknown(&self) -> impl Iterator<Item = Dimension> + '_ {
        self.errors
            .iter()
            .filter(|row| row.outcome == ForecastOutcome::UnforecastUnknown)
            .map(|row| row.dimension)
    }
}

/// One dimension's pot. Conservation: `remaining + reserved + retained +
/// settled == opening`. `overrun` is spend beyond forecast and lives outside
/// the pot; `retained` is forecast whose usage was never observed. Neither is
/// ever headroom.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionState {
    /// Immutable opening known capacity.
    pub opening: u64,
    /// Schedulable headroom.
    pub remaining: u64,
    /// Held by open reservations.
    pub reserved: u64,
    /// Held by closed reservations whose usage is unknown. Never returns.
    pub retained: u64,
    /// Known spend within forecast.
    pub settled: u64,
    /// Known spend beyond forecast (unknown liability outside the pot).
    pub overrun: u64,
    /// Settlements that consumed an unknown amount with no forecast. Liability
    /// of unknown size: counted, never sized, never headroom.
    pub unknown_events: u64,
}

impl DimensionState {
    /// Conservation identity for this dimension.
    #[must_use]
    pub fn conserved(&self) -> bool {
        self.remaining
            .checked_add(self.reserved)
            .and_then(|sum| sum.checked_add(self.retained))
            .and_then(|sum| sum.checked_add(self.settled))
            == Some(self.opening)
    }

    /// Retained plus overrun; `None` on overflow.
    #[must_use]
    pub fn unknown_liability(&self) -> Option<u64> {
        self.retained.checked_add(self.overrun)
    }

    /// True when any unknown liability exists, sized or not.
    #[must_use]
    pub const fn has_unknown_liability(&self) -> bool {
        self.retained > 0 || self.overrun > 0 || self.unknown_events > 0
    }
}

/// One admitted multi-dimension reservation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorReservation {
    /// Caller identity, unique for the ledger lifetime.
    pub id: String,
    /// Class the reservation was admitted under.
    pub class: ReserveClass,
    /// Exact policy identity and generation used for admission.
    pub policy: BudgetPolicySubject,
    /// Forecast vector held.
    pub forecast: ReservationVector,
}

/// Fail-closed multi-dimension budget refusal. Every variant that concerns one
/// dimension names it; refusals name the first failing dimension in
/// [`Dimension::ALL`] order and leave the ledger untouched.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DimensionError {
    /// Policy snapshot admission failed before budget accounting.
    #[error(transparent)]
    Policy(#[from] BudgetPolicyError),
    /// Reservation identity or vector is not admissible.
    #[error("invalid reservation: {0}")]
    Invalid(String),
    /// Reservation identity has already been issued during this ledger lifetime.
    #[error("duplicate reservation: {0}")]
    Duplicate(String),
    /// A dimension cannot cover the request from remaining.
    #[error("dimension {dimension} exhausted: requested {requested}, remaining {remaining}")]
    Exhausted {
        /// First exhausted dimension.
        dimension: Dimension,
        /// Units requested in that dimension.
        requested: u64,
        /// Units remaining in that dimension.
        remaining: u64,
    },
    /// The request would take a dimension below the class's floor.
    #[error(
        "class {class} cannot cross its floor on {dimension}: floor {floor}, remaining {remaining}, requested {requested}"
    )]
    BelowFloor {
        /// First dimension whose floor would be crossed.
        dimension: Dimension,
        /// Reserve class that requested.
        class: ReserveClass,
        /// Units the class must leave untouched.
        floor: u64,
        /// Units remaining before the request.
        remaining: u64,
        /// Units requested.
        requested: u64,
    },
    /// Settlement or release named a reservation that is not open.
    #[error("reservation not found")]
    NotFound,
    /// Conservation identity failed in one dimension.
    #[error("conservation violated on {0}")]
    Conservation(Dimension),
    /// A checked accounting operation exceeded the supported integer range.
    #[error("budget arithmetic overflow on {0}")]
    ArithmeticOverflow(Dimension),
    /// Unknown liability was treated as schedulable headroom.
    #[error("unknown liability on {0} is not headroom")]
    UnknownIsNotHeadroom(Dimension),
}

impl DimensionError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Policy(error) => error.reason_code(),
            Self::Invalid(_) => "BUDGET_RESERVATION_INVALID",
            Self::Duplicate(_) => "BUDGET_RESERVATION_DUPLICATE",
            Self::Exhausted { .. } => "BUDGET_DIMENSION_EXHAUSTED",
            Self::BelowFloor { .. } => "BUDGET_CLASS_FLOOR",
            Self::NotFound => "BUDGET_RESERVATION_NOT_FOUND",
            Self::Conservation(_) => "BUDGET_CONSERVATION",
            Self::ArithmeticOverflow(_) => "BUDGET_ARITHMETIC_OVERFLOW",
            Self::UnknownIsNotHeadroom(_) => "BUDGET_UNKNOWN_NOT_HEADROOM",
        }
    }

    /// The dimension a refusal names, when it names one.
    #[must_use]
    pub const fn dimension(&self) -> Option<Dimension> {
        match self {
            Self::Exhausted { dimension, .. } | Self::BelowFloor { dimension, .. } => {
                Some(*dimension)
            }
            Self::Conservation(dimension)
            | Self::ArithmeticOverflow(dimension)
            | Self::UnknownIsNotHeadroom(dimension) => Some(*dimension),
            Self::Policy(_) | Self::Invalid(_) | Self::Duplicate(_) | Self::NotFound => None,
        }
    }
}
