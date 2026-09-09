//! Pure in-memory dual-tree budget reservation and settlement component.
//!
//! A reservation is not spend. Settlement conserves the known-capacity sum
//! of remaining, reserved, and settled units. Unknown liability is retained
//! separately and is never scheduled as headroom.
//!
//! This crate has no durable adapter and is not transaction or release proof.
//!
//! Two ledgers live here. [`BudgetLedger`] is the original single-dimension
//! ledger. [`VectorLedger`] reserves every roadmap dimension atomically under a
//! reserve class and an exact admitted [`BudgetPolicySnapshot`], then settles
//! with forecast-error records. Neither knows time; `expires_at` belongs to the
//! durable Wave 2 adapter that owns database time.

pub mod classes;
pub mod dimensions;

pub use classes::{
    floor_units, BudgetPolicyError, BudgetPolicySnapshot, BudgetPolicySubject, ReserveClass,
    ReserveClassFloor,
};
pub use dimensions::{
    Dimension, DimensionError, DimensionState, ForecastError, ForecastOutcome, ReservationVector,
    SettlementRecord, Usage, UsageVector, VectorReservation, DIMENSION_COUNT,
};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Fail-closed budget error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetError {
    /// Reservation identity or amount is not admissible.
    #[error("invalid reservation: {0}")]
    Invalid(String),
    /// Reservation identity has already been issued during this ledger lifetime.
    #[error("duplicate reservation: {0}")]
    Duplicate(String),
    /// Reservation would exceed remaining known capacity.
    #[error("insufficient remaining capacity")]
    Insufficient,
    /// Settlement named a reservation that was never issued or already settled.
    #[error("reservation not found")]
    NotFound,
    /// Conservation identity failed.
    #[error("conservation violated")]
    Conservation,
    /// A checked accounting operation exceeded the supported integer range.
    #[error("budget arithmetic overflow")]
    ArithmeticOverflow,
    /// Unknown liability was treated as schedulable headroom.
    #[error("unknown liability is not headroom")]
    UnknownIsNotHeadroom,
}

impl BudgetError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "BUDGET_RESERVATION_INVALID",
            Self::Duplicate(_) => "BUDGET_RESERVATION_DUPLICATE",
            Self::Insufficient => "BUDGET_INSUFFICIENT",
            Self::NotFound => "BUDGET_RESERVATION_NOT_FOUND",
            Self::Conservation => "BUDGET_CONSERVATION",
            Self::ArithmeticOverflow => "BUDGET_ARITHMETIC_OVERFLOW",
            Self::UnknownIsNotHeadroom => "BUDGET_UNKNOWN_NOT_HEADROOM",
        }
    }
}

/// One reservation row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    /// Caller identity.
    pub id: String,
    /// Reserved units.
    pub amount: u64,
}

/// In-memory dual-tree ledger. Remaining, reserved, and settled share one
/// known-capacity conservation; unknown liability is retained separately.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetLedger {
    opening_known: u64,
    remaining: u64,
    reserved: u64,
    settled: u64,
    unknown_liability: u64,
    open: Vec<Reservation>,
    issued_ids: BTreeSet<String>,
}

impl BudgetLedger {
    /// Open a ledger with known remaining capacity and retained unknown.
    #[must_use]
    pub fn new(remaining: u64, unknown_liability: u64) -> Self {
        Self {
            opening_known: remaining,
            remaining,
            unknown_liability,
            ..Self::default()
        }
    }

    /// Known remaining units. Unknown is excluded.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Units reserved and not yet settled.
    #[must_use]
    pub const fn reserved(&self) -> u64 {
        self.reserved
    }

    /// Retained unknown liability. Never added to remaining.
    #[must_use]
    pub const fn unknown_liability(&self) -> u64 {
        self.unknown_liability
    }

    /// Conservation: remaining + reserved + settled equals the immutable opening known pot.
    #[must_use]
    pub fn conserved(&self) -> bool {
        self.remaining
            .checked_add(self.reserved)
            .and_then(|value| value.checked_add(self.settled))
            == Some(self.opening_known)
    }

    /// Reserve from remaining. Unknown cannot fund this.
    ///
    /// # Errors
    ///
    /// `BUDGET_INSUFFICIENT` when remaining cannot cover `amount`.
    pub fn reserve(
        &mut self,
        id: impl Into<String>,
        amount: u64,
    ) -> Result<Reservation, BudgetError> {
        let id = id.into();
        if id.is_empty() || amount == 0 {
            return Err(BudgetError::Invalid(
                "id must be non-empty and amount must be positive".into(),
            ));
        }
        if self.issued_ids.contains(&id) {
            return Err(BudgetError::Duplicate(id));
        }
        if amount > self.remaining {
            return Err(BudgetError::Insufficient);
        }
        let next_reserved = self
            .reserved
            .checked_add(amount)
            .ok_or(BudgetError::ArithmeticOverflow)?;
        let next_remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(BudgetError::Conservation)?;
        let row = Reservation { id, amount };
        self.remaining = next_remaining;
        self.reserved = next_reserved;
        self.issued_ids.insert(row.id.clone());
        self.open.push(row.clone());
        Ok(row)
    }

    /// Settle an open reservation against actual spend.
    ///
    /// Unused reserved units return to remaining. Overspend becomes unknown
    /// liability and is never treated as remaining.
    ///
    /// # Errors
    ///
    /// `BUDGET_RESERVATION_NOT_FOUND` when `id` is not open.
    pub fn settle(&mut self, id: &str, actual: u64) -> Result<(), BudgetError> {
        let index = self
            .open
            .iter()
            .position(|row| row.id == id)
            .ok_or(BudgetError::NotFound)?;
        let row = &self.open[index];
        let used = actual.min(row.amount);
        let returned = row.amount - used;
        let overspend = actual - used;
        let next_reserved = self
            .reserved
            .checked_sub(row.amount)
            .ok_or(BudgetError::Conservation)?;
        let next_settled = self
            .settled
            .checked_add(used)
            .ok_or(BudgetError::ArithmeticOverflow)?;
        let next_remaining = self
            .remaining
            .checked_add(returned)
            .ok_or(BudgetError::ArithmeticOverflow)?;
        let next_unknown = self
            .unknown_liability
            .checked_add(overspend)
            .ok_or(BudgetError::ArithmeticOverflow)?;
        self.open.remove(index);
        self.reserved = next_reserved;
        self.settled = next_settled;
        self.remaining = next_remaining;
        self.unknown_liability = next_unknown;
        Ok(())
    }

    /// Refuse to schedule unknown liability as headroom.
    ///
    /// # Errors
    ///
    /// Always `BUDGET_UNKNOWN_NOT_HEADROOM` when unknown is nonzero and the
    /// caller asks to treat it as remaining.
    pub fn unknown_as_headroom(&self) -> Result<u64, BudgetError> {
        if self.unknown_liability > 0 {
            return Err(BudgetError::UnknownIsNotHeadroom);
        }
        Ok(0)
    }
}

/// In-memory ledger over every roadmap dimension. `reserve` is all-or-nothing:
/// a refusal names the first failing dimension and changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorLedger {
    policy: BudgetPolicySnapshot,
    pots: [DimensionState; DIMENSION_COUNT],
    open: BTreeMap<String, VectorReservation>,
    issued: BTreeSet<String>,
}

fn add(dimension: Dimension, left: u64, right: u64) -> Result<u64, DimensionError> {
    left.checked_add(right)
        .ok_or(DimensionError::ArithmeticOverflow(dimension))
}

fn sub(dimension: Dimension, left: u64, right: u64) -> Result<u64, DimensionError> {
    left.checked_sub(right)
        .ok_or(DimensionError::Conservation(dimension))
}

fn check(dimension: Dimension, pot: &DimensionState) -> Result<(), DimensionError> {
    if pot.conserved() {
        Ok(())
    } else {
        Err(DimensionError::Conservation(dimension))
    }
}

impl VectorLedger {
    /// Open a ledger with known capacity, pre-existing unknown liability, and
    /// the exact policy snapshot admitted by the owning authority boundary.
    #[must_use]
    pub fn new(
        opening: ReservationVector,
        unknown: ReservationVector,
        policy: BudgetPolicySnapshot,
    ) -> Self {
        let mut pots = [DimensionState::default(); DIMENSION_COUNT];
        for (dimension, units) in opening.iter() {
            pots[dimension.index()] = DimensionState {
                opening: units,
                remaining: units,
                overrun: unknown.get(dimension),
                ..DimensionState::default()
            };
        }
        Self {
            policy,
            pots,
            open: BTreeMap::new(),
            issued: BTreeSet::new(),
        }
    }

    /// Exact policy snapshot pinned when this ledger was opened.
    #[must_use]
    pub const fn policy(&self) -> &BudgetPolicySnapshot {
        &self.policy
    }

    /// Snapshot of one dimension.
    #[must_use]
    pub const fn state(&self, dimension: Dimension) -> DimensionState {
        self.pots[dimension.index()]
    }

    /// Schedulable headroom per dimension: remaining only.
    #[must_use]
    pub fn headroom(&self) -> ReservationVector {
        ReservationVector::from_fn(|dimension| self.state(dimension).remaining)
    }

    /// Conservation holds in every dimension.
    #[must_use]
    pub fn conserved(&self) -> bool {
        self.pots.iter().all(DimensionState::conserved)
    }

    /// Open reservations in id order.
    pub fn open(&self) -> impl Iterator<Item = &VectorReservation> {
        self.open.values()
    }

    /// Refuse to schedule unknown liability as headroom.
    ///
    /// # Errors
    ///
    /// `BUDGET_UNKNOWN_NOT_HEADROOM` when retained, overrun, or unforecast
    /// unknown events are nonzero.
    pub fn unknown_as_headroom(&self, dimension: Dimension) -> Result<u64, DimensionError> {
        let pot = self.state(dimension);
        if pot.has_unknown_liability() {
            return Err(DimensionError::UnknownIsNotHeadroom(dimension));
        }
        Ok(0)
    }

    /// Reserve `forecast` in every requested dimension at once under `class`.
    ///
    /// # Errors
    ///
    /// `BUDGET_POLICY_*` when the exact admitted snapshot is absent or differs;
    /// `BUDGET_DIMENSION_EXHAUSTED` naming the first dimension (canonical
    /// order) that cannot cover its units; `BUDGET_CLASS_FLOOR` when the class
    /// would cross its floor there; `BUDGET_RESERVATION_INVALID`,
    /// `BUDGET_RESERVATION_DUPLICATE`. On any error nothing changes.
    pub fn reserve(
        &mut self,
        id: impl Into<String>,
        class: ReserveClass,
        forecast: ReservationVector,
        policy: Option<&BudgetPolicySnapshot>,
    ) -> Result<VectorReservation, DimensionError> {
        self.policy.require_exact(policy)?;
        let id = id.into();
        if id.is_empty() || forecast.is_zero() {
            return Err(DimensionError::Invalid(
                "id must be non-empty and at least one dimension must be positive".into(),
            ));
        }
        if self.issued.contains(&id) {
            return Err(DimensionError::Duplicate(id));
        }
        let mut next = self.pots;
        for (dimension, requested) in forecast.nonzero() {
            let pot = &mut next[dimension.index()];
            let remaining = pot.remaining;
            if requested > remaining {
                return Err(DimensionError::Exhausted {
                    dimension,
                    requested,
                    remaining,
                });
            }
            let after = remaining - requested;
            let floor = self.policy.floor_units(class, pot.opening);
            if after < floor {
                return Err(DimensionError::BelowFloor {
                    dimension,
                    class,
                    floor,
                    remaining,
                    requested,
                });
            }
            pot.reserved = add(dimension, pot.reserved, requested)?;
            pot.remaining = after;
            check(dimension, pot)?;
        }
        let row = VectorReservation {
            id,
            class,
            policy: self.policy.subject().clone(),
            forecast,
        };
        self.pots = next;
        self.issued.insert(row.id.clone());
        self.open.insert(row.id.clone(), row.clone());
        Ok(row)
    }

    /// Settle an open reservation against observed usage. Exact and under
    /// return the residual to remaining; over adds overrun; unknown moves the
    /// forecast to retained, where it is never headroom. Usage on a dimension
    /// that was never forecast is `UnforecastOverrun` (sized, outside the pot)
    /// or `UnforecastUnknown` (counted event); known zero there is no row.
    ///
    /// # Errors
    ///
    /// `BUDGET_POLICY_*` when the exact admitted snapshot is absent or differs;
    /// `BUDGET_RESERVATION_NOT_FOUND`; `BUDGET_ARITHMETIC_OVERFLOW` when
    /// overrun cannot be recorded. On any error nothing changes.
    pub fn settle(
        &mut self,
        id: &str,
        usage: &UsageVector,
        policy: Option<&BudgetPolicySnapshot>,
    ) -> Result<SettlementRecord, DimensionError> {
        self.policy.require_exact(policy)?;
        let row = self.open.get(id).ok_or(DimensionError::NotFound)?.clone();
        let mut next = self.pots;
        let mut errors = Vec::new();
        for (dimension, forecast) in row.forecast.iter() {
            let observed = usage.get(dimension);
            let pot = &mut next[dimension.index()];
            let outcome = match observed {
                Usage::Known(0) if forecast == 0 => continue,
                Usage::Unknown if forecast == 0 => {
                    pot.unknown_events = add(dimension, pot.unknown_events, 1)?;
                    ForecastOutcome::UnforecastUnknown
                }
                Usage::Known(actual) if forecast == 0 => {
                    pot.overrun = add(dimension, pot.overrun, actual)?;
                    ForecastOutcome::UnforecastOverrun { overrun: actual }
                }
                Usage::Unknown => {
                    pot.retained = add(dimension, pot.retained, forecast)?;
                    ForecastOutcome::Unknown { retained: forecast }
                }
                Usage::Known(actual) => {
                    let used = actual.min(forecast);
                    let (residual, overrun) = (forecast - used, actual - used);
                    pot.settled = add(dimension, pot.settled, used)?;
                    pot.remaining = add(dimension, pot.remaining, residual)?;
                    pot.overrun = add(dimension, pot.overrun, overrun)?;
                    if overrun > 0 {
                        ForecastOutcome::Over { overrun }
                    } else if residual > 0 {
                        ForecastOutcome::Under { residual }
                    } else {
                        ForecastOutcome::Exact
                    }
                }
            };
            pot.reserved = sub(dimension, pot.reserved, forecast)?;
            check(dimension, pot)?;
            errors.push(ForecastError {
                dimension,
                forecast,
                usage: observed,
                outcome,
            });
        }
        self.pots = next;
        self.open.remove(id);
        Ok(SettlementRecord {
            id: row.id,
            class: row.class,
            policy: row.policy,
            forecast: row.forecast,
            usage: *usage,
            errors,
        })
    }

    /// Release an open reservation unused: every forecast unit returns to
    /// remaining. Produces no forecast-error record.
    ///
    /// # Errors
    ///
    /// `BUDGET_RESERVATION_NOT_FOUND`.
    pub fn release(&mut self, id: &str) -> Result<ReservationVector, DimensionError> {
        let row = self.open.get(id).ok_or(DimensionError::NotFound)?.clone();
        let mut next = self.pots;
        for (dimension, forecast) in row.forecast.nonzero() {
            let pot = &mut next[dimension.index()];
            pot.reserved = sub(dimension, pot.reserved, forecast)?;
            pot.remaining = add(dimension, pot.remaining, forecast)?;
            check(dimension, pot)?;
        }
        self.pots = next;
        self.open.remove(id);
        Ok(row.forecast)
    }
}
