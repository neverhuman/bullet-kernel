//! Pure in-memory dual-tree budget reservation and settlement component.
//!
//! A reservation is not spend. Settlement conserves the known-capacity sum
//! of remaining, reserved, and settled units. Unknown liability is retained
//! separately and is never scheduled as headroom.
//!
//! This crate has no durable adapter and is not transaction or release proof.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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
