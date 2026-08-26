//! Dual-tree budget reservation and settlement.
//!
//! A reservation is not spend. Settlement must conserve reserved + remaining
//!   + unknown liability. `unknown` is retained and is never scheduled as
//!     headroom.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fail-closed budget error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetError {
    /// Reservation would exceed remaining known capacity.
    #[error("insufficient remaining capacity")]
    Insufficient,
    /// Settlement named a reservation that was never issued or already settled.
    #[error("reservation not found")]
    NotFound,
    /// Conservation identity failed.
    #[error("conservation violated")]
    Conservation,
    /// Unknown liability was treated as schedulable headroom.
    #[error("unknown liability is not headroom")]
    UnknownIsNotHeadroom,
}

impl BudgetError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Insufficient => "BUDGET_INSUFFICIENT",
            Self::NotFound => "BUDGET_RESERVATION_NOT_FOUND",
            Self::Conservation => "BUDGET_CONSERVATION",
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

/// Dual-tree ledger: reserved tree and remaining tree share one conservation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetLedger {
    remaining: u64,
    reserved: u64,
    settled: u64,
    unknown_liability: u64,
    open: Vec<Reservation>,
}

impl BudgetLedger {
    /// Open a ledger with known remaining capacity and retained unknown.
    #[must_use]
    pub fn new(remaining: u64, unknown_liability: u64) -> Self {
        Self {
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

    /// Conservation: remaining + reserved + settled equals the opening known pot.
    #[must_use]
    pub const fn conserved(&self, opening_known: u64) -> bool {
        self.remaining
            .saturating_add(self.reserved)
            .saturating_add(self.settled)
            == opening_known
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
        if amount > self.remaining {
            return Err(BudgetError::Insufficient);
        }
        self.remaining -= amount;
        self.reserved += amount;
        let row = Reservation {
            id: id.into(),
            amount,
        };
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
        let row = self.open.remove(index);
        self.reserved -= row.amount;
        let used = actual.min(row.amount);
        self.settled += used;
        self.remaining += row.amount - used;
        if actual > row.amount {
            self.unknown_liability += actual - row.amount;
        }
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
