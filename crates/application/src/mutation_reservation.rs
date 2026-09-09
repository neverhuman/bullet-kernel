//! One-use mutation reservation. The active-lease check is repeated inside
//! the same write that issues the permit. A successful check is not itself
//! a capability.

#[path = "mutation_permit/mod.rs"]
pub mod mutation_permit;

use crate::authority::ActiveLeaseSubject;
use crate::store::LedgerError;
use bullet_domain::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Gate that must be re-checked inside the reservation write.
pub trait LeaseGate {
    /// Repeat [`crate::store::Ledger::check_active_lease`] for this subject.
    ///
    /// # Errors
    ///
    /// Stale or missing lease, or store failure.
    fn check_active_lease(&mut self, subject: &ActiveLeaseSubject) -> Result<(), LedgerError>;
}

/// Request to reserve exactly one mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MutationReserveRequest {
    /// Caller-chosen mutation identity.
    pub mutation_id: String,
    /// Hub-authored kebab-case mutation-operation label.
    pub operation: String,
    /// Domain-separated request digest (hex).
    pub request_digest: String,
}

/// One-use permit issued only after the in-write lease check succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OneUsePermit {
    /// Reservation identity.
    pub reservation_id: String,
    /// Bound mutation.
    pub mutation_id: String,
    /// Bound operation.
    pub operation: String,
    /// Bound request digest.
    pub request_digest: String,
}

/// Durable reservation row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ReservationRow {
    permit: OneUsePermit,
    attempt_id: String,
    fence: u64,
    spent: bool,
    settled: bool,
}

/// Fail-closed reservation errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReservationError {
    /// Lease check failed inside the write.
    #[error("lease gate refused: {0}")]
    LeaseRefused(String),
    /// Reservation already spent or settled.
    #[error("permit already consumed: {0}")]
    AlreadySpent(String),
    /// Unknown reservation.
    #[error("reservation not found: {0}")]
    NotFound(String),
    /// Subject or digest mismatch.
    #[error("reservation subject mismatch: {0}")]
    SubjectMismatch(String),
}

impl ReservationError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::LeaseRefused(_) => "LEASE_GATE_REFUSED",
            Self::AlreadySpent(_) => "PERMIT_ALREADY_SPENT",
            Self::NotFound(_) => "RESERVATION_NOT_FOUND",
            Self::SubjectMismatch(_) => "RESERVATION_SUBJECT_MISMATCH",
        }
    }
}

impl From<LedgerError> for ReservationError {
    fn from(error: LedgerError) -> Self {
        Self::LeaseRefused(format!("{}: {error}", error.reason_code()))
    }
}

/// In-process reservation ledger. Not a production Kernel endpoint.
pub struct MutationReservationStore<G> {
    gate: G,
    rows: BTreeMap<String, ReservationRow>,
}

impl<G: LeaseGate> MutationReservationStore<G> {
    /// Bind a lease gate.
    pub const fn new(gate: G) -> Self {
        Self {
            gate,
            rows: BTreeMap::new(),
        }
    }

    /// Check the active lease and insert a one-use permit in one write.
    ///
    /// # Errors
    ///
    /// Lease refused, or an existing unused reservation for the same mutation.
    pub fn reserve(
        &mut self,
        subject: &ActiveLeaseSubject,
        request: &MutationReserveRequest,
    ) -> Result<OneUsePermit, ReservationError> {
        if let Some(existing) = self.rows.get(&request.mutation_id) {
            if existing.permit.request_digest == request.request_digest
                && existing.permit.operation == request.operation
                && !existing.spent
            {
                return Err(ReservationError::AlreadySpent(
                    "exact mutation already reserved".into(),
                ));
            }
            return Err(ReservationError::SubjectMismatch(
                "mutation_id reused with a different subject".into(),
            ));
        }
        self.gate.check_active_lease(subject)?;
        let permit = OneUsePermit {
            reservation_id: format!(
                "rsv_{}",
                Digest::of(request.mutation_id.as_bytes()).to_hex()
            ),
            mutation_id: request.mutation_id.clone(),
            operation: request.operation.clone(),
            request_digest: request.request_digest.clone(),
        };
        self.rows.insert(
            request.mutation_id.clone(),
            ReservationRow {
                permit: permit.clone(),
                attempt_id: subject.attempt_id.to_string(),
                fence: subject.fence,
                spent: false,
                settled: false,
            },
        );
        Ok(permit)
    }

    /// Consume the permit after I/O. A second consume is refused.
    ///
    /// # Errors
    ///
    /// Missing, spent, or mismatched permit.
    pub fn settle(
        &mut self,
        permit: &OneUsePermit,
        subject: &ActiveLeaseSubject,
    ) -> Result<(), ReservationError> {
        self.gate.check_active_lease(subject)?;
        let row = self
            .rows
            .get_mut(&permit.mutation_id)
            .ok_or_else(|| ReservationError::NotFound(permit.mutation_id.clone()))?;
        if row.permit != *permit
            || row.attempt_id != subject.attempt_id.to_string()
            || row.fence != subject.fence
        {
            return Err(ReservationError::SubjectMismatch(
                "settle does not bind the reserved subject".into(),
            ));
        }
        if row.spent || row.settled {
            return Err(ReservationError::AlreadySpent(
                permit.reservation_id.clone(),
            ));
        }
        row.spent = true;
        row.settled = true;
        Ok(())
    }

    /// Number of times the gate was invoked by this store is owned by the gate.
    #[must_use]
    pub fn is_settled(&self, mutation_id: &str) -> bool {
        self.rows.get(mutation_id).is_some_and(|row| row.settled)
    }
}
