//! Short-lived mutation permits minted only from a durable active lease.

use crate::mutation_reservation::OneUsePermit;
use crate::nonce_ledger::{IssuedNonce, NonceError, NonceLedger};
use thiserror::Error;

/// Fail-closed mutation-permit error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MutationPermitError {
    /// No active lease may mint a permit.
    #[error("no active lease")]
    NoActiveLease,
    /// Underlying nonce ledger refused.
    #[error("nonce: {0}")]
    Nonce(NonceError),
}

impl MutationPermitError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::NoActiveLease => "MUTATION_PERMIT_NO_ACTIVE_LEASE",
            Self::Nonce(error) => error.reason_code(),
        }
    }
}

/// First use site for a signed mutation permit: bind a one-use reservation
/// to a nonce so the permit cannot be replayed.
pub fn mint_from_active_lease<L: NonceLedger>(
    ledger: &mut L,
    lease_is_active: bool,
    reservation: &OneUsePermit,
    nonce: &IssuedNonce,
) -> Result<OneUsePermit, MutationPermitError> {
    if !lease_is_active {
        return Err(MutationPermitError::NoActiveLease);
    }
    ledger
        .issue(&nonce.key, &nonce.digest)
        .map_err(MutationPermitError::Nonce)?;
    Ok(reservation.clone())
}

/// Consume the permit nonce. Verification of a stored nonce is not this path.
///
/// # Errors
///
/// Replay is `NONCE_CONSUMED`.
pub fn consume_permit<L: NonceLedger>(
    ledger: &mut L,
    nonce: &IssuedNonce,
) -> Result<(), MutationPermitError> {
    ledger
        .consume(&nonce.key, &nonce.digest)
        .map_err(MutationPermitError::Nonce)
}
