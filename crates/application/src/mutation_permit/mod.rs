//! Mint and consume a short-lived `SignedMutationPermitV1` from a durable
//! active lease plus a one-use reservation. The harness admission boundary is
//! the first use site; a verified permit is not itself a spent reservation.

use crate::authority::ActiveLeaseSubject;
use crate::mutation_reservation::{
    LeaseGate, MutationReservationStore, OneUsePermit, ReservationError,
};
use bullet_domain::schema_bundle::SignedMutationPermitV1;
use bullet_harness_core::launch_grant::random_hex_64;
use bullet_harness_core::{
    mutation_operation_audience, parse_mutation_operation, require_signed_mutation_permit,
    MutationPermitClaims, MutationPermitExpectation, MutationPermitSigningKey,
    MutationPermitVerificationKey, MAX_MUTATION_PERMIT_TTL_MS, MUTATION_PERMIT_SCHEMA_VERSION,
};
use thiserror::Error;

/// Lease-held fields that are not on [`ActiveLeaseSubject`] today.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationPermitBinding {
    /// Repository the mutation targets.
    pub repository_id: String,
    /// Workspace generation observed at mint.
    pub workspace_generation: u64,
    /// Kernel authority epoch.
    pub authority_epoch: u64,
    /// Kernel freeze generation.
    pub freeze_generation: u64,
    /// Digest of the durable authority envelope the lease was minted under.
    pub authority_envelope_digest: String,
    /// Single-use nonce of that authority token.
    pub authority_token_nonce: String,
}

/// Fail-closed permit errors.
#[derive(Debug, Error)]
pub enum PermitError {
    /// Reservation row refused the write.
    #[error(transparent)]
    Reservation(#[from] ReservationError),
    /// Signed permit was missing, unbound, expired, or malformed.
    #[error("{0}")]
    Signed(bullet_harness_core::error::HarnessError),
}

impl PermitError {
    /// Stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Reservation(error) => error.reason_code(),
            Self::Signed(error) => error.reason_code(),
        }
    }
}

impl From<bullet_harness_core::error::HarnessError> for PermitError {
    fn from(error: bullet_harness_core::error::HarnessError) -> Self {
        Self::Signed(error)
    }
}

/// Mint a one-second PASETO permit after the reservation exists.
///
/// # Errors
///
/// Typed refusals when the reservation is not wire-shaped or signing fails.
pub fn mint_signed_permit(
    key: &MutationPermitSigningKey,
    subject: &ActiveLeaseSubject,
    reservation: &OneUsePermit,
    binding: &MutationPermitBinding,
    now_unix_ms: u64,
) -> Result<SignedMutationPermitV1, PermitError> {
    let operation = parse_mutation_operation(&reservation.operation)?;
    let claims = MutationPermitClaims {
        schema_version: MUTATION_PERMIT_SCHEMA_VERSION.to_owned(),
        issuer: key.issuer().to_owned(),
        audience: mutation_operation_audience(operation),
        operation,
        authority_envelope_digest: binding.authority_envelope_digest.clone(),
        authority_token_nonce: binding.authority_token_nonce.clone(),
        mutation_id: reservation.mutation_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        request_digest: reservation.request_digest.clone(),
        repository_id: binding.repository_id.clone(),
        workspace_id: subject.workspace_id.to_string(),
        workspace_generation: binding.workspace_generation,
        attempt_id: subject.attempt_id.to_string(),
        attempt_fence: subject.fence,
        authority_epoch: binding.authority_epoch,
        freeze_generation: binding.freeze_generation,
        issued_at_unix_ms: now_unix_ms,
        not_before_unix_ms: now_unix_ms,
        expires_at_unix_ms: now_unix_ms.saturating_add(MAX_MUTATION_PERMIT_TTL_MS),
        permit_nonce: random_hex_64()?,
    };
    key.sign(&claims).map_err(Into::into)
}

/// First use: require the signed permit, then consume the one-use reservation.
///
/// # Errors
///
/// Missing or unbound permit, closed time window, or a spent reservation.
pub fn consume_signed_permit<G: LeaseGate>(
    store: &mut MutationReservationStore<G>,
    key: &MutationPermitVerificationKey,
    permit: Option<&SignedMutationPermitV1>,
    subject: &ActiveLeaseSubject,
    reservation: &OneUsePermit,
    binding: &MutationPermitBinding,
    now_unix_ms: u64,
) -> Result<MutationPermitClaims, PermitError> {
    let operation = parse_mutation_operation(&reservation.operation)?;
    let expected = MutationPermitExpectation {
        audience: mutation_operation_audience(operation),
        operation,
        authority_envelope_digest: binding.authority_envelope_digest.clone(),
        authority_token_nonce: binding.authority_token_nonce.clone(),
        mutation_id: reservation.mutation_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        request_digest: reservation.request_digest.clone(),
        repository_id: binding.repository_id.clone(),
        workspace_id: subject.workspace_id.to_string(),
        workspace_generation: binding.workspace_generation,
        attempt_id: subject.attempt_id.to_string(),
        attempt_fence: subject.fence,
        authority_epoch: binding.authority_epoch,
        freeze_generation: binding.freeze_generation,
        now_unix_ms,
    };
    let claims = require_signed_mutation_permit(permit, key, &expected)?;
    store.settle(reservation, subject)?;
    Ok(claims)
}
