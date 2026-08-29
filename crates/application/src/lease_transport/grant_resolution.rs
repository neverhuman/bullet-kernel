//! Transaction-local resolution for grant-class lease operations.

use super::mint::{
    expectation_for, grant_subject, idempotency_digest, lease_request, SignedLeaseError,
};
use super::readback::ExpectedGrant;
use super::{presented, unknown_package, LeaseGrantRecord, SignedAcquireBody};
use crate::store::{CurrentPackage, LeaseTransportTxn};
use bullet_domain::{DomainError, VariantId};
use bullet_harness_core::lease_transport::{LeaseTransportExpectation, LeaseTransportOperation};

/// Resolve ordinary exact-one graph truth, except that an existing strict
/// grant first supplies its already-authorized Variant for replay.
pub(super) fn grant_truth(
    txn: &dyn LeaseTransportTxn,
    op: LeaseTransportOperation,
    body: &SignedAcquireBody,
    now_unix_ms: u64,
) -> Result<(LeaseTransportExpectation, ExpectedGrant), SignedLeaseError> {
    let package = match recorded_variant(txn, body)? {
        Some(variant) => txn
            .resolve_variant(&body.work_package_id, &variant)
            .map_err(unknown_package)?,
        None => txn
            .resolve_package(&body.work_package_id)
            .map_err(unknown_package)?,
    };
    grant_truth_for_package(txn, op, body, now_unix_ms, package)
}

/// Resolve one exact selected member for the feature-gated synthetic seam.
#[cfg(any(test, feature = "test-seams"))]
pub(super) fn grant_truth_for_variant(
    txn: &dyn LeaseTransportTxn,
    op: LeaseTransportOperation,
    body: &SignedAcquireBody,
    selected: &VariantId,
    now_unix_ms: u64,
) -> Result<(LeaseTransportExpectation, ExpectedGrant), SignedLeaseError> {
    if recorded_variant(txn, body)?.is_some_and(|recorded| recorded != *selected) {
        return Err(idempotency_conflict("variant_id"));
    }
    let package = txn
        .resolve_variant(&body.work_package_id, selected)
        .map_err(unknown_package)?;
    grant_truth_for_package(txn, op, body, now_unix_ms, package)
}

fn grant_truth_for_package(
    txn: &dyn LeaseTransportTxn,
    op: LeaseTransportOperation,
    body: &SignedAcquireBody,
    now_unix_ms: u64,
    package: CurrentPackage,
) -> Result<(LeaseTransportExpectation, ExpectedGrant), SignedLeaseError> {
    let authority = txn.current_authority()?;
    let request = lease_request(body, &package.mission.id, &package.variant.id);
    let subject = grant_subject(&request.workspace_id, &request.workspace_nonce, &authority)?;
    let presented = presented(&body.runner_id, body.runner_epoch, &body.work_package_id);
    let expected = expectation_for(
        op,
        body,
        presented,
        &body.idempotency_key,
        authority.authority_epoch(),
        subject.clone(),
        now_unix_ms,
    )?;
    let truth = ExpectedGrant {
        request,
        subject,
        request_digest: expected.request_digest.clone(),
    };
    Ok((expected, truth))
}

/// Validate exact signed request/body identity before a stored row's Variant
/// can influence graph resolution. A row transplanted beneath another digest
/// is corrupt store truth, not an idempotency conflict.
fn recorded_variant(
    txn: &dyn LeaseTransportTxn,
    body: &SignedAcquireBody,
) -> Result<Option<VariantId>, SignedLeaseError> {
    let digest = idempotency_digest(&body.idempotency_key)?;
    let Some(record) = txn.get_transport_grant(&digest)? else {
        return Ok(None);
    };
    if record.request.idempotency_key != body.idempotency_key
        || idempotency_digest(&record.request.idempotency_key)? != digest
    {
        return Err(SignedLeaseError::Ledger(LeaseGrantRecord::refused()));
    }
    let changed = [
        (
            record.grant.attempt.work_package_id != body.work_package_id,
            "work_package_id",
        ),
        (record.request.runner_id != body.runner_id, "runner_id"),
        (
            record.request.runner_epoch != body.runner_epoch,
            "runner_epoch",
        ),
        (
            record.request.ttl_seconds != body.ttl_seconds,
            "ttl_seconds",
        ),
    ];
    if let Some((_, field)) = changed.into_iter().find(|(differs, _)| *differs) {
        return Err(idempotency_conflict(field));
    }
    Ok(Some(record.request.variant_id))
}

fn idempotency_conflict(field: &str) -> SignedLeaseError {
    let reason = format!("lease-transport changed {field} under the same idempotency key");
    SignedLeaseError::Ledger(DomainError::Idempotency(reason).into())
}
