//! Immutable terminal lease outcomes and historical exact-subject readback.

use super::mint::{
    expectation_for, grant_subject, idempotency_digest, incarnation_truth, legal_transition,
    no_mismatch,
};
use super::{
    presented, KernelLeaseTransport, SignedAdvanceBody, SignedLeaseError, SignedReleaseBody,
};
use crate::records::ReleaseRequest;
use crate::store::{LeaseTransportTxn, Ledger};
use bullet_domain::Attempt;
use bullet_harness_core::lease_transport::LeaseTransportOperation;

mod record;

pub use record::{
    AdvanceSettlementRequest, LeaseSettlementOutcome, LeaseSettlementRecord,
    LeaseSettlementRequest, ReleaseSettlementRequest, LEASE_SETTLEMENT_RECORD_VERSION,
};

impl super::SignedAcquireBody {
    /// Canonical lease-transport digest of this exact acquire source.
    ///
    /// # Errors
    /// Canonical encoding refusal.
    pub fn request_digest(&self) -> Result<String, SignedLeaseError> {
        bullet_harness_core::lease_transport::request_digest(self)
            .map_err(SignedLeaseError::Transport)
    }
}

impl KernelLeaseTransport {
    /// Apply or replay one exact terminal request.
    ///
    /// Existing outcomes bypass current authority. New outcomes re-derive the
    /// acquire source, authority, live lease, fence, and expected state inside
    /// the same transaction that mutates and appends the immutable record.
    ///
    /// # Errors
    /// Typed authority, transition, idempotency, or store refusal.
    pub fn settle<L: Ledger>(
        &self,
        ledger: &mut L,
        request: &LeaseSettlementRequest,
        now_unix_ms: u64,
    ) -> Result<LeaseSettlementRecord, SignedLeaseError> {
        let settlement_id = request.settlement_id()?;
        ledger.with_lease_transport(|txn| {
            if let Some(record) = txn.get_transport_settlement(&settlement_id)? {
                record.require_request(request)?;
                return Ok(record);
            }
            self.settle_new(txn, request, now_unix_ms)
        })
    }

    /// Read one historical exact outcome under a distinct operation binding.
    ///
    /// # Errors
    /// LEASE_TRANSPORT_SETTLEMENT_ABSENT only when the immutable row is absent.
    pub fn settlement_readback<L: Ledger>(
        &self,
        ledger: &mut L,
        request: &LeaseSettlementRequest,
        now_unix_ms: u64,
    ) -> Result<LeaseSettlementRecord, SignedLeaseError> {
        let settlement_id = request.settlement_id()?;
        ledger.with_lease_transport(|txn| {
            let record = txn
                .get_transport_settlement(&settlement_id)?
                .ok_or(SignedLeaseError::SettlementAbsent)?;
            record.require_request(request)?;
            let presented = presented(
                request.runner_id(),
                request.runner_epoch(),
                request.package(),
            );
            let expected = expectation_for(
                LeaseTransportOperation::SettlementReadback,
                request,
                presented,
                request.key(),
                record.subject.authority_epoch,
                record.subject.clone(),
                now_unix_ms,
            )?;
            self.admit_tx(txn, |_| Ok((expected, record)), |_, _, record| Ok(record))
        })
    }

    fn settle_new(
        &self,
        txn: &mut dyn LeaseTransportTxn,
        request: &LeaseSettlementRequest,
        now_unix_ms: u64,
    ) -> Result<LeaseSettlementRecord, SignedLeaseError> {
        require_source(txn, request)?;
        let presented = presented(
            request.runner_id(),
            request.runner_epoch(),
            request.package(),
        );
        let identity = |attempt: &Attempt| {
            no_mismatch([
                (attempt.variant_id != *request.variant(), "variant_id"),
                (attempt.fence != request.fence(), "fence"),
                (attempt.state != request.expected_state(), "expected_state"),
            ])
        };
        let truth = incarnation_truth(
            txn,
            request.operation(),
            request,
            presented,
            request.key(),
            request.attempt(),
            identity,
            now_unix_ms,
        )?;
        let expected = truth.expected;
        let subject = expected.subject.clone();
        self.admit_tx(
            txn,
            |_| Ok((expected, truth.attempt)),
            |txn, _, mut attempt| {
                let outcome = match request {
                    LeaseSettlementRequest::Advance(body) => {
                        attempt.state = legal_transition(&attempt, body.target_state)?;
                        txn.put_attempt(&attempt)?;
                        LeaseSettlementOutcome::Advanced(attempt)
                    }
                    LeaseSettlementRequest::Release(body) => {
                        let call = ReleaseRequest {
                            variant_id: body.variant_id.clone(),
                            attempt_id: body.attempt_id.clone(),
                            final_state: body.final_state,
                            requeue: body.requeue,
                        };
                        txn.release_lease(&call)?;
                        attempt.state = body.final_state;
                        LeaseSettlementOutcome::Released(attempt)
                    }
                };
                let record = LeaseSettlementRecord::new(request.clone(), subject, outcome)?;
                txn.put_transport_settlement(&record)?;
                Ok(record)
            },
        )
    }

    /// Legacy ephemeral release retained only until Runner K2 switches to settle.
    pub(super) fn release_ephemeral<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedReleaseBody,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let call = &body.call;
        let presented = presented(&body.runner_id, body.runner_epoch, &body.work_package_id);
        let identity = |attempt: &Attempt| {
            no_mismatch([(call.variant_id != attempt.variant_id, "variant_id")])
        };
        let prepare = |txn: &dyn LeaseTransportTxn| {
            let truth = incarnation_truth(
                txn,
                LeaseTransportOperation::Release,
                body,
                presented,
                &body.idempotency_key,
                &call.attempt_id,
                identity,
                now_unix_ms,
            )?;
            Ok((truth.expected, ()))
        };
        self.admit(ledger, prepare, |txn, _, ()| Ok(txn.release_lease(call)?))
    }

    /// Legacy ephemeral advance retained only until Runner K2 switches to settle.
    pub(super) fn advance_ephemeral<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAdvanceBody,
        now_unix_ms: u64,
    ) -> Result<Attempt, SignedLeaseError> {
        let presented = presented(&body.runner_id, body.runner_epoch, &body.work_package_id);
        let prepare = |txn: &dyn LeaseTransportTxn| {
            let truth = incarnation_truth(
                txn,
                LeaseTransportOperation::Advance,
                body,
                presented,
                &body.idempotency_key,
                &body.attempt_id,
                |_| Ok(()),
                now_unix_ms,
            )?;
            let next = legal_transition(&truth.attempt, body.state)?;
            Ok((truth.expected, (truth.attempt, next)))
        };
        self.admit(ledger, prepare, |txn, _, (mut attempt, next)| {
            attempt.state = next;
            txn.put_attempt(&attempt)?;
            Ok(attempt)
        })
    }
}

fn require_source(
    txn: &dyn LeaseTransportTxn,
    request: &LeaseSettlementRequest,
) -> Result<(), SignedLeaseError> {
    let digest = idempotency_digest(request.key())?;
    let source = txn
        .get_transport_grant(&digest)?
        .ok_or(SignedLeaseError::GrantAbsent)?;
    let attempt = &source.grant.attempt;
    let lease = &source.grant.lease;
    let current_authority = txn.current_authority()?;
    let current_source_subject = grant_subject(
        &attempt.workspace_id,
        &attempt.workspace_nonce,
        &current_authority,
    )?;
    no_mismatch([
        (
            source.request_digest != request.acquire_digest(),
            "acquire_request_digest",
        ),
        (attempt.id != *request.attempt(), "attempt_id"),
        (attempt.variant_id != *request.variant(), "variant_id"),
        (
            attempt.work_package_id != *request.package(),
            "work_package_id",
        ),
        (attempt.runner_id != *request.runner_id(), "runner_id"),
        (
            attempt.runner_epoch != request.runner_epoch(),
            "runner_epoch",
        ),
        (attempt.fence != request.fence(), "fence"),
        (lease.attempt_id != *request.attempt(), "lease_attempt_id"),
        (source.subject != current_source_subject, "acquire_subject"),
    ])
}
