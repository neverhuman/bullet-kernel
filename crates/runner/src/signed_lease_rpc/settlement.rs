//! Restart-safe terminal lease settlement over the authenticated UDS.

use super::*;
use bullet_application::lease_transport::{
    AdvanceSettlementRequest, LeaseSettlementRecord, LeaseSettlementRequest,
    ReleaseSettlementRequest,
};

enum Prepared {
    Completed,
    Pending {
        request: LeaseSettlementRequest,
        is_new: bool,
    },
}

impl SignedLeaseRpcClient {
    pub(super) async fn settle_advance(
        &self,
        attempt_id: &AttemptId,
        target_state: AttemptState,
    ) -> Result<(), RunnerError> {
        let prepared = self.prepare_advance(attempt_id, target_state)?;
        self.reconcile_prepared(prepared).await
    }

    pub(super) async fn settle_release(&self, call: &ReleaseCall) -> Result<(), RunnerError> {
        let prepared = self.prepare_release(call)?;
        self.reconcile_prepared(prepared).await
    }

    fn prepare_advance(
        &self,
        attempt_id: &AttemptId,
        target_state: AttemptState,
    ) -> Result<Prepared, RunnerError> {
        self.mutate_recovery(|journal| {
            if let Some(pending) = journal.pending_for(attempt_id) {
                return require_advance(&pending, target_state).map(|()| Prepared::Pending {
                    request: pending,
                    is_new: false,
                });
            }
            if let Some(record) = journal.completed_for(attempt_id) {
                if require_advance(&record.request, target_state).is_ok() {
                    return Ok(Prepared::Completed);
                }
            }
            let meta = journal.intent_for(attempt_id).ok_or_else(unknown_attempt)?;
            let request = advance_request(&meta, attempt_id, target_state)?;
            let is_new = journal.reserve_settlement(request.clone())?;
            Ok(Prepared::Pending { request, is_new })
        })
    }

    fn prepare_release(&self, call: &ReleaseCall) -> Result<Prepared, RunnerError> {
        self.mutate_recovery(|journal| {
            if let Some(pending) = journal.pending_for(&call.attempt_id) {
                return require_release(&pending, call).map(|()| Prepared::Pending {
                    request: pending,
                    is_new: false,
                });
            }
            if let Some(record) = journal.completed_for(&call.attempt_id) {
                if require_release(&record.request, call).is_ok() {
                    return Ok(Prepared::Completed);
                }
                if matches!(record.request, LeaseSettlementRequest::Release(_)) {
                    return Err(rpc_err(
                        "IDEMPOTENCY_CONFLICT",
                        "released attempt cannot accept a different terminal request",
                    ));
                }
            }
            let meta = journal
                .intent_for(&call.attempt_id)
                .ok_or_else(unknown_attempt)?;
            let request = release_request(&meta, call)?;
            let is_new = journal.reserve_settlement(request.clone())?;
            Ok(Prepared::Pending { request, is_new })
        })
    }

    async fn reconcile_prepared(&self, prepared: Prepared) -> Result<(), RunnerError> {
        let Prepared::Pending { request, is_new } = prepared else {
            return Ok(());
        };
        let first = if is_new {
            Some(self.call::<_, serde_json::Value>("settle", &request).await)
        } else {
            None
        };
        match self.readback_settlement(&request).await {
            Ok(record) => return self.publish_completion(&request, &record),
            Err(error) if settlement_absent(&error) => {}
            Err(error) => return Err(unknown_outcome(&request, &error)),
        }
        if let Some(Err(refusal @ RunnerError::Lease { .. })) = first {
            return self.publish_refusal(&request, refusal);
        }
        let replay = self.call::<_, serde_json::Value>("settle", &request).await;
        match self.readback_settlement(&request).await {
            Ok(record) => self.publish_completion(&request, &record),
            Err(error) if settlement_absent(&error) => {
                if let Err(refusal @ RunnerError::Lease { .. }) = replay {
                    self.publish_refusal(&request, refusal)
                } else {
                    Err(unknown_outcome(&request, &error))
                }
            }
            Err(error) => Err(unknown_outcome(&request, &error)),
        }
    }

    async fn readback_settlement(
        &self,
        request: &LeaseSettlementRequest,
    ) -> Result<LeaseSettlementRecord, RunnerError> {
        self.call("settlement_readback", request).await
    }

    fn publish_completion(
        &self,
        request: &LeaseSettlementRequest,
        record: &LeaseSettlementRecord,
    ) -> Result<(), RunnerError> {
        self.mutate_recovery(|journal| journal.complete_settlement(request, record))
            .map_err(|error| unknown_outcome(request, &error))
    }

    fn publish_refusal(
        &self,
        request: &LeaseSettlementRequest,
        refusal: RunnerError,
    ) -> Result<(), RunnerError> {
        self.mutate_recovery(|journal| journal.abandon_settlement(request))
            .map_err(|error| unknown_outcome(request, &error))?;
        Err(refusal)
    }
}

fn advance_request(
    meta: &AcquireMeta,
    attempt_id: &AttemptId,
    target_state: AttemptState,
) -> Result<LeaseSettlementRequest, RunnerError> {
    let _grant = meta.grant.as_ref().ok_or_else(unknown_attempt)?;
    let current = meta.current_attempt.as_ref().ok_or_else(unknown_attempt)?;
    if &current.id != attempt_id {
        return Err(unknown_attempt());
    }
    Ok(LeaseSettlementRequest::Advance(AdvanceSettlementRequest {
        acquire_request_digest: meta.request_digest.clone(),
        work_package_id: meta.body.work_package_id.clone(),
        runner_id: meta.body.runner_id.clone(),
        runner_epoch: meta.body.runner_epoch,
        idempotency_key: meta.body.idempotency_key.clone(),
        variant_id: current.variant_id.clone(),
        attempt_id: attempt_id.clone(),
        attempt_fence: current.fence,
        expected_state: current.state,
        target_state,
    }))
}

fn release_request(
    meta: &AcquireMeta,
    call: &ReleaseCall,
) -> Result<LeaseSettlementRequest, RunnerError> {
    let _grant = meta.grant.as_ref().ok_or_else(unknown_attempt)?;
    let current = meta.current_attempt.as_ref().ok_or_else(unknown_attempt)?;
    Ok(LeaseSettlementRequest::Release(ReleaseSettlementRequest {
        acquire_request_digest: meta.request_digest.clone(),
        work_package_id: meta.body.work_package_id.clone(),
        runner_id: meta.body.runner_id.clone(),
        runner_epoch: meta.body.runner_epoch,
        idempotency_key: meta.body.idempotency_key.clone(),
        variant_id: current.variant_id.clone(),
        attempt_id: call.attempt_id.clone(),
        attempt_fence: current.fence,
        expected_state: current.state,
        final_state: call.outcome,
        requeue: call.requeue,
    }))
}

fn require_advance(
    request: &LeaseSettlementRequest,
    target_state: AttemptState,
) -> Result<(), RunnerError> {
    match request {
        LeaseSettlementRequest::Advance(body) if body.target_state == target_state => Ok(()),
        _ => Err(rpc_err(
            "IDEMPOTENCY_CONFLICT",
            "pending terminal request is not the requested advance",
        )),
    }
}

fn require_release(
    request: &LeaseSettlementRequest,
    call: &ReleaseCall,
) -> Result<(), RunnerError> {
    match request {
        LeaseSettlementRequest::Release(body)
            if body.final_state == call.outcome && body.requeue == call.requeue =>
        {
            Ok(())
        }
        _ => Err(rpc_err(
            "IDEMPOTENCY_CONFLICT",
            "pending terminal request is not the requested release",
        )),
    }
}

fn settlement_absent(error: &RunnerError) -> bool {
    matches!(error, RunnerError::Lease { code, .. } if code == "LEASE_TRANSPORT_SETTLEMENT_ABSENT")
}

fn unknown_outcome(request: &LeaseSettlementRequest, error: &RunnerError) -> RunnerError {
    let message = format!("settlement readback failed with {}", error.reason_code());
    match request {
        LeaseSettlementRequest::Advance(_) => RunnerError::AdvanceOutcomeUnknown { message },
        LeaseSettlementRequest::Release(_) => RunnerError::ReleaseOutcomeUnknown { message },
    }
}

fn unknown_attempt() -> RunnerError {
    rpc_err(
        "LEASE_TRANSPORT_UNKNOWN",
        "no durable signed acquire grant exists for the requested attempt",
    )
}
