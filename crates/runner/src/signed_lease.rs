//! Test-seam-only in-process `LeaseClient` that self-mints a lease-runner
//! permit before every writer mutation. Co-locating the signing key and
//! verifier makes this a simulator, never a production admission path.
//! Ready-queue reads stay unsigned projections. `advance` is not admitted.

use crate::error::RunnerError;
use crate::lease::{
    graph_for_package, AcquireGrant, AcquireRequest, HeartbeatCall, LeaseClient, ReadyView,
    ReleaseCall,
};
use async_trait::async_trait;
use bullet_application::lease_transport::{
    issue_operation_permit, issue_permit, SignedAcquireBody, SignedLeaseError, SignedLeaseService,
};
use bullet_application::{HeartbeatRequest, LeaseService, Ledger, ReleaseRequest};
use bullet_domain::{AttemptId, AttemptState, RunnerId, WorkPackageId};
use bullet_harness_core::lease_transport::{LeaseTransportOperation, LeaseTransportSigningKey};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

struct AcquireMeta {
    work_package_id: WorkPackageId,
    idempotency_key: String,
    runner_id: RunnerId,
    runner_epoch: u64,
}

/// Simulator-only signed lease transport over a shared ledger.
///
/// This type owns the signing key and therefore must never be wired into a
/// production Runner. Its module is absent unless `test-seams` is enabled.
pub struct SignedLeaseClient<L: Ledger + Send> {
    ledger: Arc<Mutex<L>>,
    service: Mutex<SignedLeaseService>,
    key: LeaseTransportSigningKey,
    last: Mutex<BTreeMap<String, AcquireMeta>>,
}

impl<L: Ledger + Send> SignedLeaseClient<L> {
    /// Bind one simulator signing key and the matching verification service.
    ///
    /// # Errors
    ///
    /// `LEASE_TRANSPORT_INVALID` when the public half cannot be derived.
    pub fn new(ledger: Arc<Mutex<L>>, key: LeaseTransportSigningKey) -> Result<Self, RunnerError> {
        let verification = key.verification_key().map_err(map_signed_transport)?;
        Ok(Self {
            ledger,
            service: Mutex::new(SignedLeaseService::new(verification)),
            key,
            last: Mutex::new(BTreeMap::new()),
        })
    }

    fn lock_ledger(&self) -> Result<MutexGuard<'_, L>, RunnerError> {
        self.ledger.lock().map_err(|_| RunnerError::Io {
            context: "ledger lock".into(),
            reason: "poisoned".into(),
        })
    }

    fn lock_service(&self) -> Result<MutexGuard<'_, SignedLeaseService>, RunnerError> {
        self.service.lock().map_err(|_| RunnerError::Io {
            context: "lease-transport service lock".into(),
            reason: "poisoned".into(),
        })
    }

    fn lock_last(&self) -> Result<MutexGuard<'_, BTreeMap<String, AcquireMeta>>, RunnerError> {
        self.last.lock().map_err(|_| RunnerError::Io {
            context: "lease-transport meta lock".into(),
            reason: "poisoned".into(),
        })
    }

    fn meta_for(&self, attempt_id: &AttemptId) -> Result<AcquireMeta, RunnerError> {
        self.lock_last()?
            .get(attempt_id.as_str())
            .map(|meta| AcquireMeta {
                work_package_id: meta.work_package_id.clone(),
                idempotency_key: meta.idempotency_key.clone(),
                runner_id: meta.runner_id.clone(),
                runner_epoch: meta.runner_epoch,
            })
            .ok_or_else(|| RunnerError::Lease {
                code: "LEASE_TRANSPORT_UNKNOWN".into(),
                message: format!("no signed acquire recorded for {attempt_id}"),
            })
    }
}

#[async_trait]
impl<L: Ledger + Send> LeaseClient for SignedLeaseClient<L> {
    async fn acquire(&self, request: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
        let body = SignedAcquireBody {
            work_package_id: request.work_package_id.clone(),
            runner_id: request.runner_id.clone(),
            runner_epoch: request.runner_epoch,
            idempotency_key: request.idempotency_key.clone(),
            ttl_seconds: request.ttl_seconds,
        };
        let now = now_unix_ms();
        let mut service = self.lock_service()?;
        let permit = issue_permit(
            &self.key,
            &mut service,
            LeaseTransportOperation::Acquire,
            &body,
            now,
        )
        .map_err(map_signed)?;
        let mut ledger = self.lock_ledger()?;
        let grant = service
            .acquire(&mut *ledger, &permit, &body, now)
            .map_err(map_signed)?;
        let (graph, _) =
            graph_for_package(&*ledger, &request.work_package_id)?.ok_or_else(|| {
                RunnerError::Lease {
                    code: "NOT_FOUND".into(),
                    message: format!("work package {} not in any graph", request.work_package_id),
                }
            })?;
        let token = LeaseService::token_for(&graph, &grant.attempt).map_err(map_ledger)?;
        self.lock_last()?.insert(
            grant.attempt.id.to_string(),
            AcquireMeta {
                work_package_id: request.work_package_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                runner_id: request.runner_id.clone(),
                runner_epoch: request.runner_epoch,
            },
        );
        Ok(AcquireGrant {
            attempt: grant.attempt,
            authority_token: token,
            lease: grant.lease,
        })
    }

    async fn heartbeat(&self, call: &HeartbeatCall) -> Result<(), RunnerError> {
        let meta = self.meta_for(&call.attempt_id)?;
        let request = HeartbeatRequest {
            variant_id: call.variant_id.clone(),
            attempt_id: call.attempt_id.clone(),
            fence: call.fence,
            runner_id: call.runner_id.clone(),
            runner_epoch: call.runner_epoch,
            workspace_nonce: call.workspace_nonce,
            ttl_seconds: call.ttl_seconds,
        };
        let now = now_unix_ms();
        let mut service = self.lock_service()?;
        let permit = issue_operation_permit(
            &self.key,
            &mut service,
            LeaseTransportOperation::Heartbeat,
            &request.runner_id,
            request.runner_epoch,
            meta.work_package_id.as_str(),
            &meta.idempotency_key,
            &request,
            now,
        )
        .map_err(map_signed)?;
        let mut ledger = self.lock_ledger()?;
        service
            .heartbeat(
                &mut *ledger,
                &permit,
                &meta.work_package_id,
                &meta.idempotency_key,
                &request,
                now,
            )
            .map_err(map_signed)
    }

    async fn advance(
        &self,
        _attempt_id: &AttemptId,
        _state: AttemptState,
    ) -> Result<(), RunnerError> {
        Err(RunnerError::Lease {
            code: "LEASE_TRANSPORT_UNSUPPORTED".into(),
            message: "signed advance is not implemented; do not fall back to DirectLeaseClient"
                .into(),
        })
    }

    async fn release(&self, call: &ReleaseCall) -> Result<(), RunnerError> {
        let meta = self.meta_for(&call.attempt_id)?;
        let now = now_unix_ms();
        let mut service = self.lock_service()?;
        let mut ledger = self.lock_ledger()?;
        let attempt = ledger
            .get_attempt(&call.attempt_id)
            .map_err(map_ledger)?
            .ok_or_else(|| RunnerError::Lease {
                code: "NOT_FOUND".into(),
                message: format!("attempt {} unknown", call.attempt_id),
            })?;
        let request = ReleaseRequest {
            variant_id: attempt.variant_id,
            attempt_id: call.attempt_id.clone(),
            final_state: call.outcome,
            requeue: call.requeue,
        };
        let permit = issue_operation_permit(
            &self.key,
            &mut service,
            LeaseTransportOperation::Release,
            &meta.runner_id,
            meta.runner_epoch,
            meta.work_package_id.as_str(),
            &meta.idempotency_key,
            &request,
            now,
        )
        .map_err(map_signed)?;
        service
            .release(
                &mut *ledger,
                &permit,
                &meta.runner_id,
                meta.runner_epoch,
                &meta.work_package_id,
                &meta.idempotency_key,
                &request,
                now,
            )
            .map_err(map_signed)
    }

    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
        let ledger = self.lock_ledger()?;
        let Some(row) = ledger.ready_rows().map_err(map_ledger)?.into_iter().next() else {
            return Ok(None);
        };
        let Some((graph, variant_id)) = graph_for_package(&*ledger, &row.work_package_id)? else {
            return Ok(None);
        };
        let title = graph
            .packages
            .iter()
            .find(|package| package.id == row.work_package_id)
            .map(|package| package.title.clone())
            .unwrap_or_default();
        Ok(Some(ReadyView {
            work_package_id: row.work_package_id.to_string(),
            mission_id: graph.mission.id.to_string(),
            variant_id: variant_id.to_string(),
            title,
            enqueued_at: row.enqueued_at,
        }))
    }
}

fn now_unix_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn map_ledger(err: bullet_application::LedgerError) -> RunnerError {
    if err.reason_code() == "STALE_AUTHORITY" {
        return RunnerError::StaleAuthority(err.to_string());
    }
    RunnerError::Lease {
        code: err.reason_code().to_string(),
        message: err.to_string(),
    }
}

fn map_signed(err: SignedLeaseError) -> RunnerError {
    RunnerError::Lease {
        code: err.reason_code().to_string(),
        message: err.to_string(),
    }
}

fn map_signed_transport(
    err: bullet_harness_core::lease_transport::LeaseTransportError,
) -> RunnerError {
    RunnerError::Lease {
        code: err.reason_code().to_string(),
        message: err.to_string(),
    }
}
