//! `LeaseClient`: how the runner talks to writer-lease authority. A production
//! signed transport is not implemented yet. `DirectLeaseClient` is unsigned
//! and stays test/embedded-only. `HttpLeaseClient` talks to farmd
//! `/api/v1/leases/*`, which is not mounted. The feature-gated
//! `SignedLeaseClient` co-locates permit issuance and verification and is a
//! simulator only, never an admission path.

use crate::error::RunnerError;
use crate::signed_lease_rpc::CandidatePreparationRpcClient;
use async_trait::async_trait;
use bullet_application::{
    ActiveLease, HeartbeatRequest, LeaseRequest, LeaseService, Ledger, ReleaseRequest, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, AuthorityToken, Digest, RunnerId, VariantId, WorkPackageId,
    WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};

/// Frozen Phase-1 lease maximum, forwarded from the application authority contract.
pub const MAX_LEASE_TTL_SECONDS: i64 = bullet_application::records::MAX_LEASE_TTL_SECONDS;

/// Lease acquisition request keyed by work package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcquireRequest {
    /// Package to lease (the server resolves the variant).
    pub work_package_id: WorkPackageId,
    /// Runner identity.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Idempotency key; also seeds the attempt id.
    pub idempotency_key: String,
    /// Lease TTL in seconds.
    pub ttl_seconds: i64,
}

/// Result of an acquisition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcquireGrant {
    /// The fenced attempt created in the grant transaction.
    pub attempt: Attempt,
    /// Complete immutable authority for the incarnation.
    pub authority_token: AuthorityToken,
    /// The active lease row (carries `expires_at`).
    pub lease: ActiveLease,
}

/// Six-identity heartbeat call (spec section 26.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatCall {
    /// Variant under lease.
    pub variant_id: VariantId,
    /// Attempt incarnation.
    pub attempt_id: AttemptId,
    /// Fence epoch.
    pub fence: u64,
    /// Runner identity.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Workspace nonce.
    pub workspace_nonce: [u8; 32],
    /// TTL used to extend the lease.
    pub ttl_seconds: i64,
}

impl HeartbeatCall {
    /// Heartbeat identity for one grant.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_LEASE_TTL` when a decoded grant carries an invalid TTL.
    pub fn for_grant(grant: &AcquireGrant) -> Result<Self, RunnerError> {
        LeaseService::validate_ttl(grant.lease.ttl_seconds).map_err(map_ledger)?;
        Ok(Self {
            variant_id: grant.lease.variant_id.clone(),
            attempt_id: grant.lease.attempt_id.clone(),
            fence: grant.lease.fence,
            runner_id: grant.lease.runner_id.clone(),
            runner_epoch: grant.lease.runner_epoch,
            workspace_nonce: grant.lease.workspace_nonce,
            ttl_seconds: grant.lease.ttl_seconds,
        })
    }
}

/// Close one lease with a terminal attempt state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseCall {
    /// Attempt that must hold the lease.
    pub attempt_id: AttemptId,
    /// Terminal state.
    pub outcome: AttemptState,
    /// Return the package to the ready queue.
    pub requeue: bool,
}

/// The next dispatchable package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadyView {
    /// Package.
    pub work_package_id: String,
    /// Mission.
    pub mission_id: String,
    /// Variant that will hold the writer.
    pub variant_id: String,
    /// Package title.
    pub title: String,
    /// When the ready row was enqueued.
    pub enqueued_at: String,
}

/// Writer-lease authority as seen by the runner.
#[async_trait]
pub trait LeaseClient: Send + Sync {
    /// Candidate authority on the same authenticated workload client.
    ///
    /// Generic lease simulators and retired transports expose no fallback.
    fn candidate_preparation_rpc(&self) -> Option<&dyn CandidatePreparationRpcClient> {
        None
    }
    /// Acquire the writer lease for one work package.
    async fn acquire(&self, request: &AcquireRequest) -> Result<AcquireGrant, RunnerError>;
    /// Renew the lease. Zero matched rows is typed `STALE_AUTHORITY`.
    async fn heartbeat(&self, call: &HeartbeatCall) -> Result<(), RunnerError>;
    /// Apply one legal attempt state transition.
    async fn advance(&self, attempt_id: &AttemptId, state: AttemptState)
        -> Result<(), RunnerError>;
    /// Close the lease with a terminal state.
    async fn release(&self, call: &ReleaseCall) -> Result<(), RunnerError>;
    /// The next ready work package, if any.
    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError>;
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

/// Unsigned in-process client over any `Ledger`. Tests and the archived
/// live-demo path use this. It is not admission.
pub struct DirectLeaseClient<L: Ledger + Send> {
    ledger: Arc<Mutex<L>>,
}

impl<L: Ledger + Send> DirectLeaseClient<L> {
    /// Wrap a shared ledger.
    #[must_use]
    pub fn new(ledger: Arc<Mutex<L>>) -> Self {
        Self { ledger }
    }

    fn lock(&self) -> Result<MutexGuard<'_, L>, RunnerError> {
        self.ledger.lock().map_err(|_| RunnerError::Io {
            context: "ledger lock".into(),
            reason: "poisoned".into(),
        })
    }
}

pub(crate) fn graph_for_package<L: Ledger>(
    ledger: &L,
    package: &WorkPackageId,
) -> Result<Option<(StoredGraph, VariantId)>, RunnerError> {
    for mission in ledger.list_missions().map_err(map_ledger)? {
        let Some(graph) = ledger.get_graph(&mission.id).map_err(map_ledger)? else {
            continue;
        };
        if let Some(variant) = graph
            .variants
            .iter()
            .find(|variant| variant.work_package_id == *package)
        {
            let variant_id = variant.id.clone();
            return Ok(Some((graph, variant_id)));
        }
    }
    Ok(None)
}

/// Build the full `LeaseRequest` the ledger transaction needs from the wire
/// request. Workspace identity is derived from the idempotency key so a
/// replay reconstructs the same authority.
#[must_use]
pub fn lease_request(
    request: &AcquireRequest,
    graph: &StoredGraph,
    variant_id: &VariantId,
) -> LeaseRequest {
    LeaseRequest {
        idempotency_key: request.idempotency_key.clone(),
        mission_id: graph.mission.id.clone(),
        variant_id: variant_id.clone(),
        attempt_seed: request.idempotency_key.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        workspace_id: WorkspaceId::from_seed(&request.idempotency_key),
        workspace_nonce: *Digest::of(request.idempotency_key.as_bytes()).as_bytes(),
        scope_revision: 1,
        context_revision: 1,
        ttl_seconds: request.ttl_seconds,
    }
}

#[async_trait]
impl<L: Ledger + Send> LeaseClient for DirectLeaseClient<L> {
    async fn acquire(&self, request: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
        let mut ledger = self.lock()?;
        let (graph, variant_id) = graph_for_package(&*ledger, &request.work_package_id)?
            .ok_or_else(|| RunnerError::Lease {
                code: "NOT_FOUND".into(),
                message: format!("work package {} not in any graph", request.work_package_id),
            })?;
        let req = lease_request(request, &graph, &variant_id);
        let grant = ledger.acquire_lease(&req).map_err(map_ledger)?;
        let token = LeaseService::token_for(&graph, &grant.attempt).map_err(map_ledger)?;
        Ok(AcquireGrant {
            attempt: grant.attempt,
            authority_token: token,
            lease: grant.lease,
        })
    }

    async fn heartbeat(&self, call: &HeartbeatCall) -> Result<(), RunnerError> {
        let mut ledger = self.lock()?;
        let request = HeartbeatRequest {
            variant_id: call.variant_id.clone(),
            attempt_id: call.attempt_id.clone(),
            fence: call.fence,
            runner_id: call.runner_id.clone(),
            runner_epoch: call.runner_epoch,
            workspace_nonce: call.workspace_nonce,
            ttl_seconds: call.ttl_seconds,
        };
        ledger.heartbeat(&request).map_err(map_ledger)
    }

    async fn advance(
        &self,
        attempt_id: &AttemptId,
        state: AttemptState,
    ) -> Result<(), RunnerError> {
        let mut ledger = self.lock()?;
        let mut attempt = ledger
            .get_attempt(attempt_id)
            .map_err(map_ledger)?
            .ok_or_else(|| RunnerError::Lease {
                code: "NOT_FOUND".into(),
                message: format!("attempt {attempt_id} unknown"),
            })?;
        attempt.state = state;
        ledger.put_attempt(&attempt).map_err(map_ledger)
    }

    async fn release(&self, call: &ReleaseCall) -> Result<(), RunnerError> {
        let mut ledger = self.lock()?;
        let attempt = ledger
            .get_attempt(&call.attempt_id)
            .map_err(map_ledger)?
            .ok_or_else(|| RunnerError::Lease {
                code: "NOT_FOUND".into(),
                message: format!("attempt {} unknown", call.attempt_id),
            })?;
        ledger
            .release_lease(&ReleaseRequest {
                variant_id: attempt.variant_id,
                attempt_id: call.attempt_id.clone(),
                final_state: call.outcome,
                requeue: call.requeue,
            })
            .map_err(map_ledger)
    }

    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
        let ledger = self.lock()?;
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
