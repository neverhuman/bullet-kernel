//! Writer-lease API for runners: acquire, heartbeat, release, attempt state
//! advancement, and the next ready package. Every mutation delegates to the
//! Ledger's single-transaction operations; refusals map to problem-details.

use crate::api::{snapshot_response, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use bullet_application::{
    ActiveLease, HeartbeatRequest, LeaseRequest, LeaseService, Ledger, ReleaseRequest, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, AuthorityToken, Digest, RunnerId, VariantId, WorkPackageId,
    WorkspaceId,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

const DEFAULT_TTL_SECONDS: i64 = 30;

/// Lease routes merged into the main router.
pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/v1/leases/acquire", post(acquire))
        .route("/v1/leases/heartbeat", post(heartbeat))
        .route("/v1/leases/release", post(release))
        .route("/v1/attempts/advance", post(advance))
        .route("/v1/ready", get(next_ready))
}

fn ttl_of(requested: Option<i64>) -> i64 {
    requested.unwrap_or(DEFAULT_TTL_SECONDS).clamp(1, 3600)
}

fn graph_for_package<L: Ledger>(
    ledger: &L,
    package: &WorkPackageId,
) -> Result<Option<(StoredGraph, VariantId)>, ApiError> {
    for mission in ledger.list_missions()? {
        let Some(graph) = ledger.get_graph(&mission.id)? else {
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

#[derive(Deserialize)]
struct AcquireBody {
    work_package_id: String,
    runner_id: String,
    runner_epoch: u64,
    idempotency_key: String,
    ttl_seconds: Option<i64>,
}

#[derive(Serialize)]
struct AcquireView {
    attempt: Attempt,
    authority_token: AuthorityToken,
    lease: ActiveLease,
}

async fn acquire(
    State(state): State<SharedState>,
    Json(body): Json<AcquireBody>,
) -> Result<Json<AcquireView>, ApiError> {
    let package = WorkPackageId::parse(&body.work_package_id)?;
    let runner = RunnerId::parse(&body.runner_id)?;
    let ttl = ttl_of(body.ttl_seconds);
    let mut ledger = state.ledger.lock().await;
    let (graph, variant_id) = graph_for_package(&*ledger, &package)?
        .ok_or_else(|| ApiError::NotFound(format!("work package {package}")))?;
    let now = Utc::now();
    let request = LeaseRequest {
        idempotency_key: body.idempotency_key.clone(),
        mission_id: graph.mission.id.clone(),
        variant_id,
        attempt_seed: body.idempotency_key.clone(),
        runner_id: runner,
        runner_epoch: body.runner_epoch,
        workspace_id: WorkspaceId::from_seed(&body.idempotency_key),
        workspace_nonce: *Digest::of(body.idempotency_key.as_bytes()).as_bytes(),
        scope_revision: 1,
        context_revision: 1,
        now: LeaseService::rfc3339(now),
        expires_at: LeaseService::rfc3339(now + Duration::seconds(ttl)),
    };
    let grant = ledger.acquire_lease(&request)?;
    let token = LeaseService::token_for(&graph, &grant.attempt)?;
    Ok(Json(AcquireView {
        attempt: grant.attempt,
        authority_token: token,
        lease: grant.lease,
    }))
}

#[derive(Deserialize)]
struct HeartbeatBody {
    variant_id: String,
    attempt_id: String,
    fence: u64,
    runner_id: String,
    runner_epoch: u64,
    workspace_nonce: [u8; 32],
    ttl_seconds: Option<i64>,
}

async fn heartbeat(
    State(state): State<SharedState>,
    Json(body): Json<HeartbeatBody>,
) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let request = HeartbeatRequest {
        variant_id: VariantId::parse(&body.variant_id)?,
        attempt_id: AttemptId::parse(&body.attempt_id)?,
        fence: body.fence,
        runner_id: RunnerId::parse(&body.runner_id)?,
        runner_epoch: body.runner_epoch,
        workspace_nonce: body.workspace_nonce,
        now: LeaseService::rfc3339(now),
        expires_at: LeaseService::rfc3339(now + Duration::seconds(ttl_of(body.ttl_seconds))),
    };
    let mut ledger = state.ledger.lock().await;
    ledger.heartbeat(&request)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ReleaseBody {
    attempt_id: String,
    outcome: String,
    requeue: Option<bool>,
}

async fn release(
    State(state): State<SharedState>,
    Json(body): Json<ReleaseBody>,
) -> Result<StatusCode, ApiError> {
    let attempt_id = AttemptId::parse(&body.attempt_id)?;
    let final_state = AttemptState::parse(&body.outcome)?;
    let mut ledger = state.ledger.lock().await;
    let attempt = ledger
        .get_attempt(&attempt_id)?
        .ok_or_else(|| ApiError::NotFound(format!("attempt {attempt_id}")))?;
    ledger.release_lease(&ReleaseRequest {
        variant_id: attempt.variant_id,
        attempt_id,
        final_state,
        requeue: body.requeue.unwrap_or(false),
        now: LeaseService::rfc3339(Utc::now()),
    })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AdvanceBody {
    attempt_id: String,
    state: String,
}

async fn advance(
    State(state): State<SharedState>,
    Json(body): Json<AdvanceBody>,
) -> Result<StatusCode, ApiError> {
    let attempt_id = AttemptId::parse(&body.attempt_id)?;
    let to = AttemptState::parse(&body.state)?;
    let mut ledger = state.ledger.lock().await;
    let mut attempt = ledger
        .get_attempt(&attempt_id)?
        .ok_or_else(|| ApiError::NotFound(format!("attempt {attempt_id}")))?;
    attempt.state = to;
    ledger.put_attempt(&attempt)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct ReadyViewBody {
    work_package_id: String,
    mission_id: String,
    variant_id: String,
    title: String,
    enqueued_at: String,
}

async fn next_ready(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let Some(row) = ledger.ready_rows()?.into_iter().next() else {
        return Err(ApiError::NotFound("ready queue is empty".into()));
    };
    let (graph, variant_id) = graph_for_package(&*ledger, &row.work_package_id)?
        .ok_or_else(|| ApiError::NotFound(format!("graph for {}", row.work_package_id)))?;
    let title = graph
        .packages
        .iter()
        .find(|package| package.id == row.work_package_id)
        .map(|package| package.title.clone())
        .unwrap_or_default();
    let view = ReadyViewBody {
        work_package_id: row.work_package_id.to_string(),
        mission_id: graph.mission.id.to_string(),
        variant_id: variant_id.to_string(),
        title,
        enqueued_at: row.enqueued_at,
    };
    let as_of_sequence = ledger.latest_event_sequence()?;
    snapshot_response(view, as_of_sequence)
}
