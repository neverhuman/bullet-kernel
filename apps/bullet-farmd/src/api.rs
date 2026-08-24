//! HTTP + JSON API. Generated TypeScript clients consume this contract.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bullet_adapters::SqliteLedger;
use bullet_application::{run_demo, DemoReceipt, Ledger};
use bullet_domain::{Mission, MissionId};
use serde::Serialize;
use std::path::Path as FsPath;
use std::sync::Mutex;
use tower_http::cors::CorsLayer;

const OPENAPI: &str = include_str!("../../../contracts/openapi.yaml");

/// Shared daemon state.
pub struct AppState {
    ledger: Mutex<SqliteLedger>,
}

/// Build the router.
pub fn router(db: &FsPath) -> Router {
    let ledger = SqliteLedger::open(db).unwrap_or_else(|err| panic!("open ledger: {err}"));
    let state = AppState {
        ledger: Mutex::new(ledger),
    };
    Router::new()
        .route("/health", get(health))
        .route("/openapi.yaml", get(openapi))
        .route("/v1/missions", get(list_missions))
        .route("/v1/missions/{id}", get(get_mission))
        .route("/v1/demo", get(get_demo))
        .route("/v1/demo/run", post(run_demo_handler))
        .route("/v1/outbox", get(outbox))
        .layer(CorsLayer::permissive())
        .with_state(std::sync::Arc::new(state))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn openapi() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/yaml")],
        OPENAPI,
    )
}

async fn list_missions(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<Json<Vec<Mission>>, ApiError> {
    let ledger = state.ledger.lock().map_err(ApiError::lock)?;
    Ok(Json(ledger.list_missions()?))
}

#[derive(Serialize)]
struct MissionView {
    mission: Mission,
    packages: Vec<bullet_domain::WorkPackage>,
    fence: Option<u64>,
}

async fn get_mission(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<MissionView>, ApiError> {
    let mission_id = MissionId::parse(&id)?;
    let ledger = state.ledger.lock().map_err(ApiError::lock)?;
    let graph = ledger.get_graph(&mission_id)?.ok_or(ApiError::NotFound)?;
    let fence = graph.variants.first().map(|v| v.fence_counter);
    Ok(Json(MissionView {
        mission: graph.mission,
        packages: graph.packages,
        fence,
    }))
}

async fn get_demo(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<Json<Option<DemoReceipt>>, ApiError> {
    let ledger = state.ledger.lock().map_err(ApiError::lock)?;
    let missions = ledger.list_missions()?;
    let Some(mission) = missions.into_iter().next() else {
        return Ok(Json(None));
    };
    let graph = ledger.get_graph(&mission.id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(Some(DemoReceipt {
        mission_id: mission.id.to_string(),
        plan_hash: graph.plan.canonical_hash.to_hex(),
        fence: graph.variants.first().map_or(0, |v| v.fence_counter),
        attempt_id: String::new(),
        stale_attempt_id: String::new(),
        candidate_head: String::new(),
        evidence_result: String::new(),
        effect_outcome: String::new(),
        materialize_idempotent: true,
        stale_refused: true,
    })))
}

async fn run_demo_handler(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<Json<DemoReceipt>, ApiError> {
    let mut ledger = state.ledger.lock().map_err(ApiError::lock)?;
    Ok(Json(run_demo(&mut *ledger)?))
}

#[derive(Serialize)]
struct OutboxView {
    pending: Vec<String>,
}

async fn outbox(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<Json<OutboxView>, ApiError> {
    let ledger = state.ledger.lock().map_err(ApiError::lock)?;
    let pending = ledger
        .pending_outbox()?
        .into_iter()
        .map(|c| format!("{}:{}", c.kind, c.phase.as_str()))
        .collect();
    Ok(Json(OutboxView { pending }))
}

enum ApiError {
    NotFound,
    Domain(String),
}

impl ApiError {
    fn lock<T>(_: T) -> Self {
        Self::Domain("ledger lock poisoned".into())
    }
}

impl From<bullet_application::LedgerError> for ApiError {
    fn from(value: bullet_application::LedgerError) -> Self {
        Self::Domain(value.to_string())
    }
}

impl From<bullet_domain::DomainError> for ApiError {
    fn from(value: bullet_domain::DomainError) -> Self {
        Self::Domain(value.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            Self::Domain(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
        }
    }
}
