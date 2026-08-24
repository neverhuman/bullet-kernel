//! HTTP + SSE API. Generated TypeScript clients consume this contract.

use crate::errors::ApiError;
use axum::extract::{Path, Query, State};
use axum::response::sse::{Event as SseFrame, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use bullet_adapters::SqliteLedger;
use bullet_application::{
    derive_receipt, run_demo, DemoReceipt, Ledger, LedgerError, LedgerEvent, OutboxItem,
};
use bullet_domain::{Mission, MissionId};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

const OPENAPI: &str = include_str!("../../../contracts/openapi.yaml");
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Shared daemon state. The async mutex cannot poison; a panicked holder
/// simply releases the lock.
pub struct AppState {
    ledger: Mutex<SqliteLedger>,
}

type SharedState = Arc<AppState>;

/// Build the router against a SQLite file.
///
/// # Errors
///
/// Returns a ledger error when the database cannot be opened or migrated.
pub fn router(db: &FsPath) -> Result<Router, LedgerError> {
    let ledger = SqliteLedger::open(db)?;
    let state: SharedState = Arc::new(AppState {
        ledger: Mutex::new(ledger),
    });
    Ok(Router::new()
        .route("/health", get(health))
        .route("/openapi.yaml", get(openapi))
        .route("/v1/missions", get(list_missions))
        .route("/v1/missions/{id}", get(get_mission))
        .route("/v1/demo", get(get_demo))
        .route("/v1/demo/run", post(run_demo_handler))
        .route("/v1/outbox", get(outbox))
        .route("/v1/events", get(events))
        .layer(CorsLayer::permissive())
        .with_state(state))
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

async fn list_missions(State(state): State<SharedState>) -> Result<Json<Vec<Mission>>, ApiError> {
    let ledger = state.ledger.lock().await;
    Ok(Json(ledger.list_missions()?))
}

#[derive(Serialize)]
struct MissionView {
    mission: Mission,
    packages: Vec<bullet_domain::WorkPackage>,
    fence: Option<u64>,
}

async fn get_mission(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<MissionView>, ApiError> {
    let mission_id = MissionId::parse(&id)?;
    let ledger = state.ledger.lock().await;
    let graph = ledger
        .get_graph(&mission_id)?
        .ok_or_else(|| ApiError::NotFound(format!("mission {id}")))?;
    let fence = graph.variants.first().map(|variant| variant.fence_counter);
    Ok(Json(MissionView {
        mission: graph.mission,
        packages: graph.packages,
        fence,
    }))
}

async fn get_demo(State(state): State<SharedState>) -> Result<Json<Option<DemoReceipt>>, ApiError> {
    let mut ledger = state.ledger.lock().await;
    Ok(Json(derive_receipt(&mut *ledger)?))
}

async fn run_demo_handler(State(state): State<SharedState>) -> Result<Json<DemoReceipt>, ApiError> {
    let mut ledger = state.ledger.lock().await;
    Ok(Json(run_demo(&mut *ledger)?))
}

#[derive(Serialize)]
struct OutboxView {
    items: Vec<OutboxItem>,
}

async fn outbox(State(state): State<SharedState>) -> Result<Json<OutboxView>, ApiError> {
    let ledger = state.ledger.lock().await;
    Ok(Json(OutboxView {
        items: ledger.outbox_all()?,
    }))
}

#[derive(Deserialize)]
struct EventsQuery {
    after: Option<u64>,
}

async fn events(
    State(state): State<SharedState>,
    Query(query): Query<EventsQuery>,
) -> Sse<impl Stream<Item = Result<SseFrame, Infallible>>> {
    Sse::new(event_stream(state, query.after.unwrap_or(0))).keep_alive(KeepAlive::default())
}

fn event_stream(
    state: SharedState,
    after: u64,
) -> impl Stream<Item = Result<SseFrame, Infallible>> {
    let seed: (SharedState, u64, VecDeque<LedgerEvent>) = (state, after, VecDeque::new());
    futures_util::stream::unfold(seed, |(state, mut last, mut buffer)| async move {
        loop {
            if let Some(event) = buffer.pop_front() {
                let frame = sse_frame(&event);
                return Some((Ok(frame), (state, last, buffer)));
            }
            let batch = {
                let ledger = state.ledger.lock().await;
                ledger.list_events_after(last, 64)
            };
            match batch {
                Ok(events) if !events.is_empty() => {
                    if let Some(max) = events.iter().map(|event| event.seq).max() {
                        last = last.max(max);
                    }
                    buffer.extend(events);
                }
                Ok(_) => tokio::time::sleep(POLL_INTERVAL).await,
                Err(err) => {
                    tracing::warn!(error = %err, "event poll failed; retrying");
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        }
    })
}

fn sse_frame(event: &LedgerEvent) -> SseFrame {
    let base = SseFrame::default()
        .id(event.seq.to_string())
        .event(event.kind.clone());
    match serde_json::to_string(event) {
        Ok(data) => base.data(data),
        Err(err) => base.event("encoding_failure").data(
            serde_json::json!({
                "seq": event.seq,
                "code": "ENCODING_FAILURE",
                "detail": err.to_string(),
            })
            .to_string(),
        ),
    }
}
