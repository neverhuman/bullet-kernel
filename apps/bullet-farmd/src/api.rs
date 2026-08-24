//! HTTP + SSE API. Generated TypeScript clients consume this contract.

use crate::errors::ApiError;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::sse::{Event as SseFrame, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
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
use std::io;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const OPENAPI: &str = include_str!("../../../contracts/openapi.yaml");
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const SNAPSHOT_SEQUENCE_HEADER: HeaderName = HeaderName::from_static("x-bullet-as-of-sequence");

/// Shared daemon state. The async mutex cannot poison; a panicked holder
/// simply releases the lock.
pub struct AppState {
    pub(crate) ledger: Mutex<SqliteLedger>,
}

pub(crate) type SharedState = Arc<AppState>;

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
        .merge(crate::leases::routes())
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

async fn list_missions(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let missions = ledger.list_missions()?;
    let as_of_sequence = ledger.latest_event_sequence()?;
    snapshot_response(missions, as_of_sequence)
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
) -> Result<Response, ApiError> {
    let mission_id = MissionId::parse(&id)?;
    let ledger = state.ledger.lock().await;
    let graph = ledger
        .get_graph(&mission_id)?
        .ok_or_else(|| ApiError::NotFound(format!("mission {id}")))?;
    let fence = graph.variants.first().map(|variant| variant.fence_counter);
    let view = MissionView {
        mission: graph.mission,
        packages: graph.packages,
        fence,
    };
    let as_of_sequence = ledger.latest_event_sequence()?;
    snapshot_response(view, as_of_sequence)
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

async fn outbox(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let view = OutboxView {
        items: ledger.outbox_all()?,
    };
    let as_of_sequence = ledger.latest_event_sequence()?;
    snapshot_response(view, as_of_sequence)
}

pub(crate) fn snapshot_response<T: Serialize>(
    data: T,
    as_of_sequence: u64,
) -> Result<Response, ApiError> {
    let mut response = Json(data).into_response();
    let value = HeaderValue::from_str(&as_of_sequence.to_string())
        .map_err(|err| ApiError::Internal(format!("snapshot header: {err}")))?;
    response
        .headers_mut()
        .insert(SNAPSHOT_SEQUENCE_HEADER, value);
    Ok(response)
}

#[derive(Deserialize)]
struct EventsQuery {
    after: Option<String>,
}

async fn events(
    State(state): State<SharedState>,
    Query(query): Query<EventsQuery>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<SseFrame, io::Error>>>, ApiError> {
    let after = event_cursor(query.after.as_deref(), &headers)?;
    Ok(Sse::new(event_stream(state, after)).keep_alive(KeepAlive::default()))
}

fn event_cursor(after: Option<&str>, headers: &HeaderMap) -> Result<u64, ApiError> {
    let last_event_id = headers
        .get("last-event-id")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::BadRequest("INVALID_CURSOR"))
        })
        .transpose()?;
    if after.is_some() && last_event_id.is_some() {
        return Err(ApiError::BadRequest("CONFLICTING_CURSOR"));
    }
    after.or(last_event_id).map_or(Ok(0), |value| {
        value
            .parse::<u64>()
            .map_err(|_| ApiError::BadRequest("INVALID_CURSOR"))
    })
}

fn event_stream(state: SharedState, after: u64) -> impl Stream<Item = Result<SseFrame, io::Error>> {
    let seed: (SharedState, u64, VecDeque<LedgerEvent>) = (state, after, VecDeque::new());
    futures_util::stream::unfold(seed, |(state, mut last, mut buffer)| async move {
        loop {
            if let Some(event) = buffer.pop_front() {
                let frame = sse_frame(&event);
                return Some((frame, (state, last, buffer)));
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
                    tracing::error!(error = %err, "event poll failed; closing stream");
                    return None;
                }
            }
        }
    })
}

#[derive(Serialize)]
struct EventEnvelope<'a> {
    id: &'a str,
    seq: u64,
    at: &'a str,
    kind: &'a str,
    body: &'a str,
}

fn sse_frame(event: &LedgerEvent) -> Result<SseFrame, io::Error> {
    let id = event
        .event_id
        .as_deref()
        .ok_or_else(|| io::Error::other("durable event has no id"))?;
    let envelope = EventEnvelope {
        id,
        seq: event.seq,
        at: &event.at,
        kind: &event.kind,
        body: &event.body,
    };
    let data = serde_json::to_string(&envelope).map_err(io::Error::other)?;
    Ok(SseFrame::default().id(event.seq.to_string()).data(data))
}
