//! HTTP + SSE API. Generated TypeScript clients consume this contract.

pub(crate) mod meta;
pub(crate) mod portal;
mod routes;
mod safe_integer;
use crate::errors::ApiError;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::sse::{Event as SseFrame, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use bullet_adapters::SqliteLedger;
use bullet_application::{derive_receipt, Ledger, LedgerError, LedgerEvent, OutboxItem};
use bullet_domain::{Digest, Mission, MissionId};
use chrono::{DateTime, Utc};
use futures_util::stream::Stream;
use serde::Serialize;
use std::collections::VecDeque;
use std::io;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const REPLAY_BATCH_SIZE: usize = 64;
const MAX_REPLAY_EVENTS: u64 = 1_024;
const SNAPSHOT_SOURCE: &str = "bullet-kernel/sqlite-ledger";
const SNAPSHOT_SEQUENCE_HEADER: HeaderName = HeaderName::from_static("x-bullet-as-of-sequence");
const DEFAULT_ORIGIN: &str = "http://127.0.0.1:7420";
pub(crate) const BROWSER_SESSION_SECONDS: u64 = 8 * 60 * 60;

/// Shared daemon state. The async mutex cannot poison; a panicked holder
/// simply releases the lock.
pub struct AppState {
    pub(crate) ledger: Mutex<SqliteLedger>,
    pub(crate) auth: Mutex<crate::auth::AuthState>,
    /// What farmd's writer-lease maintenance tick has reclaimed so far.
    pub(crate) reaper: crate::reaper::ReapObservation,
}

pub type SharedState = Arc<AppState>;

/// Build the router against a SQLite file.
///
/// # Errors
///
/// Returns a ledger error when the database cannot be opened or migrated.
pub fn router(db: &FsPath) -> Result<Router, LedgerError> {
    daemon(db, None, DEFAULT_ORIGIN.to_string(), None).map(|(router, _)| router)
}

/// Build the local browser router with one short-lived bootstrap token.
///
/// # Errors
///
/// Returns a ledger or invalid loopback-origin configuration error.
pub fn router_with_bootstrap(
    db: &FsPath,
    bootstrap_token: &str,
    portal_origin: String,
) -> Result<Router, LedgerError> {
    daemon(db, Some(bootstrap_token), portal_origin, None).map(|(router, _)| router)
}

/// Build the local browser router with independent internal worker authority.
///
/// # Errors
///
/// Returns a ledger error or invalid bootstrap/origin/worker token error.
pub fn router_with_authorities(
    db: &FsPath,
    bootstrap_token: &str,
    portal_origin: String,
    worker_token: &str,
) -> Result<Router, LedgerError> {
    daemon(db, Some(bootstrap_token), portal_origin, Some(worker_token)).map(|(router, _)| router)
}

/// Build the router together with the state it serves, so the daemon can run
/// its writer-lease maintenance tick against exactly the ledger this API
/// answers from. `bootstrap_token` is `None` for the unauthenticated local
/// router; `worker_token` mounts the reconciler's independent authority.
///
/// # Errors
///
/// Returns a ledger error or an invalid bootstrap/origin/worker token error.
pub fn daemon(
    db: &FsPath,
    bootstrap_token: Option<&str>,
    portal_origin: String,
    worker_token: Option<&str>,
) -> Result<(Router, SharedState), LedgerError> {
    let auth = match bootstrap_token {
        Some(token) => crate::auth::AuthState::new(token, portal_origin),
        None => Ok(crate::auth::AuthState::disabled(portal_origin)),
    };
    let auth = match worker_token {
        Some(token) => auth.and_then(|auth| auth.with_worker_token(token)),
        None => auth,
    };
    let ledger = SqliteLedger::open(db)?;
    let state: SharedState = Arc::new(AppState {
        ledger: Mutex::new(ledger),
        auth: Mutex::new(auth.map_err(LedgerError::Store)?),
        reaper: crate::reaper::ReapObservation::default(),
    });
    let router = routes::router()
        .merge(portal::router())
        .fallback(api_not_found)
        .with_state(Arc::clone(&state));
    Ok((router, state))
}

async fn api_not_found() -> ApiError {
    ApiError::NotFound("API route".into())
}

async fn retired_api_version() -> ApiError {
    ApiError::protocol(
        axum::http::StatusCode::GONE,
        "API_VERSION_RETIRED",
        "The legacy /v1 operator API is retired and performs no operation.",
        "Repeat the request against /api/v1 after refreshing the current OpenAPI contract.",
    )
}

async fn list_missions(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (missions, as_of_sequence) = ledger.read_snapshot(Ledger::list_missions)?;
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
    let (graph, as_of_sequence) = ledger.read_snapshot(|ledger| ledger.get_graph(&mission_id))?;
    let graph = graph.ok_or_else(|| ApiError::NotFound(format!("mission {id}")))?;
    let fence = graph.variants.first().map(|variant| variant.fence_counter);
    let view = MissionView {
        mission: graph.mission,
        packages: graph.packages,
        fence,
    };
    snapshot_response(view, as_of_sequence)
}

async fn get_demo(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (receipt, as_of_sequence) = ledger.read_snapshot(derive_receipt)?;
    snapshot_response(receipt, as_of_sequence)
}

async fn removed_demo_mutation() -> ApiError {
    ApiError::protocol(
        axum::http::StatusCode::GONE,
        "MUTATION_ENDPOINT_REMOVED",
        "Direct demo mutation was removed because transport success is not verification.",
        "Submit an authenticated run_demo envelope to POST /api/v1/commands and reconcile its command id.",
    )
}

#[derive(Serialize)]
struct OutboxView {
    items: Vec<OutboxItem>,
}

async fn outbox(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (view, as_of_sequence) = ledger.read_snapshot(|ledger| {
        Ok(OutboxView {
            items: ledger.outbox_all()?,
        })
    })?;
    for item in &view.items {
        safe_integer::outbox_sequence(item.seq)?;
    }
    snapshot_response(view, as_of_sequence)
}

#[derive(Serialize)]
struct Snapshot<T> {
    data: T,
    as_of_sequence: u64,
    observed_at: String,
    source: &'static str,
}

pub(crate) fn snapshot_response<T: Serialize>(
    data: T,
    as_of_sequence: u64,
) -> Result<Response, ApiError> {
    safe_integer::snapshot_watermark(as_of_sequence)?;
    let body = Snapshot {
        data,
        as_of_sequence,
        observed_at: bullet_application::LeaseService::rfc3339(Utc::now()),
        source: SNAPSHOT_SOURCE,
    };
    let mut response = Json(body).into_response();
    let value = HeaderValue::from_str(&as_of_sequence.to_string())
        .map_err(|err| ApiError::Internal(format!("snapshot header: {err}")))?;
    response
        .headers_mut()
        .insert(SNAPSHOT_SEQUENCE_HEADER, value);
    Ok(response)
}

async fn events(
    State(state): State<SharedState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<SseFrame, io::Error>>>, ApiError> {
    let after = event_cursor(query.as_deref(), &headers)?;
    let initial = replay_preflight(&state, after).await?;
    Ok(Sse::new(event_stream(state, after, initial)).keep_alive(KeepAlive::default()))
}

fn event_cursor(query: Option<&str>, headers: &HeaderMap) -> Result<u64, ApiError> {
    let query_cursor = match query {
        None => None,
        Some(raw) => {
            let fields: Vec<_> = raw.split('&').collect();
            if fields.len() != 1 {
                let after_count = fields
                    .iter()
                    .filter(|field| field.starts_with("after="))
                    .count();
                return Err(ApiError::BadRequest(if after_count > 1 {
                    "CONFLICTING_CURSOR"
                } else {
                    "INVALID_CURSOR"
                }));
            }
            Some(
                fields[0]
                    .strip_prefix("after=")
                    .ok_or(ApiError::BadRequest("INVALID_CURSOR"))?,
            )
        }
    };
    let mut header_values = headers.get_all("last-event-id").iter();
    let last_event_id = header_values
        .next()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::BadRequest("INVALID_CURSOR"))
        })
        .transpose()?;
    if header_values.next().is_some() {
        return Err(ApiError::BadRequest("CONFLICTING_CURSOR"));
    }
    if query_cursor.is_some() && last_event_id.is_some() {
        return Err(ApiError::BadRequest("CONFLICTING_CURSOR"));
    }
    query_cursor.or(last_event_id).map_or(Ok(0), parse_cursor)
}

fn parse_cursor(value: &str) -> Result<u64, ApiError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::BadRequest("INVALID_CURSOR"));
    }
    value
        .parse::<u64>()
        .map_err(|_| ApiError::BadRequest("INVALID_CURSOR"))
}

async fn replay_preflight(
    state: &SharedState,
    after: u64,
) -> Result<VecDeque<LedgerEvent>, ApiError> {
    let ledger = state.ledger.lock().await;
    let ((earliest, latest, initial), watermark) = ledger.read_snapshot(|ledger| {
        let earliest = ledger
            .list_events_after(0, 1)?
            .first()
            .map(|event| event.seq);
        let latest = ledger.latest_event_sequence()?;
        let initial = if after <= latest {
            ledger.list_events_after(after, MAX_REPLAY_EVENTS as usize)?
        } else {
            Vec::new()
        };
        Ok((earliest, latest, initial))
    })?;
    if latest != watermark {
        return Err(ApiError::Internal(
            "snapshot returned inconsistent replay watermark".into(),
        ));
    }
    if after > latest {
        return Err(replay_unavailable(
            after,
            latest,
            "cursor is ahead of the durable log",
        ));
    }
    if let Some(earliest) = earliest {
        if earliest > after.saturating_add(1) {
            return Err(replay_unavailable(
                after,
                latest,
                "required prefix was retained away",
            ));
        }
    }
    if latest.saturating_sub(after) > MAX_REPLAY_EVENTS {
        return Err(replay_unavailable(
            after,
            latest,
            "replay exceeds the bounded window",
        ));
    }
    if after < latest && initial.is_empty() {
        return Err(replay_unavailable(
            after,
            latest,
            "the next sequence is unavailable",
        ));
    }
    validate_batch(after, &initial)?;
    Ok(initial.into())
}

fn replay_unavailable(after: u64, latest: u64, reason: &str) -> ApiError {
    ApiError::ReplayUnavailable(format!(
        "Exclusive cursor {after} cannot be replayed through sequence {latest}: {reason}."
    ))
}

fn validate_batch(after: u64, events: &[LedgerEvent]) -> Result<(), ApiError> {
    let mut expected = after
        .checked_add(1)
        .ok_or_else(|| replay_unavailable(after, after, "cursor cannot advance"))?;
    for event in events {
        if event.seq != expected {
            return Err(replay_unavailable(
                after,
                event.seq,
                "the durable sequence has a gap",
            ));
        }
        validate_event(event)?;
        expected = expected
            .checked_add(1)
            .ok_or_else(|| replay_unavailable(after, event.seq, "sequence overflow"))?;
    }
    Ok(())
}

pub(crate) fn validate_event(event: &LedgerEvent) -> Result<(), ApiError> {
    safe_integer::event_sequence(event.seq)?;
    let id = event
        .event_id
        .as_deref()
        .ok_or_else(|| ApiError::Internal("durable event id is absent".into()))?;
    let expected_id =
        Digest::of(format!("evt:{}:{}:{}", event.seq, event.kind, event.body).as_bytes()).to_hex();
    if id != expected_id || event.sequence != Some(event.seq) || event.kind.is_empty() {
        return Err(ApiError::Internal(
            "durable event envelope failed integrity validation".into(),
        ));
    }
    DateTime::parse_from_rfc3339(&event.at)
        .map_err(|_| ApiError::Internal("durable event timestamp is malformed".into()))?;
    Ok(())
}

fn event_stream(
    state: SharedState,
    after: u64,
    initial: VecDeque<LedgerEvent>,
) -> impl Stream<Item = Result<SseFrame, io::Error>> {
    let seed: (SharedState, u64, VecDeque<LedgerEvent>) = (state, after, initial);
    futures_util::stream::unfold(seed, |(state, mut last, mut buffer)| async move {
        loop {
            if let Some(event) = buffer.pop_front() {
                let frame = sse_frame(&event);
                last = event.seq;
                return Some((frame, (state, last, buffer)));
            }
            let batch = {
                let ledger = state.ledger.lock().await;
                ledger.list_events_after(last, REPLAY_BATCH_SIZE)
            };
            match batch {
                Ok(events) if !events.is_empty() => {
                    if validate_batch(last, &events).is_err() {
                        tracing::error!(
                            after = last,
                            "event replay validation failed; closing stream"
                        );
                        return None;
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
    safe_integer::event_sequence(event.seq)
        .map_err(|_| io::Error::other("event sequence exceeds JavaScript safe integer range"))?;
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
