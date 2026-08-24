//! Authenticated public command submission and durable reconciliation.

use crate::api::SharedState;
use crate::errors::ApiError;
use axum::extract::{rejection::JsonRejection, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use bullet_application::{CommandRecord, CommandRequest, Ledger};
use bullet_domain::{CommandId, CommandPhase};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandEnvelope {
    idempotency_key: String,
    kind: String,
    payload: Map<String, Value>,
}

#[derive(Serialize)]
pub(crate) struct CommandStatus {
    id: String,
    status: &'static str,
    kind: String,
    payload_digest: String,
    result: Option<Value>,
}

pub(crate) async fn submit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Result<Json<CommandEnvelope>, JsonRejection>,
) -> Result<(StatusCode, Json<CommandStatus>), ApiError> {
    state.auth.lock().await.authorize_mutation(&headers)?;
    let body = body.map_err(|_| ApiError::invalid_json())?.0;
    let request = CommandRequest::new(body.idempotency_key, body.kind, &body.payload)?;
    let mut ledger = state.ledger.lock().await;
    let record = ledger.submit_command(&request)?;
    Ok((StatusCode::ACCEPTED, Json(status_view(record)?)))
}

pub(crate) async fn get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<CommandStatus>, ApiError> {
    state.auth.lock().await.authorize_read(&headers)?;
    let id = CommandId::parse(id)?;
    let ledger = state.ledger.lock().await;
    let record = ledger
        .get_command_by_id(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("command {id}")))?;
    let request = CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)
        .map_err(|error| ApiError::Internal(format!("persisted command request: {error}")))?;
    let dispatch = serde_json::to_string(&request)
        .map_err(|error| ApiError::Internal(format!("command dispatch encoding: {error}")))?;
    let outbox = ledger.outbox_for_command(&id)?;
    if outbox.len() != 1 || outbox[0].kind != "command_dispatch" || outbox[0].payload != dispatch {
        return Err(ApiError::Internal(
            "command has incomplete or conflicting dispatch truth".into(),
        ));
    }
    let submitted_events = ledger
        .list_events()?
        .into_iter()
        .filter(|event| {
            event.kind == "command_submitted"
                && event.body == id.as_str()
                && event.correlation_id.as_deref() == Some(id.as_str())
        })
        .count();
    if submitted_events != 1 {
        return Err(ApiError::Internal(
            "command has incomplete or conflicting submitted audit truth".into(),
        ));
    }
    Ok(Json(status_view(record)?))
}

fn status_view(record: CommandRecord) -> Result<CommandStatus, ApiError> {
    let result = record
        .response
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| ApiError::Internal(format!("persisted command result: {error}")))?;
    Ok(CommandStatus {
        id: record.id.to_string(),
        status: status_name(record.phase),
        kind: record.kind,
        payload_digest: record.payload_digest.to_hex(),
        result,
    })
}

fn status_name(phase: CommandPhase) -> &'static str {
    match phase {
        CommandPhase::Pending => "PENDING",
        CommandPhase::Applied => "APPLIED",
        CommandPhase::Verified => "VERIFIED",
        CommandPhase::Failed => "FAILED",
        CommandPhase::Unknown => "UNKNOWN",
    }
}
