//! Authenticated public command submission and durable reconciliation.

use crate::api::SharedState;
use crate::errors::ApiError;
use axum::extract::{rejection::JsonRejection, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use bullet_application::commands::COMMAND_RECONCILED_EVENT;
use bullet_application::{CommandRecord, CommandRequest, Ledger, LedgerEvent, OutboxItem};
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
    let events = ledger.list_events()?;
    validate_projection(&record, &dispatch, &outbox, &events)?;
    Ok(Json(status_view(record)?))
}

fn validate_projection(
    record: &CommandRecord,
    dispatch: &str,
    outbox: &[OutboxItem],
    events: &[LedgerEvent],
) -> Result<(), ApiError> {
    if outbox.len() != 1
        || outbox[0].command_id.as_ref() != Some(&record.id)
        || outbox[0].kind != "command_dispatch"
        || outbox[0].payload != dispatch
    {
        return Err(ApiError::Internal(
            "command has incomplete or conflicting dispatch truth".into(),
        ));
    }
    let id = record.id.as_str();
    let submitted: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == "command_submitted"
                && (event.stream_id.as_deref() == Some(id)
                    || event.correlation_id.as_deref() == Some(id))
        })
        .collect();
    if submitted.len() != 1
        || submitted[0].body != id
        || submitted[0].stream_id.as_deref() != Some(id)
        || submitted[0].correlation_id.as_deref() != Some(id)
    {
        return Err(ApiError::Internal(
            "command has incomplete or conflicting submitted audit truth".into(),
        ));
    }
    let reconciled: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == COMMAND_RECONCILED_EVENT
                && (event.stream_id.as_deref() == Some(id)
                    || event.correlation_id.as_deref() == Some(id))
        })
        .collect();
    let row = &outbox[0];
    if record.phase == CommandPhase::Pending {
        if row.phase != CommandPhase::Pending
            || row.delivered_at.is_some()
            || row.acked_at.is_some()
            || !reconciled.is_empty()
        {
            return Err(ApiError::Internal(
                "pending command has conflicting projection truth".into(),
            ));
        }
        return Ok(());
    }
    let response = record
        .response
        .as_deref()
        .ok_or_else(|| ApiError::Internal("settled command has no exact result truth".into()))?;
    if row.phase != record.phase
        || row.acked_at.is_none()
        || reconciled.len() != 1
        || reconciled[0].stream_id.as_deref() != Some(id)
        || reconciled[0].correlation_id.as_deref() != Some(id)
        || reconciled[0].body != response
    {
        return Err(ApiError::Internal(
            "settled command has incomplete or conflicting projection truth".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn reconcile(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<CommandStatus>, ApiError> {
    state.auth.lock().await.authorize_worker(&headers)?;
    let id = CommandId::parse(id)?;
    let now = bullet_application::LeaseService::rfc3339(chrono::Utc::now());
    let mut ledger = state.ledger.lock().await;
    let record = ledger.reconcile_offline_command(&id, &now)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::CommandRequest;

    fn fixture() -> (CommandRecord, String, OutboxItem, Vec<LedgerEvent>) {
        let request =
            CommandRequest::new("projection", "run_demo", &serde_json::json!({})).expect("request");
        let resolution = request.offline_worker_resolution().expect("resolution");
        let response = resolution.response().to_string();
        let record = resolution
            .resolved_record(CommandRecord {
                id: request.id(),
                idempotency_key: request.idempotency_key.clone(),
                kind: request.kind.clone(),
                payload: request.payload.clone(),
                payload_digest: request.digest(),
                phase: CommandPhase::Pending,
                response: None,
            })
            .expect("record");
        let dispatch = serde_json::to_string(&request).expect("dispatch");
        let outbox = OutboxItem {
            seq: 1,
            command_id: Some(record.id.clone()),
            kind: "command_dispatch".into(),
            payload: dispatch.clone(),
            phase: record.phase,
            delivered_at: None,
            acked_at: Some("2026-08-25T00:00:00Z".into()),
        };
        let event = |kind: &str, body: String| LedgerEvent {
            seq: 1,
            at: "2026-08-25T00:00:00Z".into(),
            kind: kind.into(),
            body,
            event_id: Some("event".into()),
            stream_id: Some(record.id.to_string()),
            sequence: Some(1),
            causation_id: None,
            correlation_id: Some(record.id.to_string()),
            authority_token_hash: None,
        };
        let events = vec![
            event("command_submitted", record.id.to_string()),
            event(COMMAND_RECONCILED_EVENT, response),
        ];
        (record, dispatch, outbox, events)
    }

    #[test]
    fn projection_requires_exact_correlated_result_and_outbox_truth() {
        let (record, dispatch, outbox, events) = fixture();
        assert!(
            validate_projection(&record, &dispatch, std::slice::from_ref(&outbox), &events).is_ok()
        );

        let mut substituted = record.clone();
        substituted.response = Some(r#"{"evidence":"PASS"}"#.into());
        assert!(validate_projection(
            &substituted,
            &dispatch,
            std::slice::from_ref(&outbox),
            &events
        )
        .is_err());

        let mut wrong_phase = outbox;
        wrong_phase.phase = CommandPhase::Pending;
        assert!(validate_projection(&record, &dispatch, &[wrong_phase], &events).is_err());

        assert!(validate_projection(&record, &dispatch, &[], &events).is_err());
        assert!(validate_projection(&record, &dispatch, &[fixture().2], &events[..1]).is_err());

        let mut conflicting_events = events;
        let mut conflict = conflicting_events[1].clone();
        conflict.stream_id = Some("cmd_conflict".into());
        conflicting_events.push(conflict);
        assert!(
            validate_projection(&record, &dispatch, &[fixture().2], &conflicting_events).is_err()
        );
    }
}
