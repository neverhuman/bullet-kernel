//! Authenticated public command submission and durable reconciliation.

use crate::api::SharedState;
use crate::errors::ApiError;
use axum::extract::{rejection::JsonRejection, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bullet_application::operator_commands::{
    OperatorCommandError, OperatorCommandSnapshot, OperatorCommandStore,
};
use bullet_application::{CommandRecord, CommandRequest};
use bullet_harness_core::strict_json::StrictJson;

pub(crate) mod coding;
pub(crate) mod conversations;
pub(crate) mod discovery;
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
    body: Result<Json<StrictJson>, JsonRejection>,
) -> Result<Response, ApiError> {
    let operator = {
        let auth = state.auth.lock().await;
        auth.authorize_mutation(&headers)?;
        auth.authorize_session(&headers)?.operator_id
    };
    let value = body.map_err(|_| ApiError::invalid_json())?.0 .0;
    let body: CommandEnvelope =
        serde_json::from_value(value).map_err(|_| ApiError::invalid_json())?;
    let request = CommandRequest::new(body.idempotency_key, body.kind, &body.payload)?;
    let snapshot = state
        .ledger
        .lock()
        .await
        .submit_operator_command(&operator, &request)
        .map_err(operator_error)?;
    command_response(snapshot, StatusCode::ACCEPTED)
}

pub(crate) async fn get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let operator = state
        .auth
        .lock()
        .await
        .authorize_session(&headers)?
        .operator_id;
    let id = CommandId::parse(id)?;
    let snapshot = state
        .ledger
        .lock()
        .await
        .get_operator_command(&operator, &id)
        .map_err(operator_error)?
        .ok_or_else(|| ApiError::NotFound(format!("command {id}")))?;
    command_response(snapshot, StatusCode::OK)
}

fn command_response(
    snapshot: OperatorCommandSnapshot,
    status: StatusCode,
) -> Result<Response, ApiError> {
    if snapshot.as_of_sequence > 9_007_199_254_740_991 {
        return Err(ApiError::UnsafeInteger("CommandStatus.as_of_sequence"));
    }
    let mut response = (status, Json(status_view(snapshot.command)?)).into_response();
    response.headers_mut().insert(
        "x-bullet-as-of-sequence",
        HeaderValue::from_str(&snapshot.as_of_sequence.to_string())
            .map_err(|error| ApiError::Internal(error.to_string()))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn operator_error(error: OperatorCommandError) -> ApiError {
    match error {
        OperatorCommandError::Store(error)=>error.into(),
        OperatorCommandError::InvalidRequest=>ApiError::protocol(StatusCode::BAD_REQUEST,"OPERATOR_COMMAND_REQUEST_INVALID","The operator command query is invalid.","Use an authenticated operator, nonnegative safe-integer cursor and limit between 1 and 100."),
        OperatorCommandError::OwnershipConflict=>ApiError::protocol(StatusCode::CONFLICT,"COMMAND_OWNERSHIP_CONFLICT","The idempotency key is already bound outside this operator's command history.","Use a different key; historical unowned commands cannot be adopted by retry."),
        OperatorCommandError::ObsoleteCodingShape=>ApiError::protocol(StatusCode::CONFLICT,"RUN_CODING_LEGACY_AUTHORITY_SHAPE_RETIRED","New coding submissions cannot supply execution authority.","Submit bullet.run-coding.v2 task intent and runtime selection; exact retries of previously owned commands retain their original payload."),
    }
}

pub(crate) async fn reconcile(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Result<Json<CommandStatus>, ApiError> {
    state.auth.lock().await.authorize_worker(&headers)?;
    Err(ApiError::protocol(
        StatusCode::GONE,
        "WORKLOAD_API_UDS_REQUIRED",
        "Public HTTP cannot carry Runner workload authority and performs no reconciliation.",
        "Use the registered Runner service identity on the admitted Unix workload socket.",
    ))
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
    use bullet_application::commands::COMMAND_RECONCILED_EVENT;
    use bullet_application::operator_commands::validate_projection;
    use bullet_application::{
        CommandDispatchClaim, CommandDispatchDisposition, CommandRequest, LedgerEvent, OutboxItem,
    };

    fn fixture() -> (
        CommandRecord,
        String,
        CommandDispatchClaim,
        OutboxItem,
        Vec<LedgerEvent>,
    ) {
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
            delivered_at: Some("2026-08-25T00:00:00Z".into()),
            acked_at: Some("2026-08-25T00:00:00Z".into()),
        };
        let claim = CommandDispatchClaim {
            schema_version: "bullet.command-dispatch-claim.v1".into(),
            claim_id: format!("dcl_{}", "a".repeat(64)),
            command_id: record.id.clone(),
            outbox_sequence: 1,
            request: request.clone(),
            request_digest: request.digest(),
            runner_id: bullet_domain::RunnerId::from_seed("projection"),
            runner_epoch: 1,
            authority_epoch: 1,
            freeze_generation: 0,
            restore_epoch: 0,
            disposition: CommandDispatchDisposition::Unknown,
            completion_digest: Some(bullet_domain::Digest::of(response.as_bytes())),
            claimed_at: "2026-08-25T00:00:00Z".into(),
            updated_at: "2026-08-25T00:00:00Z".into(),
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
            event("command_dispatch_claimed", claim.claim_id.clone()),
            event(COMMAND_RECONCILED_EVENT, response),
        ];
        (record, dispatch, claim, outbox, events)
    }

    #[test]
    fn projection_requires_exact_correlated_result_and_outbox_truth() {
        let (record, dispatch, claim, outbox, events) = fixture();
        let request =
            CommandRequest::new("projection", "run_demo", &serde_json::json!({})).expect("request");
        assert_eq!(serde_json::to_string(&request).expect("dispatch"), dispatch);
        let settlement = request.offline_worker_resolution().expect("settlement");
        assert_eq!(settlement.phase(), CommandPhase::Unknown);
        assert!(settlement
            .response()
            .contains("EXECUTION_ADAPTER_UNAVAILABLE"));
        assert!(validate_projection(
            &record,
            &dispatch,
            Some(&claim),
            std::slice::from_ref(&outbox),
            &events
        )
        .is_ok());

        let mut substituted = record.clone();
        substituted.response = Some(r#"{"evidence":"PASS"}"#.into());
        assert!(validate_projection(
            &substituted,
            &dispatch,
            Some(&claim),
            std::slice::from_ref(&outbox),
            &events
        )
        .is_err());

        let mut wrong_phase = outbox;
        wrong_phase.phase = CommandPhase::Pending;
        assert!(
            validate_projection(&record, &dispatch, Some(&claim), &[wrong_phase], &events).is_err()
        );

        assert!(validate_projection(&record, &dispatch, Some(&claim), &[], &events).is_err());
        assert!(validate_projection(&record, &dispatch, None, &[fixture().3], &events).is_err());
        assert!(validate_projection(
            &record,
            &dispatch,
            Some(&claim),
            &[fixture().3],
            &events[..2]
        )
        .is_err());

        let mut conflicting_events = events;
        let mut conflict = conflicting_events[1].clone();
        conflict.stream_id = Some("cmd_conflict".into());
        conflicting_events.push(conflict);
        assert!(validate_projection(
            &record,
            &dispatch,
            Some(&claim),
            &[fixture().3],
            &conflicting_events
        )
        .is_err());
    }
}
