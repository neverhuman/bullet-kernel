//! Owner-scoped accepted task intent. Queued intent is never execution authority.
use super::{operator_error, status_view, CommandStatus};
use crate::{api::SharedState, errors::ApiError};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use bullet_application::coding_tasks::{
    CodingQueueBlocker, CodingRuntimeSelection, CodingTaskContract, CodingTaskStore,
};
use bullet_domain::CommandId;
use serde::Serialize;

#[derive(Serialize)]
struct CodingRunView {
    command: CommandStatus,
    run_id: String,
    task_revision_id: String,
    task: CodingTaskContract,
    selection: CodingRuntimeSelection,
    accepted_at: String,
    blockers: Vec<CodingQueueBlocker>,
}

#[derive(Serialize)]
struct CodingRunSnapshot {
    data: CodingRunView,
    as_of_sequence: u64,
    observed_at: String,
    source: &'static str,
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
    let run = state
        .ledger
        .lock()
        .await
        .get_operator_coding(&operator, &id)
        .map_err(operator_error)?
        .ok_or_else(|| ApiError::NotFound(format!("coding command {id}")))?;
    if run.as_of_sequence > 9_007_199_254_740_991 {
        return Err(ApiError::UnsafeInteger("CodingRunSnapshot.as_of_sequence"));
    }
    let sequence = run.as_of_sequence;
    let snapshot = CodingRunSnapshot {
        data: CodingRunView {
            command: status_view(run.command)?,
            run_id: run.run_id,
            task_revision_id: run.task_revision_id,
            task: run.task,
            selection: run.selection,
            accepted_at: run.accepted_at,
            blockers: run.blockers,
        },
        as_of_sequence: sequence,
        observed_at: run.observed_at,
        source: "bullet-kernel/sqlite-ledger",
    };
    let mut response = Json(snapshot).into_response();
    response.headers_mut().insert(
        "x-bullet-as-of-sequence",
        HeaderValue::from_str(&sequence.to_string())
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}
