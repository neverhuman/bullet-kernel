use super::super::{commands, store};
use super::storage;
use bullet_application::coding_tasks::{coding_run_id, CodingTaskRefusal, RunCodingTaskPayload};
use bullet_application::{CommandRequest, LedgerError};
use bullet_domain::Digest;
use rusqlite::{params, Transaction};

pub(in crate::sqlite) fn admit(
    tx: &Transaction<'_>,
    fail_after: &mut Option<u8>,
    operator: &str,
    request: &CommandRequest,
    payload: &RunCodingTaskPayload,
) -> Result<(), LedgerError> {
    payload.validate()?;
    let revision_id = payload.task.revision_id(operator)?;
    let submitted = storage::submitted(tx, &request.id())?;
    let accepted_ms = chrono::DateTime::parse_from_rfc3339(&submitted.1)
        .map_err(store)?
        .timestamp_millis();
    if payload.task.deadline_unix_ms <= u64::try_from(accepted_ms).map_err(store)? {
        return Err(CodingTaskRefusal::DeadlineExpired.into());
    }
    let existing = storage::task(tx, &revision_id)?;
    if let Some(existing) = &existing {
        if existing.operator != operator || existing.contract != payload.task {
            return Err(store(
                "coding revision identity collides with different task intent",
            ));
        }
    }
    for dependency in &payload.task.dependencies {
        let known =
            storage::task(tx, dependency)?.ok_or(CodingTaskRefusal::DependencyNotAccepted)?;
        if dependency == &revision_id || known.operator != operator || known.sequence >= submitted.0
        {
            return Err(CodingTaskRefusal::DependencyNotAccepted.into());
        }
    }
    let count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM coding_runs WHERE task_revision_id=?1",
            [&revision_id],
            |row| row.get(0),
        )
        .map_err(store)?;
    if count >= i64::from(payload.task.budget.max_invocations) {
        return Err(CodingTaskRefusal::InvocationLimit.into());
    }
    if existing.is_none() {
        let body = payload.task.canonical_json()?;
        tx.execute("INSERT INTO coding_task_revisions(revision_id,operator_id,task_json,task_digest,accepted_command_id,accepted_sequence,accepted_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![revision_id, operator, body, Digest::of(body.as_bytes()).to_hex(), request.id().as_str(), i64::try_from(submitted.0).map_err(store)?, submitted.1]).map_err(store)?;
        commands::fail_boundary(fail_after)?;
        for dependency in &payload.task.dependencies {
            tx.execute(
                "INSERT INTO coding_task_dependencies(revision_id,dependency_id) VALUES(?1,?2)",
                params![revision_id, dependency],
            )
            .map_err(store)?;
            commands::fail_boundary(fail_after)?;
        }
    }
    let selection = serde_json::to_string(&payload.selection).map_err(store)?;
    tx.execute("INSERT INTO coding_runs(run_id,command_id,operator_id,task_revision_id,request_digest,selection_json,accepted_sequence,accepted_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![coding_run_id(&request.id()), request.id().as_str(), operator, revision_id, request.digest().to_hex(), selection, i64::try_from(submitted.0).map_err(store)?, submitted.1]).map_err(store)?;
    commands::fail_boundary(fail_after)?;
    Ok(())
}
