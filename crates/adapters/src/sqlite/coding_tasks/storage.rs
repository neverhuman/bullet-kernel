use super::super::{commands, store};
use bullet_application::coding_tasks::{
    coding_run_id, task_payload, CodingRuntimeSelection, CodingTaskContract,
};
use bullet_application::{CommandRecord, CommandRequest, LedgerError};
use bullet_domain::{CommandId, Digest};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;

pub(super) struct StoredTask {
    pub(super) revision_id: String,
    pub(super) operator: String,
    pub(super) contract: CodingTaskContract,
    pub(super) sequence: u64,
}

pub(super) struct StoredRun {
    pub(super) run_id: String,
    pub(super) operator: String,
    pub(super) task: StoredTask,
    pub(super) command: CommandRecord,
    pub(super) selection: CodingRuntimeSelection,
    pub(super) accepted_at: String,
}

pub(super) fn submitted(conn: &Connection, id: &CommandId) -> Result<(u64, String), LedgerError> {
    let mut query = conn.prepare("SELECT seq,at FROM events WHERE kind='command_submitted' AND body=?1 AND stream_id=?1 AND correlation_id=?1").map_err(store)?;
    let rows = query
        .query_map([id.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    let [(sequence, at)] = rows.as_slice() else {
        return Err(store("coding subject lacks one exact submitted event"));
    };
    let sequence = u64::try_from(*sequence).map_err(store)?;
    if !(1..=bullet_application::coding_tasks::MAX_CODING_SAFE_INTEGER).contains(&sequence) {
        return Err(store("coding event sequence is invalid"));
    }
    chrono::DateTime::parse_from_rfc3339(at).map_err(store)?;
    Ok((sequence, at.clone()))
}

struct TaskRow {
    operator: String,
    body: String,
    digest: String,
    command_id: String,
    sequence: i64,
    at: String,
}

pub(super) fn task(conn: &Connection, id: &str) -> Result<Option<StoredTask>, LedgerError> {
    let row = conn.query_row("SELECT operator_id,task_json,task_digest,accepted_command_id,accepted_sequence,accepted_at FROM coding_task_revisions WHERE revision_id=?1", [id], |row| Ok(TaskRow {
        operator: row.get(0)?, body: row.get(1)?, digest: row.get(2)?, command_id: row.get(3)?, sequence: row.get(4)?, at: row.get(5)?,
    })).optional().map_err(store)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let contract: CodingTaskContract = serde_json::from_str(&row.body).map_err(store)?;
    if contract.canonical_json().map_err(store)? != row.body
        || contract.revision_id(&row.operator).map_err(store)? != id
        || Digest::of(row.body.as_bytes()).to_hex() != row.digest
    {
        return Err(store("immutable coding task content or identity differs"));
    }
    let command_id = CommandId::parse(&row.command_id).map_err(store)?;
    let command = commands::get_command_by_id(conn, &command_id)?
        .ok_or_else(|| store("accepted task command absent"))?;
    let request =
        CommandRequest::from_json(&command.idempotency_key, &command.kind, &command.payload)
            .map_err(store)?;
    let payload = task_payload(&request)
        .map_err(store)?
        .ok_or_else(|| store("accepted task refers to legacy/noncoding command"))?;
    let submitted = submitted(conn, &command_id)?;
    let owner: Option<String> = conn
        .query_row(
            "SELECT operator_id FROM operator_command_ownership WHERE command_id=?1",
            [command_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(store)?;
    if payload.task != contract
        || owner.as_deref() != Some(&row.operator)
        || submitted.0 != u64::try_from(row.sequence).map_err(store)?
        || submitted.1 != row.at
    {
        return Err(store(
            "accepted task owner, request or audit binding differs",
        ));
    }
    let mut query = conn.prepare("SELECT d.dependency_id,t.operator_id,t.accepted_sequence FROM coding_task_dependencies d LEFT JOIN coding_task_revisions t ON t.revision_id=d.dependency_id WHERE d.revision_id=?1 ORDER BY d.dependency_id LIMIT 65").map_err(store)?;
    let edges = query
        .query_map([id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    if edges.iter().any(|(_, owner, sequence)| {
        owner.as_deref() != Some(row.operator.as_str())
            || !sequence.is_some_and(|sequence| sequence > 0 && sequence < row.sequence)
    }) || edges.iter().map(|edge| &edge.0).collect::<BTreeSet<_>>()
        != contract.dependencies.iter().collect::<BTreeSet<_>>()
    {
        return Err(store(
            "coding dependency lineage differs from accepted task",
        ));
    }
    Ok(Some(StoredTask {
        revision_id: id.into(),
        operator: row.operator,
        contract,
        sequence: submitted.0,
    }))
}

struct RunRow {
    id: String,
    operator: String,
    task: String,
    digest: String,
    selection: String,
    sequence: i64,
    at: String,
}

pub(super) fn run(conn: &Connection, request: &CommandRequest) -> Result<StoredRun, LedgerError> {
    let id = request.id();
    let row = conn.query_row("SELECT run_id,operator_id,task_revision_id,request_digest,selection_json,accepted_sequence,accepted_at FROM coding_runs WHERE command_id=?1", [id.as_str()], |row| Ok(RunRow {
        id: row.get(0)?, operator: row.get(1)?, task: row.get(2)?, digest: row.get(3)?, selection: row.get(4)?, sequence: row.get(5)?, at: row.get(6)?,
    })).map_err(store)?;
    let payload = task_payload(request)
        .map_err(store)?
        .ok_or_else(|| store("coding run has no task-shaped request"))?;
    let command = commands::get_command_by_id(conn, &id)?
        .ok_or_else(|| store("coding run command absent"))?;
    request.matches(&command).map_err(store)?;
    let task = task(conn, &row.task)?.ok_or_else(|| store("coding run task absent"))?;
    let selection: CodingRuntimeSelection = serde_json::from_str(&row.selection).map_err(store)?;
    let original = submitted(conn, &id)?;
    let owner: Option<String> = conn
        .query_row(
            "SELECT operator_id FROM operator_command_ownership WHERE command_id=?1",
            params![id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(store)?;
    if row.id != coding_run_id(&id)
        || row.digest != request.digest().to_hex()
        || row.operator != task.operator
        || owner.as_deref() != Some(&row.operator)
        || task.contract != payload.task
        || selection != payload.selection
        || serde_json::to_string(&selection).map_err(store)? != row.selection
        || original.0 != u64::try_from(row.sequence).map_err(store)?
        || original.1 != row.at
        || task.sequence > original.0
    {
        return Err(store(
            "coding run differs from immutable owner/request/task/audit bindings",
        ));
    }
    Ok(StoredRun {
        run_id: row.id,
        operator: row.operator,
        task,
        command,
        selection,
        accepted_at: row.at,
    })
}
