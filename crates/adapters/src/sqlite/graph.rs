//! Graph snapshots, typed attempts, and append-only candidate/evidence/
//! effect rows.

use super::{commands, context, events, from_json, json, store};
use bullet_application::{
    graph_delta::{evaluate_graph_delta, GraphDeltaCommandResult},
    CommandRequest, GraphDelta, LedgerError, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, CommandPhase, DomainError, Mission, MissionId, RunnerId,
    VariantId, WorkPackageId, WorkPackageState, WorkspaceId,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub(super) const LIVE_STATES: &str = "('starting','running','paused','checkpointing','preparing')";

pub(super) fn nonce_from(blob: Vec<u8>) -> Result<[u8; 32], LedgerError> {
    blob.try_into()
        .map_err(|_| LedgerError::Store("workspace nonce must be 32 bytes".into()))
}

pub(super) fn materialize_graph(
    conn: &mut Connection,
    graph: &StoredGraph,
    now: &str,
) -> Result<(), LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let mission_key = graph.mission.id.to_string();
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM graphs WHERE mission_id = ?1)",
            params![mission_key],
            |row| row.get(0),
        )
        .map_err(store)?;
    if exists {
        return Err(
            DomainError::Conflict(format!("graph {mission_key} already materialized")).into(),
        );
    }
    tx.execute(
        "INSERT INTO graphs (mission_id, body) VALUES (?1, ?2)",
        params![mission_key, json(graph)?],
    )
    .map_err(store)?;
    context::insert_initial_set(&tx, graph, now)?;
    for variant in &graph.variants {
        tx.execute(
            "INSERT INTO variant_fence_counters (variant_id, next_fence) VALUES (?1, 0)
             ON CONFLICT(variant_id) DO NOTHING",
            params![variant.id.to_string()],
        )
        .map_err(store)?;
    }
    for package in &graph.packages {
        if package.state == WorkPackageState::Ready {
            tx.execute(
                "INSERT INTO ready_queue (work_package_id, enqueued_at) VALUES (?1, ?2)
                 ON CONFLICT(work_package_id) DO NOTHING",
                params![package.id.to_string(), now],
            )
            .map_err(store)?;
        }
    }
    events::insert_event(
        &tx,
        "graph_materialized",
        graph.mission.id.as_str(),
        Some(&mission_key),
        None,
        None,
    )?;
    tx.commit().map_err(store)
}

pub(super) fn put_graph(conn: &Connection, graph: &StoredGraph) -> Result<(), LedgerError> {
    let changed = conn
        .execute(
            "UPDATE graphs SET body = ?2 WHERE mission_id = ?1",
            params![graph.mission.id.to_string(), json(graph)?],
        )
        .map_err(store)?;
    if changed == 0 {
        return Err(LedgerError::Store(format!(
            "graph {} was never materialized",
            graph.mission.id
        )));
    }
    Ok(())
}

fn delta_step(fail_after: &mut Option<u8>) -> Result<(), LedgerError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(LedgerError::Store("injected graph delta failpoint".into()))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

pub(super) fn apply_graph_delta(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    request: &CommandRequest,
    mission: &MissionId,
    delta: &GraphDelta,
) -> Result<StoredGraph, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    delta_step(fail_after)?;
    let record = commands::record_command(&tx, request)?;
    match record.phase {
        CommandPhase::Applied | CommandPhase::Verified => {
            let response = record.response.ok_or_else(|| {
                LedgerError::Store("applied delta command has no stored result".into())
            })?;
            return match GraphDeltaCommandResult::decode(&response)? {
                GraphDeltaCommandResult::Applied { graph } if graph.mission.id == *mission => {
                    Ok(*graph)
                }
                GraphDeltaCommandResult::Applied { .. } => Err(LedgerError::Store(
                    "applied delta result belongs to another mission".into(),
                )),
                GraphDeltaCommandResult::Failed { .. } => Err(LedgerError::Store(
                    "applied delta command stores a failed result".into(),
                )),
            };
        }
        CommandPhase::Failed => {
            let response = record.response.ok_or_else(|| {
                LedgerError::Store("failed delta command has no stored result".into())
            })?;
            return match GraphDeltaCommandResult::decode(&response)? {
                GraphDeltaCommandResult::Failed { error } => Err(error.into_error()),
                GraphDeltaCommandResult::Applied { .. } => Err(LedgerError::Store(
                    "failed delta command stores an applied result".into(),
                )),
            };
        }
        CommandPhase::Pending | CommandPhase::Unknown => {}
    }

    let graph = get_graph(&tx, mission)?.ok_or_else(|| LedgerError::Store("graph missing".into()));
    let next = match graph.and_then(|graph| evaluate_graph_delta(&graph, delta)) {
        Ok(next) => next,
        Err(error) => {
            let response = GraphDeltaCommandResult::failed(&error)?;
            delta_step(fail_after)?;
            commands::set_phase(
                &tx,
                &request.idempotency_key,
                CommandPhase::Failed,
                Some(&response),
            )?;
            delta_step(fail_after)?;
            tx.commit().map_err(store)?;
            delta_step(fail_after)?;
            return Err(error);
        }
    };

    let response = GraphDeltaCommandResult::applied(&next)?;
    let event_body = delta.digest()?.to_hex();
    delta_step(fail_after)?;
    put_graph(&tx, &next)?;
    delta_step(fail_after)?;
    events::insert_event(&tx, "graph_delta", &event_body, None, None, None)?;
    delta_step(fail_after)?;
    commands::set_phase(
        &tx,
        &request.idempotency_key,
        CommandPhase::Applied,
        Some(&response),
    )?;
    delta_step(fail_after)?;
    tx.commit().map_err(store)?;
    delta_step(fail_after)?;
    Ok(next)
}

pub(super) fn get_graph(
    conn: &Connection,
    mission: &MissionId,
) -> Result<Option<StoredGraph>, LedgerError> {
    let body = conn
        .query_row(
            "SELECT body FROM graphs WHERE mission_id = ?1",
            params![mission.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(store)?;
    body.map(|text| from_json(&text)).transpose()
}

pub(super) fn list_missions(conn: &Connection) -> Result<Vec<Mission>, LedgerError> {
    let mut stmt = conn.prepare("SELECT body FROM graphs").map_err(store)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        let graph: StoredGraph = from_json(&row.map_err(store)?)?;
        out.push(graph.mission);
    }
    Ok(out)
}

pub(super) type AttemptRow = (
    String,
    String,
    String,
    i64,
    String,
    i64,
    String,
    Vec<u8>,
    i64,
    i64,
    String,
);

pub(super) const ATTEMPT_COLUMNS: &str =
    "id, variant_id, work_package_id, fence, runner_id, runner_epoch, \
                               workspace_id, workspace_nonce, scope_revision, context_revision, \
                               state";

pub(super) fn read_attempt(row: AttemptRow) -> Result<Attempt, LedgerError> {
    let (id, variant, package, fence, runner, epoch, workspace, nonce, scope, context, state) = row;
    Ok(Attempt {
        id: AttemptId::parse(&id)?,
        variant_id: VariantId::parse(&variant)?,
        work_package_id: WorkPackageId::parse(&package)?,
        fence: u64::try_from(fence).map_err(store)?,
        runner_id: RunnerId::parse(&runner)?,
        runner_epoch: u64::try_from(epoch).map_err(store)?,
        workspace_id: WorkspaceId::parse(&workspace)?,
        workspace_nonce: nonce_from(nonce)?,
        scope_revision: u64::try_from(scope).map_err(store)?,
        context_revision: u64::try_from(context).map_err(store)?,
        state: AttemptState::parse(&state)?,
    })
}

pub(super) fn attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttemptRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

pub(super) fn get_attempt(
    conn: &Connection,
    id: &AttemptId,
) -> Result<Option<Attempt>, LedgerError> {
    let row = conn
        .query_row(
            &format!("SELECT {ATTEMPT_COLUMNS} FROM attempts WHERE id = ?1"),
            params![id.to_string()],
            attempt_row,
        )
        .optional()
        .map_err(store)?;
    row.map(read_attempt).transpose()
}

pub(super) fn insert_attempt(conn: &Connection, attempt: &Attempt) -> Result<(), LedgerError> {
    conn.execute(
        "INSERT INTO attempts (id, variant_id, work_package_id, fence, runner_id, runner_epoch,
                               workspace_id, workspace_nonce, scope_revision, context_revision,
                               state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            attempt.id.to_string(),
            attempt.variant_id.to_string(),
            attempt.work_package_id.to_string(),
            i64::try_from(attempt.fence).map_err(store)?,
            attempt.runner_id.to_string(),
            i64::try_from(attempt.runner_epoch).map_err(store)?,
            attempt.workspace_id.to_string(),
            attempt.workspace_nonce.to_vec(),
            i64::try_from(attempt.scope_revision).map_err(store)?,
            i64::try_from(attempt.context_revision).map_err(store)?,
            attempt.state.as_str(),
        ],
    )
    .map_err(store)?;
    Ok(())
}

pub(super) fn put_attempt(conn: &mut Connection, attempt: &Attempt) -> Result<(), LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    put_attempt_on(&tx, attempt)?;
    tx.commit().map_err(store)
}

pub(in crate::sqlite) fn put_attempt_on(
    tx: &rusqlite::Transaction<'_>,
    attempt: &Attempt,
) -> Result<(), LedgerError> {
    let existing = get_attempt(tx, &attempt.id)?.ok_or_else(|| {
        LedgerError::Domain(DomainError::Conflict(format!(
            "attempt {} does not exist; attempts are created by acquire_lease",
            attempt.id
        )))
    })?;
    if existing.variant_id != attempt.variant_id
        || existing.work_package_id != attempt.work_package_id
        || existing.fence != attempt.fence
        || existing.runner_id != attempt.runner_id
        || existing.runner_epoch != attempt.runner_epoch
        || existing.workspace_id != attempt.workspace_id
        || existing.workspace_nonce != attempt.workspace_nonce
    {
        return Err(DomainError::Conflict(format!(
            "attempt {} identity columns are immutable",
            attempt.id
        ))
        .into());
    }
    if existing.state != attempt.state {
        existing.state.transition(attempt.state)?;
    }
    tx.execute(
        "UPDATE attempts SET state = ?2, scope_revision = ?3, context_revision = ?4
         WHERE id = ?1",
        params![
            attempt.id.to_string(),
            attempt.state.as_str(),
            i64::try_from(attempt.scope_revision).map_err(store)?,
            i64::try_from(attempt.context_revision).map_err(store)?,
        ],
    )
    .map_err(store)?;
    Ok(())
}

pub(super) fn active_attempt(
    conn: &Connection,
    package: &WorkPackageId,
) -> Result<Option<Attempt>, LedgerError> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {ATTEMPT_COLUMNS} FROM attempts
                 WHERE work_package_id = ?1 AND state IN {LIVE_STATES} LIMIT 1"
            ),
            params![package.to_string()],
            attempt_row,
        )
        .optional()
        .map_err(store)?;
    row.map(read_attempt).transpose()
}

pub(super) fn list_attempts(
    conn: &Connection,
    mission: &MissionId,
) -> Result<Vec<Attempt>, LedgerError> {
    let Some(graph) = get_graph(conn, mission)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {ATTEMPT_COLUMNS} FROM attempts WHERE variant_id = ?1 ORDER BY fence"
        ))
        .map_err(store)?;
    for variant in &graph.variants {
        let rows = stmt
            .query_map(params![variant.id.to_string()], attempt_row)
            .map_err(store)?;
        for row in rows {
            out.push(read_attempt(row.map_err(store)?)?);
        }
    }
    Ok(out)
}

pub(super) fn put_json_row<T: serde::Serialize>(
    conn: &Connection,
    table: &str,
    id: &str,
    value: &T,
) -> Result<bool, LedgerError> {
    let body = json(value)?;
    let changed = conn
        .execute(
            &format!("INSERT INTO {table} (id, body) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING"),
            params![id, body],
        )
        .map_err(store)?;
    if changed == 1 {
        return Ok(true);
    }
    let existing: String = conn
        .query_row(
            &format!("SELECT body FROM {table} WHERE id = ?1"),
            params![id],
            |row| row.get(0),
        )
        .map_err(store)?;
    if existing == body {
        Ok(false)
    } else {
        Err(DomainError::Conflict(format!("{table} row {id} differs from the stored row")).into())
    }
}

pub(super) fn get_json_row<T: serde::de::DeserializeOwned>(
    conn: &Connection,
    table: &str,
    id: &str,
) -> Result<Option<T>, LedgerError> {
    let body = conn
        .query_row(
            &format!("SELECT body FROM {table} WHERE id = ?1"),
            params![id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(store)?;
    body.map(|text| from_json(&text)).transpose()
}

/// Return a package to the ready queue when its writer lease ends, updating
/// the graph snapshot and the push-maintained ready row together.
pub(super) fn requeue_package(
    tx: &Connection,
    package: &WorkPackageId,
    now: &str,
) -> Result<(), LedgerError> {
    let missions = {
        let mut stmt = tx
            .prepare("SELECT mission_id FROM graphs ORDER BY mission_id")
            .map_err(store)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(store)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(store)?);
        }
        out
    };
    for mission in missions {
        let mission_id = MissionId::parse(&mission)?;
        let Some(mut stored) = get_graph(tx, &mission_id)? else {
            continue;
        };
        if let Some(idx) = stored.packages.iter().position(|p| p.id == *package) {
            let current = stored.packages[idx].state;
            if let Ok(next) = current.transition(WorkPackageState::Ready) {
                stored.packages[idx].state = next;
                put_graph(tx, &stored)?;
                tx.execute(
                    "INSERT INTO ready_queue (work_package_id, enqueued_at) VALUES (?1, ?2)
                     ON CONFLICT(work_package_id) DO NOTHING",
                    params![package.to_string(), now],
                )
                .map_err(store)?;
            }
            return Ok(());
        }
    }
    Err(LedgerError::Store(format!(
        "package {package} not in any graph"
    )))
}
