//! One-transaction Mission materialization and exact command replay.

use super::{commands, context, events, json, store};
use bullet_application::{
    materializer::MaterializeCommandResult, CommandRequest, LedgerError, StoredGraph,
};
use bullet_domain::{CommandPhase, DomainError, WorkPackageState};
use rusqlite::{params, Connection, TransactionBehavior};

fn step(fail_after: &mut Option<u8>) -> Result<(), LedgerError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(LedgerError::Store(
                "injected materialization failpoint".into(),
            ))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

pub(super) fn materialize_plan_command(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    request: &CommandRequest,
    graph: &StoredGraph,
    now: &str,
) -> Result<StoredGraph, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    step(fail_after)?;
    let record = commands::record_command(&tx, request)?;
    match record.phase {
        CommandPhase::Applied | CommandPhase::Verified => {
            let response = record.response.ok_or_else(|| {
                LedgerError::Store("applied materialization command has no stored result".into())
            })?;
            let graph = MaterializeCommandResult::decode(&response)?.graph_for(graph)?;
            context::require_initial_set(&tx, &graph)?;
            return Ok(graph);
        }
        CommandPhase::Failed | CommandPhase::Unknown => {
            return Err(LedgerError::Store(format!(
                "materialization command is {}",
                record.phase.as_str()
            )));
        }
        CommandPhase::Pending => {
            if record.response.is_some() {
                return Err(LedgerError::Store(
                    "pending materialization command has a stored result".into(),
                ));
            }
        }
    }

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
    let response = MaterializeCommandResult::applied(graph)?;

    step(fail_after)?;
    tx.execute(
        "INSERT INTO graphs (mission_id, body) VALUES (?1, ?2)",
        params![mission_key, json(graph)?],
    )
    .map_err(store)?;
    step(fail_after)?;
    context::insert_initial_set(&tx, graph, now)?;
    for variant in &graph.variants {
        step(fail_after)?;
        tx.execute(
            "INSERT INTO variant_fence_counters (variant_id, next_fence) VALUES (?1, 0)",
            params![variant.id.to_string()],
        )
        .map_err(store)?;
    }
    for package in &graph.packages {
        if package.state == WorkPackageState::Ready {
            step(fail_after)?;
            tx.execute(
                "INSERT INTO ready_queue (work_package_id, enqueued_at) VALUES (?1, ?2)",
                params![package.id.to_string(), now],
            )
            .map_err(store)?;
        }
    }
    step(fail_after)?;
    events::insert_event(
        &tx,
        "graph_materialized",
        graph.mission.id.as_str(),
        Some(&mission_key),
        Some(&request.idempotency_key),
        None,
    )?;
    step(fail_after)?;
    commands::set_phase(
        &tx,
        &request.idempotency_key,
        CommandPhase::Applied,
        Some(&response),
    )?;
    step(fail_after)?;
    tx.commit().map_err(store)?;
    step(fail_after)?;
    Ok(graph.clone())
}
