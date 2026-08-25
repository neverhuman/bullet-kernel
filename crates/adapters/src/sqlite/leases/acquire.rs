//! One-transaction lease acquisition and exact command replay.

use super::super::{commands, context, events, from_json, graph, json, lease_time, outbox, store};
use bullet_application::{
    ActiveLease, CommandRecord, CommandRequest, LeaseGrant, LeaseRequest, LedgerError,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, CommandPhase, Digest, DomainError, WorkPackageState,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

fn step(fail_after: &mut Option<u8>) -> Result<(), LedgerError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(LedgerError::Store(
                "injected lease acquisition failpoint".into(),
            ))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

pub(in crate::sqlite) fn acquire_lease(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    req: &LeaseRequest,
) -> Result<LeaseGrant, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let grant = acquire_on(&tx, fail_after, req)?;
    tx.commit().map_err(store)?;
    step(fail_after)?;
    Ok(grant)
}

pub(in crate::sqlite) fn acquire_on(
    tx: &Transaction<'_>,
    fail_after: &mut Option<u8>,
    req: &LeaseRequest,
) -> Result<LeaseGrant, LedgerError> {
    let stable = req.stable_payload()?;
    let command_request =
        CommandRequest::from_json(&req.idempotency_key, "acquire_lease", &stable)?;
    step(fail_after)?;

    if let Some(existing) = commands::get_command(tx, &req.idempotency_key)? {
        command_request.matches(&existing)?;
        let response = existing
            .response
            .ok_or_else(|| LedgerError::Store("lease command has no stored result".into()))?;
        let grant: LeaseGrant = from_json(&response)?;
        let graph = graph::get_graph(tx, &req.mission_id)?
            .ok_or_else(|| LedgerError::Store("lease replay graph missing".into()))?;
        context::require_revision(
            tx,
            &graph,
            &grant.attempt.work_package_id,
            grant.attempt.context_revision,
        )?;
        return Ok(grant);
    }

    let ttl_seconds = req.validated_ttl()?;
    let (now, expires_at) = lease_time::database_window(tx, ttl_seconds)?;
    // A runner that died without releasing leaves a holder row behind, and the
    // checks below refuse every successor while it exists. Reclaim it here, in
    // this same transaction and against this same database clock, so a crashed
    // incarnation can never block its Variant forever. A live lease is untouched.
    super::reclaim_expired_variant(tx, &req.variant_id, &now)?;
    let stored = graph::get_graph(tx, &req.mission_id)?
        .ok_or_else(|| LedgerError::Store("graph missing".into()))?;
    let variant_index = stored
        .variants
        .iter()
        .position(|variant| variant.id == req.variant_id)
        .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
    let package_index = stored
        .packages
        .iter()
        .position(|package| package.id == stored.variants[variant_index].work_package_id)
        .ok_or_else(|| LedgerError::Store("package missing".into()))?;
    context::require_revision(
        tx,
        &stored,
        &stored.packages[package_index].id,
        req.context_revision,
    )?;
    if stored.packages[package_index].state != WorkPackageState::Ready {
        return Err(DomainError::Conflict(format!(
            "package {} is {:?}, not ready",
            stored.packages[package_index].id, stored.packages[package_index].state
        ))
        .into());
    }
    let package_key = stored.packages[package_index].id.to_string();
    let has_ready: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM ready_queue WHERE work_package_id = ?1)",
            params![package_key],
            |row| row.get(0),
        )
        .map_err(store)?;
    if !has_ready {
        return Err(
            DomainError::Conflict(format!("package {package_key} has no ready row")).into(),
        );
    }
    let holder: Option<String> = tx
        .query_row(
            "SELECT attempt_id FROM active_leases WHERE variant_id = ?1",
            params![req.variant_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(store)?;
    if let Some(holder) = holder {
        return Err(DomainError::Fence(format!(
            "variant {} already leased to {holder}",
            req.variant_id
        ))
        .into());
    }

    tx.execute(
        "INSERT INTO variant_fence_counters (variant_id, next_fence) VALUES (?1, 1)
         ON CONFLICT(variant_id) DO UPDATE SET next_fence = next_fence + 1",
        params![req.variant_id.to_string()],
    )
    .map_err(store)?;
    step(fail_after)?;
    let fence_raw: i64 = tx
        .query_row(
            "SELECT next_fence FROM variant_fence_counters WHERE variant_id = ?1",
            params![req.variant_id.to_string()],
            |row| row.get(0),
        )
        .map_err(store)?;
    let fence = u64::try_from(fence_raw).map_err(store)?;
    let attempt = Attempt {
        id: AttemptId::from_seed(&req.attempt_seed),
        variant_id: req.variant_id.clone(),
        work_package_id: stored.packages[package_index].id.clone(),
        fence,
        runner_id: req.runner_id.clone(),
        runner_epoch: req.runner_epoch,
        workspace_id: req.workspace_id.clone(),
        workspace_nonce: req.workspace_nonce,
        scope_revision: req.scope_revision,
        context_revision: req.context_revision,
        state: AttemptState::Starting,
    };
    if graph::get_attempt(tx, &attempt.id)?.is_some() {
        return Err(DomainError::Conflict(format!("attempt {} already exists", attempt.id)).into());
    }
    graph::insert_attempt(tx, &attempt)?;
    step(fail_after)?;

    tx.execute(
        "INSERT INTO active_leases (variant_id, attempt_id, fence, runner_id, runner_epoch,
                                    workspace_nonce, heartbeat_at, expires_at, ttl_seconds)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            req.variant_id.to_string(),
            attempt.id.to_string(),
            fence_raw,
            req.runner_id.to_string(),
            i64::try_from(req.runner_epoch).map_err(store)?,
            req.workspace_nonce.to_vec(),
            now,
            expires_at,
            ttl_seconds,
        ],
    )
    .map_err(store)?;
    step(fail_after)?;
    tx.execute(
        "DELETE FROM ready_queue WHERE work_package_id = ?1",
        params![package_key],
    )
    .map_err(store)?;
    step(fail_after)?;

    let mut next_graph = stored;
    next_graph.packages[package_index].state = next_graph.packages[package_index]
        .state
        .transition(WorkPackageState::Leased)?;
    next_graph.variants[variant_index].fence_counter = fence;
    graph::put_graph(tx, &next_graph)?;
    step(fail_after)?;

    let lease = ActiveLease {
        variant_id: req.variant_id.clone(),
        attempt_id: attempt.id.clone(),
        fence,
        runner_id: req.runner_id.clone(),
        runner_epoch: req.runner_epoch,
        workspace_nonce: req.workspace_nonce,
        heartbeat_at: now,
        expires_at,
        ttl_seconds,
    };
    let grant = LeaseGrant { attempt, lease };
    let grant_json = json(&grant)?;
    let token_hash = Digest::of(grant_json.as_bytes()).to_hex();
    events::insert_event(
        tx,
        "attempt_leased",
        &grant_json,
        Some(&req.variant_id.to_string()),
        Some(&req.idempotency_key),
        Some(&token_hash),
    )?;
    step(fail_after)?;

    let command = CommandRecord {
        id: command_request.id(),
        idempotency_key: command_request.idempotency_key.clone(),
        kind: command_request.kind.clone(),
        payload: command_request.payload.clone(),
        payload_digest: command_request.digest(),
        phase: CommandPhase::Applied,
        response: Some(grant_json.clone()),
    };
    commands::insert_command(tx, &command)?;
    step(fail_after)?;
    outbox::enqueue(tx, Some(&command.id), "dispatch_attempt", &grant_json)?;
    step(fail_after)?;
    Ok(grant)
}
