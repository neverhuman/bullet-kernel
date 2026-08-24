//! Single-transaction lease acquisition (spec section 26.3), six-column
//! heartbeat (26.4), expiry reclaim, release, and the push-maintained ready
//! queue (26.5).

use super::{commands, events, from_json, graph, json, store};
use bullet_application::{
    ActiveLease, CommandRecord, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest,
    LedgerError, ReadyRow, ReleaseRequest,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, CommandId, CommandPhase, Digest, DomainError, RunnerId,
    VariantId, WorkPackageId, WorkPackageState,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub(super) fn acquire_lease(
    conn: &mut Connection,
    req: &LeaseRequest,
) -> Result<LeaseGrant, LedgerError> {
    let stable = req.stable_payload()?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    // 1. Idempotent replay.
    if let Some(existing) = commands::get_command(&tx, &req.idempotency_key)? {
        if existing.payload != stable {
            return Err(DomainError::Idempotency(req.idempotency_key.clone()).into());
        }
        let response = existing
            .response
            .ok_or_else(|| LedgerError::Store("lease command has no stored result".into()))?;
        return from_json(&response);
    }
    // 2. Load the graph; find variant and package.
    let stored = graph::get_graph(&tx, &req.mission_id)?
        .ok_or_else(|| LedgerError::Store("graph missing".into()))?;
    let vidx = stored
        .variants
        .iter()
        .position(|variant| variant.id == req.variant_id)
        .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
    let pidx = stored
        .packages
        .iter()
        .position(|package| package.id == stored.variants[vidx].work_package_id)
        .ok_or_else(|| LedgerError::Store("package missing".into()))?;
    // 3. Require READY with a live ready row.
    if stored.packages[pidx].state != WorkPackageState::Ready {
        return Err(DomainError::Conflict(format!(
            "package {} is {:?}, not ready",
            stored.packages[pidx].id, stored.packages[pidx].state
        ))
        .into());
    }
    let package_key = stored.packages[pidx].id.to_string();
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
    // 4. Require no active lease.
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
    // 5. Increment the permanent fence.
    tx.execute(
        "INSERT INTO variant_fence_counters (variant_id, next_fence) VALUES (?1, 1)
         ON CONFLICT(variant_id) DO UPDATE SET next_fence = next_fence + 1",
        params![req.variant_id.to_string()],
    )
    .map_err(store)?;
    let fence_raw: i64 = tx
        .query_row(
            "SELECT next_fence FROM variant_fence_counters WHERE variant_id = ?1",
            params![req.variant_id.to_string()],
            |row| row.get(0),
        )
        .map_err(store)?;
    let fence = u64::try_from(fence_raw).map_err(store)?;
    // 6. Insert the attempt (STARTING). UNIQUE(variant_id, fence) enforced.
    let attempt = Attempt {
        id: AttemptId::from_seed(&req.attempt_seed),
        variant_id: req.variant_id.clone(),
        work_package_id: stored.packages[pidx].id.clone(),
        fence,
        runner_id: req.runner_id.clone(),
        runner_epoch: req.runner_epoch,
        workspace_id: req.workspace_id.clone(),
        workspace_nonce: req.workspace_nonce,
        scope_revision: req.scope_revision,
        context_revision: req.context_revision,
        state: AttemptState::Starting,
    };
    if graph::get_attempt(&tx, &attempt.id)?.is_some() {
        return Err(DomainError::Conflict(format!("attempt {} already exists", attempt.id)).into());
    }
    graph::insert_attempt(&tx, &attempt)?;
    // 7. Insert the lease.
    tx.execute(
        "INSERT INTO active_leases (variant_id, attempt_id, fence, runner_id, runner_epoch,
                                    workspace_nonce, heartbeat_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            req.variant_id.to_string(),
            attempt.id.to_string(),
            fence_raw,
            req.runner_id.to_string(),
            i64::try_from(req.runner_epoch).map_err(store)?,
            req.workspace_nonce.to_vec(),
            req.now,
            req.expires_at,
        ],
    )
    .map_err(store)?;
    // 8. Remove the ready row.
    tx.execute(
        "DELETE FROM ready_queue WHERE work_package_id = ?1",
        params![package_key],
    )
    .map_err(store)?;
    // 9. Mirror the grant into the graph snapshot.
    let mut next_graph = stored;
    next_graph.packages[pidx].state = next_graph.packages[pidx]
        .state
        .transition(WorkPackageState::Leased)?;
    next_graph.variants[vidx].fence_counter = fence;
    graph::put_graph(&tx, &next_graph)?;
    // 10-12. Event, outbox dispatch, stored command result.
    let lease = ActiveLease {
        variant_id: req.variant_id.clone(),
        attempt_id: attempt.id.clone(),
        fence,
        runner_id: req.runner_id.clone(),
        runner_epoch: req.runner_epoch,
        workspace_nonce: req.workspace_nonce,
        heartbeat_at: req.now.clone(),
        expires_at: req.expires_at.clone(),
    };
    let grant = LeaseGrant { attempt, lease };
    let grant_json = json(&grant)?;
    let token_hash = Digest::of(grant_json.as_bytes()).to_hex();
    events::insert_event(
        &tx,
        "attempt_leased",
        &grant_json,
        Some(&req.variant_id.to_string()),
        Some(&req.idempotency_key),
        Some(&token_hash),
    )?;
    super::outbox::enqueue(&tx, "dispatch_attempt", &grant_json)?;
    commands::insert_command(
        &tx,
        &CommandRecord {
            id: CommandId::from_seed(&req.idempotency_key),
            idempotency_key: req.idempotency_key.clone(),
            kind: "acquire_lease".into(),
            payload: stable.clone(),
            payload_digest: Digest::of(stable.as_bytes()),
            phase: CommandPhase::Applied,
            response: Some(grant_json),
        },
    )?;
    tx.commit().map_err(store)?;
    Ok(grant)
}

pub(super) fn heartbeat(conn: &Connection, req: &HeartbeatRequest) -> Result<(), LedgerError> {
    let changed = conn
        .execute(
            "UPDATE active_leases SET heartbeat_at = ?1, expires_at = ?2
             WHERE variant_id = ?3 AND attempt_id = ?4 AND fence = ?5
               AND runner_id = ?6 AND runner_epoch = ?7 AND workspace_nonce = ?8
               AND expires_at > ?1",
            params![
                req.now,
                req.expires_at,
                req.variant_id.to_string(),
                req.attempt_id.to_string(),
                i64::try_from(req.fence).map_err(store)?,
                req.runner_id.to_string(),
                i64::try_from(req.runner_epoch).map_err(store)?,
                req.workspace_nonce.to_vec(),
            ],
        )
        .map_err(store)?;
    if changed == 0 {
        return Err(DomainError::StaleAuthority(format!(
            "heartbeat matched zero lease rows for {}",
            req.attempt_id
        ))
        .into());
    }
    Ok(())
}

type LeaseRow = (String, String, i64, String, i64, Vec<u8>, String, String);

fn read_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<LeaseRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn lease_from(row: LeaseRow) -> Result<ActiveLease, LedgerError> {
    let (variant, attempt, fence, runner, epoch, nonce, heartbeat_at, expires_at) = row;
    Ok(ActiveLease {
        variant_id: VariantId::parse(&variant)?,
        attempt_id: AttemptId::parse(&attempt)?,
        fence: u64::try_from(fence).map_err(store)?,
        runner_id: RunnerId::parse(&runner)?,
        runner_epoch: u64::try_from(epoch).map_err(store)?,
        workspace_nonce: graph::nonce_from(nonce)?,
        heartbeat_at,
        expires_at,
    })
}

const LEASE_COLUMNS: &str = "variant_id, attempt_id, fence, runner_id, runner_epoch, \
                             workspace_nonce, heartbeat_at, expires_at";

pub(super) fn get_lease(
    conn: &Connection,
    variant: &VariantId,
) -> Result<Option<ActiveLease>, LedgerError> {
    let row = conn
        .query_row(
            &format!("SELECT {LEASE_COLUMNS} FROM active_leases WHERE variant_id = ?1"),
            params![variant.to_string()],
            read_lease,
        )
        .optional()
        .map_err(store)?;
    row.map(lease_from).transpose()
}

pub(super) fn expire_leases(
    conn: &mut Connection,
    now: &str,
) -> Result<Vec<ExpiredLease>, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let expired = {
        let mut stmt = tx
            .prepare(&format!(
                "SELECT {LEASE_COLUMNS} FROM active_leases WHERE expires_at <= ?1 ORDER BY variant_id"
            ))
            .map_err(store)?;
        let rows = stmt.query_map(params![now], read_lease).map_err(store)?;
        let mut leases = Vec::new();
        for row in rows {
            leases.push(lease_from(row.map_err(store)?)?);
        }
        leases
    };
    let mut out = Vec::new();
    for lease in expired {
        let attempt = graph::get_attempt(&tx, &lease.attempt_id)?
            .ok_or_else(|| LedgerError::Store("lease without attempt".into()))?;
        let next_state = if attempt.state.may_mutate() {
            attempt.state.transition(AttemptState::Crashed)?
        } else {
            attempt.state
        };
        tx.execute(
            "UPDATE attempts SET state = ?2 WHERE id = ?1",
            params![attempt.id.to_string(), next_state.as_str()],
        )
        .map_err(store)?;
        tx.execute(
            "DELETE FROM active_leases WHERE variant_id = ?1",
            params![lease.variant_id.to_string()],
        )
        .map_err(store)?;
        graph::requeue_package(&tx, &attempt.work_package_id, now)?;
        events::insert_event(
            &tx,
            "lease_expired",
            lease.attempt_id.as_str(),
            Some(&lease.variant_id.to_string()),
            None,
            None,
        )?;
        out.push(ExpiredLease {
            variant_id: lease.variant_id.clone(),
            attempt_id: lease.attempt_id.clone(),
            work_package_id: attempt.work_package_id.clone(),
            fence: lease.fence,
        });
    }
    tx.commit().map_err(store)?;
    Ok(out)
}

pub(super) fn release_lease(
    conn: &mut Connection,
    req: &ReleaseRequest,
) -> Result<(), LedgerError> {
    if req.final_state.may_mutate() {
        return Err(DomainError::InvalidTransition {
            from: "release".into(),
            to: format!("{:?}", req.final_state),
        }
        .into());
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let holder = get_lease(&tx, &req.variant_id)?;
    match holder {
        Some(lease) if lease.attempt_id == req.attempt_id => {
            let attempt = graph::get_attempt(&tx, &req.attempt_id)?
                .ok_or_else(|| LedgerError::Store("lease without attempt".into()))?;
            let next_state = attempt.state.transition(req.final_state)?;
            tx.execute(
                "UPDATE attempts SET state = ?2 WHERE id = ?1",
                params![attempt.id.to_string(), next_state.as_str()],
            )
            .map_err(store)?;
            tx.execute(
                "DELETE FROM active_leases WHERE variant_id = ?1",
                params![req.variant_id.to_string()],
            )
            .map_err(store)?;
            if req.requeue {
                graph::requeue_package(&tx, &attempt.work_package_id, &req.now)?;
            }
            events::insert_event(
                &tx,
                "lease_released",
                req.attempt_id.as_str(),
                Some(&req.variant_id.to_string()),
                None,
                None,
            )?;
            tx.commit().map_err(store)
        }
        Some(lease) => Err(DomainError::StaleAuthority(format!(
            "lease held by {}, not {}",
            lease.attempt_id, req.attempt_id
        ))
        .into()),
        None => match graph::get_attempt(&tx, &req.attempt_id)? {
            Some(attempt) if attempt.state == req.final_state => Ok(()),
            _ => Err(DomainError::StaleAuthority(format!(
                "no active lease for {}",
                req.attempt_id
            ))
            .into()),
        },
    }
}

pub(super) fn ready_rows(conn: &Connection) -> Result<Vec<ReadyRow>, LedgerError> {
    let mut stmt = conn
        .prepare("SELECT work_package_id, enqueued_at FROM ready_queue ORDER BY work_package_id")
        .map_err(store)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        let (package, enqueued_at) = row.map_err(store)?;
        out.push(ReadyRow {
            work_package_id: WorkPackageId::parse(&package)?,
            enqueued_at,
        });
    }
    Ok(out)
}

pub(super) fn enqueue_ready(
    conn: &Connection,
    package: &WorkPackageId,
    now: &str,
) -> Result<(), LedgerError> {
    conn.execute(
        "INSERT INTO ready_queue (work_package_id, enqueued_at) VALUES (?1, ?2)
         ON CONFLICT(work_package_id) DO NOTHING",
        params![package.to_string(), now],
    )
    .map_err(store)?;
    Ok(())
}
