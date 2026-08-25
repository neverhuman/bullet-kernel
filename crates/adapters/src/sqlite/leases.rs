//! Six-column heartbeat (spec section 26.4), expiry reclaim, release, and the
//! push-maintained ready queue (26.5).

mod acquire;

pub(super) use acquire::{acquire_lease, acquire_on};

use super::{events, graph, json, lease_time, outbox, store};
use bullet_application::{
    check_active_lease_snapshot, ActiveLease, ActiveLeaseSubject, ExpiredLease, HeartbeatRequest,
    LedgerError, ReadyRow, ReleaseRequest,
};
use bullet_domain::{AttemptId, AttemptState, DomainError, RunnerId, VariantId, WorkPackageId};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

pub(super) fn heartbeat(conn: &mut Connection, req: &HeartbeatRequest) -> Result<(), LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    heartbeat_on(&tx, req)?;
    tx.commit().map_err(store)
}

pub(in crate::sqlite) fn heartbeat_on(
    tx: &Transaction<'_>,
    req: &HeartbeatRequest,
) -> Result<(), LedgerError> {
    let ttl_seconds = req.validated_ttl()?;
    let (now, expires_at) = lease_time::database_window(tx, ttl_seconds)?;
    let current = get_lease(tx, &req.variant_id)?;
    let live = if let Some(lease) = current.as_ref() {
        let attempt = graph::get_attempt(tx, &lease.attempt_id)?
            .ok_or_else(|| LedgerError::Store("active lease has no Attempt".into()))?;
        attempt.state.permits_lease_heartbeat()
            && lease.attempt_id == req.attempt_id
            && lease.fence == req.fence
            && lease.runner_id == req.runner_id
            && lease.runner_epoch == req.runner_epoch
            && lease.workspace_nonce == req.workspace_nonce
            && lease.ttl_seconds == ttl_seconds
            && lease.heartbeat_at <= now
            && now < lease.expires_at
    } else {
        false
    };
    if !live {
        return Err(DomainError::StaleAuthority(format!(
            "heartbeat matched zero live lease rows for {}",
            req.attempt_id
        ))
        .into());
    }
    let changed = tx
        .execute(
            "UPDATE active_leases SET heartbeat_at = ?1, expires_at = ?2
             WHERE variant_id = ?3 AND attempt_id = ?4 AND fence = ?5
               AND runner_id = ?6 AND runner_epoch = ?7 AND workspace_nonce = ?8
               AND ttl_seconds = ?9 AND heartbeat_at <= ?1 AND ?1 < expires_at",
            params![
                now,
                expires_at,
                req.variant_id.to_string(),
                req.attempt_id.to_string(),
                i64::try_from(req.fence).map_err(store)?,
                req.runner_id.to_string(),
                i64::try_from(req.runner_epoch).map_err(store)?,
                req.workspace_nonce.to_vec(),
                ttl_seconds,
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

pub(super) type LeaseRow = (
    String,
    String,
    i64,
    String,
    i64,
    Vec<u8>,
    String,
    String,
    i64,
);

pub(super) fn read_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<LeaseRow> {
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
    ))
}

pub(super) fn lease_from(row: LeaseRow) -> Result<ActiveLease, LedgerError> {
    let (variant, attempt, fence, runner, epoch, nonce, heartbeat_at, expires_at, ttl_seconds) =
        row;
    if !(1..=bullet_application::records::MAX_LEASE_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(store("active lease has an invalid persisted TTL"));
    }
    lease_time::validate_window(&heartbeat_at, &expires_at, ttl_seconds)?;
    Ok(ActiveLease {
        variant_id: VariantId::parse(&variant)?,
        attempt_id: AttemptId::parse(&attempt)?,
        fence: u64::try_from(fence).map_err(store)?,
        runner_id: RunnerId::parse(&runner)?,
        runner_epoch: u64::try_from(epoch).map_err(store)?,
        workspace_nonce: graph::nonce_from(nonce)?,
        heartbeat_at,
        expires_at,
        ttl_seconds,
    })
}

pub(super) const LEASE_COLUMNS: &str = "variant_id, attempt_id, fence, runner_id, runner_epoch, \
                             workspace_nonce, heartbeat_at, expires_at, ttl_seconds";

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

pub(super) fn check_active_lease(
    conn: &mut Connection,
    subject: &ActiveLeaseSubject,
) -> Result<(), LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    check_active_lease_in(&tx, subject)?;
    tx.commit().map_err(store)
}

/// Reusable inner check for the future mutation-reservation transaction.
pub(super) fn check_active_lease_in(
    conn: &Connection,
    subject: &ActiveLeaseSubject,
) -> Result<(), LedgerError> {
    let now = lease_time::database_time(conn)?;
    let lease = get_lease(conn, &subject.variant_id)?.ok_or_else(|| {
        DomainError::StaleAuthority(format!("no active lease for {}", subject.attempt_id))
    })?;
    let attempt = graph::get_attempt(conn, &lease.attempt_id)?
        .ok_or_else(|| LedgerError::Store("active lease has no Attempt".into()))?;
    check_active_lease_snapshot(&lease, &attempt, subject, &now)
}

/// Outbox kind for one lease reclaimed by expiry. It is a durable delivery
/// record of the reclamation, never a second dispatch: the successor is
/// dispatched by its own `attempt_leased` acquisition.
pub(super) const RECLAIM_OUTBOX_KIND: &str = "lease_reclaimed";

/// Every lease whose expiry has already passed, read inside the caller's
/// transaction against the store's own clock.
fn due_leases(tx: &Connection, now: &str) -> Result<Vec<ActiveLease>, LedgerError> {
    let mut stmt = tx
        .prepare(&format!(
            "SELECT {LEASE_COLUMNS} FROM active_leases ORDER BY variant_id"
        ))
        .map_err(store)?;
    let rows = stmt.query_map([], read_lease).map_err(store)?;
    let mut leases = Vec::new();
    for row in rows {
        let lease = lease_from(row.map_err(store)?)?;
        if lease.expires_at.as_str() <= now {
            leases.push(lease);
        }
    }
    Ok(leases)
}

/// Reclaim one already-expired lease inside the caller's `BEGIN IMMEDIATE`
/// transaction: the dead Attempt moves to its typed terminal `Crashed` state,
/// the lease row is deleted, the work package returns to the ready queue, and
/// the durable event plus outbox row commit with them. `variant_fence_counters`
/// is never touched, so the successor is granted fence N+1 and the dead fence
/// is never reused.
fn reclaim(tx: &Connection, lease: &ActiveLease, now: &str) -> Result<ExpiredLease, LedgerError> {
    let attempt = graph::get_attempt(tx, &lease.attempt_id)?
        .ok_or_else(|| LedgerError::Store("lease without attempt".into()))?;
    if !attempt.state.permits_expiry_reclaim() {
        return Err(LedgerError::Store(format!(
            "active lease Attempt {} cannot expire from {:?}",
            attempt.id, attempt.state
        )));
    }
    let next_state = attempt.state.transition(AttemptState::Crashed)?;
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
    graph::requeue_package(tx, &attempt.work_package_id, now)?;
    events::insert_event(
        tx,
        "lease_expired",
        lease.attempt_id.as_str(),
        Some(&lease.variant_id.to_string()),
        None,
        None,
    )?;
    let expired = ExpiredLease {
        variant_id: lease.variant_id.clone(),
        attempt_id: lease.attempt_id.clone(),
        work_package_id: attempt.work_package_id.clone(),
        fence: lease.fence,
    };
    outbox::enqueue(tx, None, RECLAIM_OUTBOX_KIND, &json(&expired)?)?;
    Ok(expired)
}

/// Reclaim exactly this variant's lease when its expiry has already passed,
/// inside the caller's acquisition transaction. A lease that is still live is
/// never reclaimed; a variant with no lease row is not an error.
pub(in crate::sqlite) fn reclaim_expired_variant(
    tx: &Connection,
    variant: &VariantId,
    now: &str,
) -> Result<Option<ExpiredLease>, LedgerError> {
    let Some(lease) = get_lease(tx, variant)? else {
        return Ok(None);
    };
    if now < lease.expires_at.as_str() {
        return Ok(None);
    }
    reclaim(tx, &lease, now).map(Some)
}

pub(super) fn expire_leases(conn: &mut Connection) -> Result<Vec<ExpiredLease>, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let now = lease_time::database_time(&tx)?;
    let mut out = Vec::new();
    for lease in due_leases(&tx, &now)? {
        out.push(reclaim(&tx, &lease, &now)?);
    }
    tx.commit().map_err(store)?;
    Ok(out)
}

pub(super) fn release_lease(
    conn: &mut Connection,
    req: &ReleaseRequest,
) -> Result<(), LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    release_on(&tx, req)?;
    tx.commit().map_err(store)
}

pub(in crate::sqlite) fn release_on(
    tx: &Transaction<'_>,
    req: &ReleaseRequest,
) -> Result<(), LedgerError> {
    if !req.final_state.is_terminal_release_target() {
        return Err(DomainError::InvalidTransition {
            from: "release".into(),
            to: format!("{:?}", req.final_state),
        }
        .into());
    }
    let now = lease_time::database_time(tx)?;
    let holder = get_lease(tx, &req.variant_id)?;
    match holder {
        Some(lease) if lease.attempt_id == req.attempt_id => {
            let attempt = graph::get_attempt(tx, &req.attempt_id)?
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
                graph::requeue_package(tx, &attempt.work_package_id, &now)?;
            }
            events::insert_event(
                tx,
                "lease_released",
                req.attempt_id.as_str(),
                Some(&req.variant_id.to_string()),
                None,
                None,
            )?;
            Ok(())
        }
        Some(lease) => Err(DomainError::StaleAuthority(format!(
            "lease held by {}, not {}",
            lease.attempt_id, req.attempt_id
        ))
        .into()),
        None => match graph::get_attempt(tx, &req.attempt_id)? {
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
