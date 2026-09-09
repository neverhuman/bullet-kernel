//! Idempotent command rows.

use super::{authority, events, nonces, outbox, store};
use bullet_application::commands::COMMAND_RECONCILED_EVENT;
use bullet_application::{
    plan_run_coding_admission, CodingAdmissionView, CommandRecord, CommandRequest, LedgerError,
    RunCodingPayload, RUN_CODING_KIND,
};
use bullet_domain::{CommandId, CommandPhase, Digest, DomainError};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

const DISPATCH_KIND: &str = "command_dispatch";

type CommandRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CommandRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn decode(row: CommandRow) -> Result<CommandRecord, LedgerError> {
    let (key, id, kind, payload, digest, phase, response) = row;
    let record = (|| -> Result<CommandRecord, DomainError> {
        Ok(CommandRecord {
            id: CommandId::parse(&id)?,
            idempotency_key: key,
            kind,
            payload,
            payload_digest: Digest::from_hex(&digest)?,
            phase: CommandPhase::parse(&phase)?,
            response,
        })
    })()
    .map_err(|error| store(format!("invalid persisted command: {error}")))?;
    record
        .validate()
        .map_err(|error| store(format!("invalid persisted command: {error}")))?;
    Ok(record)
}

pub(super) fn get_command(
    conn: &Connection,
    key: &str,
) -> Result<Option<CommandRecord>, LedgerError> {
    let row = conn
        .query_row(
            "SELECT idempotency_key, id, kind, payload, payload_digest, phase, response_json
             FROM commands WHERE idempotency_key = ?1",
            params![key],
            read_row,
        )
        .optional()
        .map_err(store)?;
    row.map(decode).transpose()
}

pub(super) fn get_command_by_id(
    conn: &Connection,
    id: &CommandId,
) -> Result<Option<CommandRecord>, LedgerError> {
    let row = conn
        .query_row(
            "SELECT idempotency_key, id, kind, payload, payload_digest, phase, response_json
             FROM commands WHERE id = ?1",
            params![id.to_string()],
            read_row,
        )
        .optional()
        .map_err(store)?;
    row.map(decode).transpose()
}

pub(super) fn insert_command(conn: &Connection, record: &CommandRecord) -> Result<(), LedgerError> {
    record.validate()?;
    conn.execute(
        "INSERT INTO commands
           (idempotency_key, id, kind, payload, payload_digest, phase, response_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            record.idempotency_key,
            record.id.to_string(),
            record.kind,
            record.payload,
            record.payload_digest.to_hex(),
            record.phase.as_str(),
            record.response,
        ],
    )
    .map_err(store)?;
    Ok(())
}

pub(super) fn record_command(
    conn: &Connection,
    request: &CommandRequest,
) -> Result<CommandRecord, LedgerError> {
    request.validate()?;
    if let Some(existing) = get_command(conn, &request.idempotency_key)? {
        request.matches(&existing)?;
        return Ok(existing);
    }
    let record = CommandRecord {
        id: request.id(),
        idempotency_key: request.idempotency_key.clone(),
        kind: request.kind.clone(),
        payload: request.payload.clone(),
        payload_digest: request.digest(),
        phase: CommandPhase::Pending,
        response: None,
    };
    insert_command(conn, &record)?;
    Ok(record)
}

pub(super) fn submit_command(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    request: &CommandRequest,
) -> Result<CommandRecord, LedgerError> {
    request.validate()?;
    let transaction = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(store)?;
    let existed = get_command(&transaction, &request.idempotency_key)?.is_some();
    let record = record_command(&transaction, request)?;
    fail_boundary(fail_after)?;
    let dispatch = serde_json::to_string(request).map_err(store)?;
    if existed {
        let rows = outbox::for_command(&transaction, &record.id)?;
        if rows.len() != 1 || rows[0].kind != DISPATCH_KIND || rows[0].payload != dispatch {
            return Err(LedgerError::Store(
                "public command has incomplete or conflicting outbox truth".into(),
            ));
        }
        let events: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE kind = 'command_submitted' AND body = ?1 AND correlation_id = ?1",
                params![record.id.as_str()],
                |row| row.get(0),
            )
            .map_err(store)?;
        if events != 1 {
            return Err(LedgerError::Store(
                "public command has incomplete or conflicting event truth".into(),
            ));
        }
    } else {
        outbox::enqueue(&transaction, Some(&record.id), DISPATCH_KIND, &dispatch)?;
        fail_boundary(fail_after)?;
        events::insert_event(
            &transaction,
            "command_submitted",
            record.id.as_str(),
            Some(record.id.as_str()),
            Some(record.id.as_str()),
            None,
        )?;
    }
    fail_boundary(fail_after)?;
    admit_run_coding(&transaction, request, existed)?;
    fail_boundary(fail_after)?;
    transaction.commit().map_err(store)?;
    Ok(record)
}

fn admit_run_coding(
    tx: &Transaction<'_>,
    request: &CommandRequest,
    existed: bool,
) -> Result<(), LedgerError> {
    if request.kind != RUN_CODING_KIND {
        return Ok(());
    }
    let payload = RunCodingPayload::parse(&request.payload)?;
    let authority = authority::current(tx)?;
    let used: i64 = tx
        .query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM budget_reservations",
            [],
            |row| row.get(0),
        )
        .map_err(store)?;
    let existing = tx
        .query_row(
            "SELECT reservation_id, amount FROM budget_reservations WHERE reservation_id = ?1",
            params![payload.quota_reservation],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(store)?;
    let existing_reservation = match existing {
        Some((id, amount)) => Some((
            id,
            u64::try_from(amount).map_err(|error| store(error.to_string()))?,
        )),
        None => None,
    };
    let mut nonce = nonces::inspect(tx, &payload.launch_nonce).map_err(nonce_store)?;
    if nonce.is_none() && !existed {
        let digest = request.digest().to_hex();
        nonces::issue_in(tx, &payload.launch_nonce, &digest).map_err(nonce_store)?;
        nonce = nonces::inspect(tx, &payload.launch_nonce).map_err(nonce_store)?;
    }
    let view = CodingAdmissionView {
        authority_epoch: authority.authority_epoch(),
        used_quota: u64::try_from(used).map_err(|error| store(error.to_string()))?,
        existing_reservation,
        nonce,
    };
    let Some(plan) = plan_run_coding_admission(request, existed, &view)? else {
        return Ok(());
    };
    nonces::consume_in(tx, &plan.consume_nonce, &request.digest().to_hex()).map_err(nonce_store)?;
    tx.execute(
        "INSERT INTO budget_reservations (reservation_id, amount, settled_amount, unknown_liability)
         VALUES (?1, ?2, NULL, 0)",
        params![
            plan.reservation.0,
            i64::try_from(plan.reservation.1).map_err(|error| store(error.to_string()))?
        ],
    )
    .map_err(store)?;
    Ok(())
}

fn nonce_store(error: bullet_application::NonceError) -> LedgerError {
    LedgerError::Store(error.to_string())
}

pub(super) fn reconcile_offline_command(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    id: &CommandId,
    now: &str,
) -> Result<CommandRecord, LedgerError> {
    let transaction = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(store)?;
    let record = get_command_by_id(&transaction, id)?
        .ok_or_else(|| LedgerError::Store(format!("unknown command {id}")))?;
    let request =
        CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)?;
    request.matches(&record)?;
    let dispatch = serde_json::to_string(&request).map_err(store)?;
    let rows = outbox::for_command(&transaction, id)?;
    if rows.len() != 1 || rows[0].kind != DISPATCH_KIND || rows[0].payload != dispatch {
        return Err(LedgerError::Store(
            "command has incomplete or conflicting dispatch truth".into(),
        ));
    }
    let submitted = event_count(&transaction, "command_submitted", id, Some(id.as_str()))?;
    if submitted != 1 {
        return Err(LedgerError::Store(
            "command has incomplete or conflicting submitted audit truth".into(),
        ));
    }
    let resolution = request.offline_worker_resolution()?;
    let expected = resolution.resolved_record(record.clone())?;
    let reconciled = event_count(&transaction, COMMAND_RECONCILED_EVENT, id, None)?;
    let exact_reconciled = event_count(
        &transaction,
        COMMAND_RECONCILED_EVENT,
        id,
        Some(resolution.response()),
    )?;
    let row = &rows[0];
    if record.phase != CommandPhase::Pending {
        if record != expected
            || row.phase != resolution.phase()
            || row.delivered_at.is_some()
            || row.acked_at.is_none()
            || reconciled != 1
            || exact_reconciled != 1
        {
            return Err(LedgerError::Store(
                "command has conflicting reconciled truth".into(),
            ));
        }
        transaction.commit().map_err(store)?;
        return Ok(record);
    }
    if row.phase != CommandPhase::Pending
        || row.delivered_at.is_some()
        || row.acked_at.is_some()
        || reconciled != 0
    {
        return Err(LedgerError::Store(
            "pending command has conflicting worker truth".into(),
        ));
    }
    let changed = transaction
        .execute(
            "UPDATE commands SET phase = ?1, response_json = ?2
             WHERE id = ?3 AND phase = 'pending' AND response_json IS NULL",
            params![
                resolution.phase().as_str(),
                resolution.response(),
                id.as_str()
            ],
        )
        .map_err(store)?;
    if changed != 1 {
        return Err(LedgerError::Store(
            "command changed during reconciliation".into(),
        ));
    }
    reconcile_fail_boundary(fail_after)?;
    let changed = transaction
        .execute(
            "UPDATE outbox SET phase = ?1, acked_at = ?2
             WHERE seq = ?3 AND command_id = ?4 AND phase = 'pending'
               AND delivered_at IS NULL AND acked_at IS NULL",
            params![
                resolution.phase().as_str(),
                now,
                i64::try_from(row.seq).map_err(store)?,
                id.as_str()
            ],
        )
        .map_err(store)?;
    if changed != 1 {
        return Err(LedgerError::Store(
            "command outbox changed during reconciliation".into(),
        ));
    }
    reconcile_fail_boundary(fail_after)?;
    events::insert_event(
        &transaction,
        COMMAND_RECONCILED_EVENT,
        resolution.response(),
        Some(id.as_str()),
        Some(id.as_str()),
        None,
    )?;
    reconcile_fail_boundary(fail_after)?;
    reconcile_fail_boundary(fail_after)?;
    transaction.commit().map_err(store)?;
    Ok(expected)
}

fn event_count(
    conn: &Connection,
    kind: &str,
    id: &CommandId,
    body: Option<&str>,
) -> Result<i64, LedgerError> {
    match body {
        Some(body) => conn
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE kind = ?1 AND correlation_id = ?2 AND body = ?3",
                params![kind, id.as_str(), body],
                |row| row.get(0),
            )
            .map_err(store),
        None => conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = ?1 AND correlation_id = ?2",
                params![kind, id.as_str()],
                |row| row.get(0),
            )
            .map_err(store),
    }
}

fn reconcile_fail_boundary(fail_after: &mut Option<u8>) -> Result<(), LedgerError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(LedgerError::Store(
                "injected command reconciliation boundary".into(),
            ))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

fn fail_boundary(fail_after: &mut Option<u8>) -> Result<(), LedgerError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(LedgerError::Store(
                "injected command ingress boundary".into(),
            ))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

pub(super) fn set_phase(
    conn: &Connection,
    key: &str,
    phase: CommandPhase,
    response: Option<&str>,
) -> Result<(), LedgerError> {
    let mut record = get_command(conn, key)?
        .ok_or_else(|| LedgerError::Store(format!("unknown command key {key}")))?;
    record.phase = phase;
    if let Some(response) = response {
        record.response = Some(response.to_string());
    }
    record.validate()?;
    let changed = if let Some(response) = response {
        conn.execute(
            "UPDATE commands SET phase = ?1, response_json = ?2 WHERE idempotency_key = ?3",
            params![phase.as_str(), response, key],
        )
        .map_err(store)?
    } else {
        conn.execute(
            "UPDATE commands SET phase = ?1 WHERE idempotency_key = ?2",
            params![phase.as_str(), key],
        )
        .map_err(store)?
    };
    if changed == 0 {
        return Err(LedgerError::Store(format!("unknown command key {key}")));
    }
    Ok(())
}
