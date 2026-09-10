//! First admission and immutable replay binding checks have separate purposes.
use super::super::{authority, nonces, store};
use bullet_application::{
    plan_run_coding_admission, CodingAdmissionView, CommandRequest, LedgerError, RunCodingPayload,
    RUN_CODING_KIND,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

pub(in crate::sqlite) fn verify_replay(
    conn: &Connection,
    request: &CommandRequest,
) -> Result<(), LedgerError> {
    if request.kind != RUN_CODING_KIND {
        return Ok(());
    }
    let payload = RunCodingPayload::parse(&request.payload).map_err(store)?;
    let reservation: Option<(String, i64)> = conn
        .query_row(
            "SELECT reservation_id, amount FROM budget_reservations WHERE reservation_id=?1",
            [&payload.quota_reservation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(store)?;
    let reservation = reservation
        .map(|(id, amount)| u64::try_from(amount).map(|amount| (id, amount)))
        .transpose()
        .map_err(store)?;
    let nonce = nonces::inspect(conn, &payload.launch_nonce).map_err(nonce_store)?;
    bullet_application::run_coding::validate_run_coding_replay(request, &reservation, &nonce)
        .map_err(store)
}

pub(super) fn admit_run_coding(
    tx: &Transaction<'_>,
    request: &CommandRequest,
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
    if nonce.is_none() {
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
    let Some(plan) = plan_run_coding_admission(request, false, &view)? else {
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
