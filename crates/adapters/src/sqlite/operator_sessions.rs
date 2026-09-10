//! Digest-only operator authority; every check reads current durable state.

use super::{store, SqliteLedger};
use bullet_application::operator_sessions::{
    BootstrapRegistration, OperatorSession, OperatorSessionError as AuthError,
    OperatorSessionStore, SessionIssue, SessionRevocation,
};
use bullet_domain::Digest;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

type Result<T> = std::result::Result<T, AuthError>;

fn valid_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(super::migrations::valid_digest)
}

fn valid_origin(origin: &str) -> bool {
    origin
        .strip_prefix("http://")
        .and_then(|authority| authority.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|address| address.ip().is_loopback())
}

fn clock(conn: &Connection) -> Result<i64> {
    let now = conn
        .query_row("SELECT unixepoch()", [], |row| row.get::<_, i64>(0))
        .map_err(store)?;
    if !(0..=253_402_300_799).contains(&now) {
        return Err(store("operator auth clock is outside admitted range").into());
    }
    Ok(now)
}

fn epoch(conn: &Connection) -> Result<i64> {
    let (epoch, pending): (i64, i64) = conn
        .query_row(
            "SELECT restore_epoch, pending_admission FROM restore_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(store)?;
    if epoch < 0 || pending != 0 {
        return Err(store("RESTORE_ADMISSION_REQUIRED").into());
    }
    Ok(epoch)
}

fn read(conn: &Connection, bearer: Digest, origin: &str) -> Result<OperatorSession> {
    let now = clock(conn)?;
    let current_epoch = epoch(conn)?;
    let row = conn.query_row(
        "SELECT session_id, operator_id, csrf_digest, issued_at, expires_at
         FROM operator_sessions AS session
         WHERE bearer_digest = ?1 AND origin = ?2 AND restore_epoch = ?3
           AND issued_at <= ?4 AND expires_at > ?4
           AND NOT EXISTS (SELECT 1 FROM operator_session_revocations AS revoked WHERE revoked.session_id = session.session_id)",
        params![bearer.to_hex(), origin, current_epoch, now],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?)),
    ).optional().map_err(store)?.ok_or(AuthError::SessionInvalid)?;
    if !valid_id(&row.0, "sid_")
        || !valid_id(&row.1, "opr_")
        || !super::migrations::valid_digest(&row.2)
        || row.3 < 0
        || row.4 > 253_402_300_799
        || !row
            .4
            .checked_sub(row.3)
            .is_some_and(|seconds| (1..=28_800).contains(&seconds))
    {
        return Err(store("corrupt operator session row").into());
    }
    Ok(OperatorSession {
        session_id: row.0,
        operator_id: row.1,
        bearer_digest: bearer,
        csrf_digest: Digest::from_hex(&row.2).map_err(store)?,
        issued_at: row.3,
        expires_at: row.4,
    })
}

impl OperatorSessionStore for SqliteLedger {
    fn register_operator_bootstrap(&mut self, request: &BootstrapRegistration) -> Result<()> {
        if !valid_id(&request.proposed_operator_id, "opr_")
            || !valid_origin(&request.origin)
            || !(1..=600).contains(&request.lifetime_seconds)
        {
            return Err(AuthError::InvalidRequest);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store)?;
        let now = clock(&tx)?;
        let current_epoch = epoch(&tx)?;
        let existing: Option<(String, i64)> = tx
            .query_row(
                "SELECT origin, restore_epoch FROM operator_bootstraps WHERE digest = ?1",
                [request.digest.to_hex()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(store)?;
        if let Some((origin, restore_epoch)) = existing {
            if origin != request.origin || restore_epoch != current_epoch {
                return Err(AuthError::BootstrapInvalid);
            }
            tx.commit().map_err(store)?;
            return Ok(());
        }
        let operator: Option<String> = tx
            .query_row(
                "SELECT operator_id FROM local_operator WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(store)?;
        let operator = match operator {
            Some(operator) => operator,
            None => {
                tx.execute("INSERT INTO local_operator (singleton, operator_id, created_at) VALUES (1, ?1, ?2)",
                    params![request.proposed_operator_id, now]).map_err(store)?;
                request.proposed_operator_id.clone()
            }
        };
        if !valid_id(&operator, "opr_") {
            return Err(store("corrupt local operator identity").into());
        }
        tx.execute("INSERT INTO operator_bootstraps (digest, operator_id, origin, issued_at, expires_at, restore_epoch)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![request.digest.to_hex(), operator, request.origin, now, now + i64::from(request.lifetime_seconds), current_epoch]).map_err(store)?;
        tx.commit().map_err(store)?;
        Ok(())
    }

    fn exchange_operator_bootstrap(&mut self, request: &SessionIssue) -> Result<OperatorSession> {
        if !valid_id(&request.session_id, "sid_")
            || !valid_origin(&request.origin)
            || !(1..=28_800).contains(&request.lifetime_seconds)
        {
            return Err(AuthError::InvalidRequest);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store)?;
        let now = clock(&tx)?;
        let current_epoch = epoch(&tx)?;
        let bootstrap: Option<(String, i64, i64)> = tx.query_row(
            "SELECT operator_id, issued_at, expires_at FROM operator_bootstraps WHERE digest = ?1 AND origin = ?2 AND restore_epoch = ?3",
            params![request.bootstrap_digest.to_hex(), request.origin, current_epoch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(store)?;
        let (operator, issued, expires) = bootstrap.ok_or(AuthError::BootstrapInvalid)?;
        if !valid_id(&operator, "opr_")
            || issued < 0
            || expires > 253_402_300_799
            || !expires
                .checked_sub(issued)
                .is_some_and(|seconds| (1..=600).contains(&seconds))
        {
            return Err(store("corrupt operator bootstrap row").into());
        }
        let consumed: bool = tx
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM operator_sessions WHERE bootstrap_digest = ?1)",
                [request.bootstrap_digest.to_hex()],
                |row| row.get(0),
            )
            .map_err(store)?;
        if consumed {
            return Err(AuthError::BootstrapConsumed);
        }
        if now >= expires {
            return Err(AuthError::BootstrapExpired);
        }
        if now < issued {
            return Err(AuthError::BootstrapInvalid);
        }
        tx.execute("INSERT INTO operator_sessions (session_id, bootstrap_digest, operator_id, origin, restore_epoch,
                    bearer_digest, csrf_digest, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![request.session_id, request.bootstrap_digest.to_hex(), operator, request.origin, current_epoch,
                request.bearer_digest.to_hex(), request.csrf_digest.to_hex(), now, now + i64::from(request.lifetime_seconds)]).map_err(store)?;
        let session = read(&tx, request.bearer_digest, &request.origin)?;
        tx.commit().map_err(store)?;
        Ok(session)
    }

    fn read_operator_session(&self, bearer: Digest, origin: &str) -> Result<OperatorSession> {
        // One read transaction binds expiry/restore/revocation to the same view.
        let tx = super::ReadTransaction::begin(&self.conn)?;
        let session = read(&self.conn, bearer, origin)?;
        tx.commit()?;
        Ok(session)
    }

    fn revoke_operator_session(
        &mut self,
        bearer: Digest,
        csrf: Digest,
        origin: &str,
    ) -> Result<SessionRevocation> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store)?;
        let session = read(&tx, bearer, origin)?;
        let mismatch = session
            .csrf_digest
            .as_bytes()
            .iter()
            .zip(csrf.as_bytes())
            .fold(0_u8, |bits, (expected, observed)| {
                bits | (expected ^ observed)
            });
        if mismatch != 0 {
            return Err(AuthError::CsrfInvalid);
        }
        let revoked_at = clock(&tx)?;
        tx.execute("INSERT INTO operator_session_revocations (session_id, operator_id, revoked_at) VALUES (?1, ?2, ?3)",
            params![session.session_id, session.operator_id, revoked_at]).map_err(store)?;
        tx.commit().map_err(store)?;
        Ok(SessionRevocation {
            session_id: session.session_id,
            operator_id: session.operator_id,
            revoked_at,
        })
    }
}

#[cfg(test)]
mod tests;
