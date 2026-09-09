//! Atomic schema-20 admission of one validated generated scope grant.

use super::{authority, events, store, SqliteLedger};
use bullet_application::{
    prepare_authority_scope_admission, AuthorityScopeAdmission, AuthorityScopeError,
    AuthorityScopeStore, PreparedAuthorityScopeAdmission,
};
use bullet_domain::schema_bundle::ScopeGrantV1;
use bullet_domain::CommandId;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

impl SqliteLedger {
    /// Inject a one-shot failure after `allowed` scope-admission write boundaries.
    pub fn set_authority_scope_failpoint(&mut self, allowed: u8) {
        self.authority_scope_fail_after = Some(allowed);
    }
}

impl AuthorityScopeStore for SqliteLedger {
    fn admit_scope_grant(
        &mut self,
        grant: &ScopeGrantV1,
        expected_authority_epoch: u64,
        idempotency_key: &str,
        now: &str,
    ) -> Result<AuthorityScopeAdmission, AuthorityScopeError> {
        let prepared = prepare_authority_scope_admission(
            grant,
            expected_authority_epoch,
            idempotency_key,
            now,
        )?;
        admit(
            &mut self.conn,
            &mut self.authority_scope_fail_after,
            &prepared,
        )
    }
}

fn admit(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    prepared: &PreparedAuthorityScopeAdmission,
) -> Result<AuthorityScopeAdmission, AuthorityScopeError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(scope_store)?;
    if let Some(existing) = load(&tx, prepared.command().idempotency_key.as_str())? {
        let result = exact_replay(&tx, prepared, existing)?;
        tx.commit().map_err(scope_store)?;
        return Ok(result);
    }
    refuse_rebound_subject(&tx, prepared)?;
    let current = authority::current(&tx)?;
    if current.freeze_generation() != 0 {
        return Err(AuthorityScopeError::Frozen(current.freeze_generation()));
    }
    if current.authority_epoch() != prepared.expected_authority_epoch() {
        return Err(AuthorityScopeError::StaleAuthority {
            expected: prepared.expected_authority_epoch(),
            current: current.authority_epoch(),
        });
    }
    let next_epoch = current
        .authority_epoch()
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| AuthorityScopeError::Invalid("authority epoch overflow".to_owned()))?;
    let changed = tx
        .execute(
            "UPDATE authority_revisions
             SET scope_digest = ?1, authority_epoch = ?2
             WHERE singleton = 1 AND authority_epoch = ?3 AND freeze_generation = 0",
            params![
                prepared.scope_paths_digest(),
                to_i64(next_epoch)?,
                to_i64(current.authority_epoch())?,
            ],
        )
        .map_err(scope_store)?;
    if changed != 1 {
        return Err(scope_store("normalized authority changed during admission"));
    }
    step(fail_after)?;
    events::insert_event(
        &tx,
        "authority_scope_admitted",
        &prepared.grant().scope_grant_id,
        Some(&prepared.grant().scope_grant_id),
        Some(prepared.command().id().as_str()),
        None,
    )?;
    let event_sequence = u64::try_from(tx.last_insert_rowid()).map_err(scope_store)?;
    step(fail_after)?;
    tx.execute(
        "INSERT INTO authority_scope_admissions (
           idempotency_key, command_id, request_digest, scope_grant_id, grant_bytes,
           scope_revision, scope_paths_digest, previous_authority_epoch,
           new_authority_epoch, freeze_generation, admitted_at, event_sequence
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11)",
        params![
            prepared.command().idempotency_key,
            prepared.command().id().as_str(),
            prepared.command().digest().to_hex(),
            prepared.grant().scope_grant_id,
            prepared.grant_bytes(),
            to_i64(prepared.grant().scope_revision)?,
            prepared.scope_paths_digest(),
            to_i64(current.authority_epoch())?,
            to_i64(next_epoch)?,
            prepared.admitted_at(),
            to_i64(event_sequence)?,
        ],
    )
    .map_err(scope_store)?;
    step(fail_after)?;
    let stored = load(&tx, &prepared.command().idempotency_key)?
        .ok_or_else(|| scope_store("scope admission disappeared before commit"))?;
    let result = exact_replay(&tx, prepared, stored)?;
    tx.commit().map_err(scope_store)?;
    Ok(result)
}

#[derive(Debug)]
struct RawAdmission {
    idempotency_key: String,
    command_id: String,
    request_digest: String,
    scope_grant_id: String,
    grant_bytes: Vec<u8>,
    scope_revision: i64,
    scope_paths_digest: String,
    previous_authority_epoch: i64,
    new_authority_epoch: i64,
    freeze_generation: i64,
    admitted_at: String,
    event_sequence: i64,
}

fn load(
    conn: &Connection,
    idempotency_key: &str,
) -> Result<Option<RawAdmission>, AuthorityScopeError> {
    conn.query_row(
        "SELECT idempotency_key, command_id, request_digest, scope_grant_id, grant_bytes,
                scope_revision, scope_paths_digest, previous_authority_epoch,
                new_authority_epoch, freeze_generation, admitted_at, event_sequence
         FROM authority_scope_admissions WHERE idempotency_key = ?1",
        [idempotency_key],
        |row| {
            Ok(RawAdmission {
                idempotency_key: row.get(0)?,
                command_id: row.get(1)?,
                request_digest: row.get(2)?,
                scope_grant_id: row.get(3)?,
                grant_bytes: row.get(4)?,
                scope_revision: row.get(5)?,
                scope_paths_digest: row.get(6)?,
                previous_authority_epoch: row.get(7)?,
                new_authority_epoch: row.get(8)?,
                freeze_generation: row.get(9)?,
                admitted_at: row.get(10)?,
                event_sequence: row.get(11)?,
            })
        },
    )
    .optional()
    .map_err(scope_store)
}

fn exact_replay(
    conn: &Connection,
    prepared: &PreparedAuthorityScopeAdmission,
    raw: RawAdmission,
) -> Result<AuthorityScopeAdmission, AuthorityScopeError> {
    let expected_command_id = prepared.command().id();
    let expected_request_digest = prepared.command().digest().to_hex();
    if raw.idempotency_key != prepared.command().idempotency_key
        || raw.command_id != expected_command_id.as_str()
        || raw.request_digest != expected_request_digest
        || raw.scope_grant_id != prepared.grant().scope_grant_id
        || raw.grant_bytes != prepared.grant_bytes()
        || raw.scope_revision != to_i64(prepared.grant().scope_revision)?
        || raw.scope_paths_digest != prepared.scope_paths_digest()
        || raw.previous_authority_epoch != to_i64(prepared.expected_authority_epoch())?
        || raw.admitted_at != prepared.admitted_at()
    {
        return Err(AuthorityScopeError::Conflict(
            "idempotency key is bound to another scope subject".to_owned(),
        ));
    }
    let previous = to_u64(raw.previous_authority_epoch)?;
    let new = to_u64(raw.new_authority_epoch)?;
    let freeze = to_u64(raw.freeze_generation)?;
    let event_sequence = to_u64(raw.event_sequence)?;
    if previous.checked_add(1) != Some(new) || freeze != 0 {
        return Err(scope_store(
            "persisted scope admission epoch binding is corrupt",
        ));
    }
    let event_matches: bool = conn
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM events
               WHERE seq = ?1 AND kind = 'authority_scope_admitted'
                 AND body = ?2 AND stream_id = ?2 AND correlation_id = ?3
             )",
            params![raw.event_sequence, raw.scope_grant_id, raw.command_id],
            |row| row.get(0),
        )
        .map_err(scope_store)?;
    if !event_matches {
        return Err(scope_store("scope admission audit linkage is corrupt"));
    }
    Ok(AuthorityScopeAdmission {
        schema_version: "v1alpha1".to_owned(),
        command_id: CommandId::parse(&raw.command_id).map_err(scope_store)?,
        idempotency_key: raw.idempotency_key,
        request_digest: raw.request_digest,
        scope_grant_id: raw.scope_grant_id,
        scope_revision: to_u64(raw.scope_revision)?,
        scope_paths_digest: raw.scope_paths_digest,
        previous_authority_epoch: previous,
        new_authority_epoch: new,
        freeze_generation: freeze,
        admitted_at: raw.admitted_at,
        event_sequence,
    })
}

fn refuse_rebound_subject(
    conn: &Connection,
    prepared: &PreparedAuthorityScopeAdmission,
) -> Result<(), AuthorityScopeError> {
    let rebound: bool = conn
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM authority_scope_admissions
               WHERE command_id = ?1 OR scope_grant_id = ?2
             )",
            params![
                prepared.command().id().as_str(),
                prepared.grant().scope_grant_id,
            ],
            |row| row.get(0),
        )
        .map_err(scope_store)?;
    if rebound {
        Err(AuthorityScopeError::Conflict(
            "command or scope-grant identity is already bound".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn step(fail_after: &mut Option<u8>) -> Result<(), AuthorityScopeError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(scope_store("injected authority-scope admission failure"))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

fn to_i64(value: u64) -> Result<i64, AuthorityScopeError> {
    i64::try_from(value).map_err(scope_store)
}

fn to_u64(value: i64) -> Result<u64, AuthorityScopeError> {
    u64::try_from(value).map_err(scope_store)
}

fn scope_store(error: impl ToString) -> AuthorityScopeError {
    AuthorityScopeError::Ledger(store(error))
}
