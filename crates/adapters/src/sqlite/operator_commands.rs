//! Public command ownership is committed together with original admission.
use super::{command_dispatch, commands, events, outbox, store, SqliteLedger};
use bullet_application::operator_commands::{
    validate_projection, OperatorCommandError as Error, OperatorCommandPage,
    OperatorCommandSnapshot, OperatorCommandStore,
};
use bullet_application::{CommandRecord, CommandRequest, LedgerError};
use bullet_domain::CommandId;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

type Result<T> = std::result::Result<T, Error>;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
// Below the existing 8MiB consumer cap, including generous envelope framing.
const MAX_PAGE_BYTES: usize = 7 * 1024 * 1024;
fn row_bytes(record: &CommandRecord) -> std::result::Result<usize, LedgerError> {
    let result = record
        .response
        .as_deref()
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .map_err(store)?;
    let result_bytes = serde_json::to_vec(&result).map_err(store)?.len();
    // Fixed ID/digest/status/field framing plus the admitted <=64-byte kind,
    // even with worst-case JSON escaping, fits in this 1024-byte allowance.
    result_bytes
        .checked_add(1024)
        .ok_or_else(|| store("command page size overflow"))
}

fn valid_owner(operator: &str) -> Result<()> {
    if !operator
        .strip_prefix("opr_")
        .is_some_and(super::migrations::valid_digest)
    {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}
pub(super) fn require_operator(conn: &Connection, operator: &str) -> Result<()> {
    valid_owner(operator)?;
    let admitted: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM local_operator WHERE operator_id=?1)",
            [operator],
            |row| row.get(0),
        )
        .map_err(store)?;
    if !admitted {
        return Err(Error::InvalidRequest);
    }
    let pending: i64 = conn
        .query_row(
            "SELECT pending_admission FROM restore_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(store)?;
    if pending != 0 {
        return Err(store("RESTORE_ADMISSION_REQUIRED").into());
    }
    Ok(())
}
pub(super) fn owner(
    conn: &Connection,
    id: &CommandId,
) -> std::result::Result<Option<String>, LedgerError> {
    conn.query_row(
        "SELECT operator_id FROM operator_command_ownership WHERE command_id=?1",
        [id.as_str()],
        |row| row.get(0),
    )
    .optional()
    .map_err(store)
}

pub(super) fn checked_record(
    conn: &Connection,
    id: &CommandId,
) -> std::result::Result<CommandRecord, LedgerError> {
    let record =
        commands::get_command_by_id(conn, id)?.ok_or_else(|| store("owned command is absent"))?;
    let request = CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)
        .map_err(store)?;
    request.matches(&record).map_err(store)?;
    let audit = events::command_projection_events(conn, id)?;
    if request.kind == bullet_application::conversations::CONVERSATION_MESSAGE_KIND {
        let operator =
            owner(conn, id)?.ok_or_else(|| store("conversation command has no owner"))?;
        super::conversations::verify(conn, &operator, &request, &record)?;
    } else {
        commands::verify_coding_replay(conn, &request)?;
        let dispatch = serde_json::to_string(&request).map_err(store)?;
        let rows = outbox::for_command(conn, id)?;
        let claim = command_dispatch::projection_claim(conn, id)?;
        validate_projection(&record, &dispatch, claim.as_ref(), &rows, &audit)?;
    }
    let binding: (i64,String,String)=conn.query_row("SELECT submitted_sequence,request_digest,admitted_at FROM operator_command_ownership WHERE command_id=?1", [id.as_str()], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(store)?;
    let sequence = u64::try_from(binding.0).map_err(store)?;
    if sequence == 0
        || sequence > MAX_SEQUENCE
        || binding.1 != record.payload_digest.to_hex()
        || !audit.iter().any(|event| {
            event.seq == sequence
                && event.kind == "command_submitted"
                && event.body == id.as_str()
                && event.stream_id.as_deref() == Some(id.as_str())
                && event.correlation_id.as_deref() == Some(id.as_str())
                && event.at == binding.2
        })
        || chrono::DateTime::parse_from_rfc3339(&binding.2).is_err()
    {
        return Err(store(
            "command ownership does not match its submitted subject",
        ));
    }
    Ok(record)
}

impl OperatorCommandStore for SqliteLedger {
    fn submit_operator_command(
        &mut self,
        operator: &str,
        request: &CommandRequest,
    ) -> Result<OperatorCommandSnapshot> {
        valid_owner(operator)?;
        request.validate().map_err(LedgerError::from)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM commands WHERE idempotency_key=?1)",
                [&request.idempotency_key],
                |row| row.get(0),
            )
            .map_err(store)?;
        if exists && owner(&tx, &request.id())?.as_deref() != Some(operator) {
            return Err(Error::OwnershipConflict);
        }
        require_operator(&tx, operator)?;
        if !exists
            && request.kind == bullet_application::RUN_CODING_KIND
            && bullet_application::coding_tasks::task_payload(request)
                .map_err(LedgerError::from)?
                .is_none()
        {
            return Err(Error::ObsoleteCodingShape);
        }
        let record = commands::submit_command_in(
            &tx,
            &mut self.command_submission_fail_after,
            request,
            Some(operator),
        )?;
        if !exists {
            let inserted=tx.execute("INSERT INTO operator_command_ownership (command_id,operator_id,submitted_sequence,request_digest,admitted_at)
                SELECT ?1,?2,seq,?3,at FROM events WHERE kind='command_submitted' AND body=?1 AND stream_id=?1 AND correlation_id=?1",
                params![record.id.as_str(),operator,record.payload_digest.to_hex()]).map_err(store)?;
            if inserted != 1 {
                return Err(store("new command lacks one exact submitted event").into());
            }
        }
        commands::fail_boundary(&mut self.command_submission_fail_after)?;
        let command = checked_record(&tx, &record.id)?;
        let as_of_sequence = events::latest_sequence(&tx)?;
        tx.commit().map_err(store)?;
        Ok(OperatorCommandSnapshot {
            command,
            as_of_sequence,
        })
    }
    fn get_operator_command(
        &self,
        operator: &str,
        id: &CommandId,
    ) -> Result<Option<OperatorCommandSnapshot>> {
        valid_owner(operator)?;
        let tx = super::ReadTransaction::begin(&self.conn)?;
        require_operator(&self.conn, operator)?;
        if owner(&self.conn, id)?.as_deref() != Some(operator) {
            tx.commit()?;
            return Ok(None);
        }
        let command = checked_record(&self.conn, id)?;
        let as_of_sequence = events::latest_sequence(&self.conn)?;
        tx.commit()?;
        Ok(Some(OperatorCommandSnapshot {
            command,
            as_of_sequence,
        }))
    }
    fn list_operator_commands(
        &self,
        operator: &str,
        after: u64,
        limit: u32,
    ) -> Result<OperatorCommandPage> {
        valid_owner(operator)?;
        if after > MAX_SEQUENCE || !(1..=100).contains(&limit) {
            return Err(Error::InvalidRequest);
        }
        let tx = super::ReadTransaction::begin(&self.conn)?;
        require_operator(&self.conn, operator)?;
        let mut statement=self.conn.prepare("SELECT command_id,submitted_sequence FROM operator_command_ownership WHERE operator_id=?1 AND submitted_sequence>?2 ORDER BY submitted_sequence LIMIT ?3").map_err(store)?;
        let raw = statement
            .query_map(params![operator, after, limit + 1], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(store)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(store)?;
        let mut has_more = raw.len() > limit as usize;
        let mut bytes = 4096usize;
        let mut commands = Vec::new();
        let mut last = after;
        for (id, sequence) in raw.into_iter().take(limit as usize) {
            let sequence = u64::try_from(sequence).map_err(store)?;
            if sequence <= last || sequence > MAX_SEQUENCE {
                return Err(store("invalid command discovery ordering").into());
            }
            let record = checked_record(&self.conn, &CommandId::parse(id).map_err(store)?)?;
            let next_bytes = bytes
                .checked_add(row_bytes(&record)?)
                .ok_or_else(|| store("command page size overflow"))?;
            if next_bytes > MAX_PAGE_BYTES {
                if commands.is_empty() {
                    return Err(store("one command exceeds discovery byte budget").into());
                }
                has_more = true;
                break;
            }
            bytes = next_bytes;
            commands.push(record);
            last = sequence;
        }
        let as_of_sequence = events::latest_sequence(&self.conn)?;
        if last > as_of_sequence {
            return Err(store("command discovery exceeds snapshot watermark").into());
        }
        drop(statement);
        tx.commit()?;
        Ok(OperatorCommandPage {
            commands,
            next_after: has_more.then_some(last),
            as_of_sequence,
        })
    }
}

#[cfg(test)]
mod tests;
