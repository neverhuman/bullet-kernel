//! Verify every causal predecessor without recursive reads or unbounded allocation.

use super::super::{commands, store};
use bullet_application::{CommandRequest, LedgerError};
use bullet_domain::CommandId;
use rusqlite::{params, Connection};

pub(super) fn verify_before(
    conn: &Connection,
    operator: &str,
    conversation: &str,
    through: u64,
) -> Result<(), LedgerError> {
    let mut next = 1u64;
    while next < through {
        let mut statement = conn
            .prepare(
                "SELECT sequence,role,command_id FROM conversation_messages
             WHERE conversation_id=?1 AND sequence>=?2 AND sequence<?3
             ORDER BY sequence LIMIT 100",
            )
            .map_err(store)?;
        let rows = statement
            .query_map(params![conversation, next, through], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(store)?;
        if rows.is_empty() {
            return Err(store(
                "conversation history has a missing causal predecessor",
            ));
        }
        for (sequence, role, command) in rows {
            if sequence != next {
                return Err(store("conversation history has a sequence gap"));
            }
            // A SQL fixture or a head request alone cannot establish an assistant turn.
            if role != "user" {
                return Err(store(
                    "assistant history has no admitted native head outcome",
                ));
            }
            let command = command.ok_or_else(|| store("human history has no original command"))?;
            let id = CommandId::parse(&command)?;
            let record = commands::get_command_by_id(conn, &id)?
                .ok_or_else(|| store("conversation predecessor command is absent"))?;
            let request =
                CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)?;
            super::validation::verify_one(conn, operator, &request, &record)?;
            next = next
                .checked_add(1)
                .ok_or_else(|| store("conversation history sequence overflow"))?;
        }
    }
    Ok(())
}
