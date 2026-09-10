use super::super::{commands, events, operator_commands, store, ReadTransaction, SqliteLedger};
use bullet_application::conversations::{
    validate_subject, ConversationIndex, ConversationMessage, ConversationMessagePayload,
    ConversationMessageReceipt, ConversationPage, ConversationRole, ConversationStore,
    ConversationSummary, MAX_MESSAGE_SEQUENCE,
};
use bullet_application::operator_commands::OperatorCommandError as Error;
use bullet_application::{CommandRequest, LedgerError};
use bullet_domain::CommandId;
use rusqlite::{params, Connection};

fn limits(after: u64, limit: u32) -> Result<(), Error> {
    if after > MAX_MESSAGE_SEQUENCE || !(1..=100).contains(&limit) {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}

fn observed_at(conn: &Connection) -> Result<String, LedgerError> {
    conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
        row.get(0)
    })
    .map_err(store)
}

fn message(
    conn: &Connection,
    operator: &str,
    id: &str,
) -> Result<ConversationMessage, LedgerError> {
    let (role, command, at): (String, Option<String>, String) = conn
        .query_row(
            "SELECT role,command_id,accepted_at FROM conversation_messages WHERE message_id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(store)?;
    if role != "user" {
        return Err(store(
            "assistant message has no admitted native head outcome",
        ));
    }
    let command = command.ok_or_else(|| store("human message has no original command"))?;
    let record = commands::get_command_by_id(conn, &CommandId::parse(&command)?)?
        .ok_or_else(|| store("human message command is absent"))?;
    let request =
        CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)?;
    super::validation::verify_one(conn, operator, &request, &record)?;
    let receipt: ConversationMessageReceipt = serde_json::from_str(
        record
            .response
            .as_deref()
            .ok_or_else(|| store("human message has no saved receipt"))?,
    )
    .map_err(store)?;
    if receipt.cursor.message_id != id {
        return Err(store("message lookup does not match its command"));
    }
    let payload = ConversationMessagePayload::parse(&request.payload)?;
    Ok(ConversationMessage {
        cursor: receipt.cursor,
        parent_message_id: payload.cursor.map(|cursor| cursor.message_id),
        role: ConversationRole::User,
        content: payload.content,
        content_digest: receipt.content_digest,
        command_id: Some(command),
        head_turn_id: receipt.head_turn_id,
        accepted_at: at,
    })
}

fn tip(
    conn: &Connection,
    operator: &str,
    conversation: &str,
) -> Result<ConversationMessage, LedgerError> {
    let (id, sequence): (String,u64) = conn.query_row(
        "SELECT message_id,sequence FROM conversation_messages WHERE conversation_id=?1 ORDER BY sequence DESC LIMIT 1",
        [conversation], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(store)?;
    let last = message(conn, operator, &id)?;
    if last.cursor.conversation_id != conversation || last.cursor.sequence != sequence {
        return Err(store(
            "conversation tip does not match its immutable message",
        ));
    }
    super::history::verify_before(conn, operator, conversation, sequence)?;
    Ok(last)
}

impl ConversationStore for SqliteLedger {
    fn get_operator_conversation(
        &self,
        operator: &str,
        conversation: &str,
        after: u64,
        limit: u32,
    ) -> Result<Option<ConversationPage>, Error> {
        limits(after, limit)?;
        validate_subject(conversation, "cnv_").map_err(|_| Error::InvalidRequest)?;
        let transaction = ReadTransaction::begin(&self.conn)?;
        operator_commands::require_operator(&self.conn, operator)?;
        let owned: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id=?1 AND operator_id=?2)",
            params![conversation,operator], |row| row.get(0),
        ).map_err(store)?;
        if !owned {
            transaction.commit()?;
            return Ok(None);
        }
        let last = tip(&self.conn, operator, conversation)?;
        if after > last.cursor.sequence {
            return Err(Error::InvalidRequest);
        }
        let mut statement = self
            .conn
            .prepare(
                "SELECT message_id,sequence FROM conversation_messages WHERE conversation_id=?1
             AND sequence>?2 ORDER BY sequence LIMIT ?3",
            )
            .map_err(store)?;
        let rows = statement
            .query_map(params![conversation, after, limit + 1], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(store)?;
        let has_more = rows.len() > limit as usize;
        let mut messages = Vec::new();
        let mut position = after;
        for (id, sequence) in rows.into_iter().take(limit as usize) {
            if sequence != position + 1 {
                return Err(store("conversation page has a gap").into());
            }
            let observed = message(&self.conn, operator, &id)?;
            if observed.cursor.sequence != sequence
                || observed.cursor.conversation_id != conversation
            {
                return Err(store("conversation page contains another message subject").into());
            }
            messages.push(observed);
            position = sequence;
        }
        if !has_more && position != last.cursor.sequence {
            return Err(store("conversation page ended before its observed tip").into());
        }
        let page = ConversationPage {
            cursor: last.cursor,
            messages,
            next_after: has_more.then_some(position),
            head_blocker: "HEAD_RUNTIME_BINDING_REQUIRED".into(),
            as_of_sequence: events::latest_sequence(&self.conn)?,
            observed_at: observed_at(&self.conn)?,
        };
        drop(statement);
        transaction.commit()?;
        Ok(Some(page))
    }

    fn list_operator_conversations(
        &self,
        operator: &str,
        after: u64,
        limit: u32,
    ) -> Result<ConversationIndex, Error> {
        limits(after, limit)?;
        let transaction = ReadTransaction::begin(&self.conn)?;
        operator_commands::require_operator(&self.conn, operator)?;
        let as_of_sequence = events::latest_sequence(&self.conn)?;
        if after > as_of_sequence {
            return Err(Error::InvalidRequest);
        }
        let mut statement = self
            .conn
            .prepare(
                "SELECT conversation_id,created_sequence,created_at FROM conversations
             WHERE operator_id=?1 AND created_sequence>?2 ORDER BY created_sequence LIMIT ?3",
            )
            .map_err(store)?;
        let rows = statement
            .query_map(params![operator, after, limit + 1], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(store)?;
        let has_more = rows.len() > limit as usize;
        let mut conversations = Vec::new();
        let mut position = after;
        for (id, sequence, created_at) in rows.into_iter().take(limit as usize) {
            if sequence <= position || sequence > MAX_MESSAGE_SEQUENCE {
                return Err(store("conversation index has invalid creation ordering").into());
            }
            let last = tip(&self.conn, operator, &id)?;
            let first_id: String = self.conn.query_row(
                "SELECT message_id FROM conversation_messages WHERE conversation_id=?1 AND sequence=1",
                [&id], |row| row.get(0),
            ).map_err(store)?;
            let first = message(&self.conn, operator, &first_id)?;
            conversations.push(ConversationSummary {
                cursor: last.cursor,
                preview: first
                    .content
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .take(80)
                    .collect(),
                created_at,
                last_activity_at: last.accepted_at,
            });
            position = sequence;
        }
        let index = ConversationIndex {
            conversations,
            next_after: has_more.then_some(position),
            as_of_sequence,
            observed_at: observed_at(&self.conn)?,
        };
        if position > index.as_of_sequence {
            return Err(store("conversation index exceeds its snapshot watermark").into());
        }
        drop(statement);
        transaction.commit()?;
        Ok(index)
    }
}
