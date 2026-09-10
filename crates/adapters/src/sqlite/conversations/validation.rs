use super::super::{events, operator_commands, outbox, store};
use bullet_application::conversations::{
    conversation_id, ConversationMessagePayload, ConversationMessageReceipt, HeadTurnReference,
    HEAD_TURN_OUTBOX_KIND, MAX_MESSAGE_SEQUENCE,
};
use bullet_application::{CommandRecord, CommandRequest, LedgerError};
use bullet_domain::{CommandId, CommandPhase};
use rusqlite::{params, Connection};

struct StoredMessage {
    thread: String,
    message: String,
    sequence: u64,
    parent: Option<String>,
    content: String,
    digest: String,
    event: u64,
    at: String,
    created_command: String,
    created_event: u64,
    created_at: String,
}

pub(in crate::sqlite) fn verify(
    conn: &Connection,
    operator: &str,
    request: &CommandRequest,
    record: &CommandRecord,
) -> Result<(), LedgerError> {
    verify_one(conn, operator, request, record)?;
    let saved = read(conn, operator, &record.id)?;
    super::history::verify_before(conn, operator, &saved.thread, saved.sequence)
}

pub(super) fn verify_one(
    conn: &Connection,
    operator: &str,
    request: &CommandRequest,
    record: &CommandRecord,
) -> Result<(), LedgerError> {
    request.matches(record)?;
    if operator_commands::owner(conn, &record.id)?.as_deref() != Some(operator) {
        return Err(store("saved message command has conflicting ownership"));
    }
    let payload = ConversationMessagePayload::parse(&request.payload)?;
    let saved = read(conn, operator, &record.id)?;
    let owned: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM operator_command_ownership WHERE command_id=?1
         AND operator_id=?2 AND request_digest=?3 AND submitted_sequence=?4 AND admitted_at=?5)",
            params![
                record.id.as_str(),
                operator,
                record.payload_digest.to_hex(),
                saved.event,
                saved.at
            ],
            |row| row.get(0),
        )
        .map_err(store)?;
    if !owned {
        return Err(store(
            "saved message ownership conflicts with its original command",
        ));
    }
    let receipt = ConversationMessageReceipt::for_request(request, &saved.thread, saved.sequence)?;
    let parent = payload
        .cursor
        .as_ref()
        .map(|cursor| cursor.message_id.clone());
    let (thread, sequence) = match &payload.cursor {
        None => (conversation_id(operator, &record.id)?, 1),
        Some(cursor) => (
            cursor.conversation_id.clone(),
            cursor
                .sequence
                .checked_add(1)
                .filter(|value| *value <= MAX_MESSAGE_SEQUENCE)
                .ok_or_else(|| store("saved message sequence overflow"))?,
        ),
    };
    if saved.thread != thread
        || saved.sequence != sequence
        || saved.parent != parent
        || saved.message != receipt.cursor.message_id
        || saved.content != payload.content
        || saved.digest != receipt.content_digest
        || saved.event == 0
        || saved.event > MAX_MESSAGE_SEQUENCE
        || chrono::DateTime::parse_from_rfc3339(&saved.at).is_err()
        || saved.thread != conversation_id(operator, &CommandId::parse(&saved.created_command)?)?
    {
        return Err(store(
            "saved conversation message conflicts with original request",
        ));
    }
    let predecessor: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversation_messages m
         JOIN operator_command_ownership o ON o.command_id=m.command_id
         WHERE m.conversation_id=?1 AND m.sequence=1 AND m.parent_message_id IS NULL
           AND m.role='user' AND m.command_id=?2 AND m.accepted_sequence=?3 AND m.accepted_at=?4
           AND o.operator_id=?5 AND o.submitted_sequence=m.accepted_sequence AND o.admitted_at=m.accepted_at)",
        params![saved.thread,saved.created_command,saved.created_event,saved.created_at,operator],
        |row| row.get(0),
    ).map_err(store)?;
    let parent_valid: bool = conn
        .query_row(
            "SELECT ?2=1 OR EXISTS(SELECT 1 FROM conversation_messages
         WHERE conversation_id=?1 AND sequence=?2-1 AND message_id=?3)",
            params![saved.thread, saved.sequence, saved.parent],
            |row| row.get(0),
        )
        .map_err(store)?;
    if !predecessor || !parent_valid {
        return Err(store("conversation ancestry is incomplete"));
    }
    validate_projection(conn, request, record, &saved, &receipt)
}

fn read(conn: &Connection, operator: &str, id: &CommandId) -> Result<StoredMessage, LedgerError> {
    conn.query_row(
        "SELECT m.conversation_id,m.message_id,m.sequence,m.parent_message_id,m.content,
         m.content_digest,m.accepted_sequence,m.accepted_at,c.created_command_id,c.created_sequence,c.created_at
         FROM conversation_messages m JOIN conversations c ON c.conversation_id=m.conversation_id
         WHERE m.command_id=?1 AND m.role='user' AND m.head_turn_id IS NULL AND c.operator_id=?2",
        params![id.as_str(),operator], |row| Ok(StoredMessage {
            thread:row.get(0)?,message:row.get(1)?,sequence:row.get(2)?,parent:row.get(3)?,
            content:row.get(4)?,digest:row.get(5)?,event:row.get(6)?,at:row.get(7)?,
            created_command:row.get(8)?,created_event:row.get(9)?,created_at:row.get(10)?,
        }),
    ).map_err(store)
}

fn validate_projection(
    conn: &Connection,
    request: &CommandRequest,
    record: &CommandRecord,
    saved: &StoredMessage,
    receipt: &ConversationMessageReceipt,
) -> Result<(), LedgerError> {
    let response = serde_json::to_string(receipt).map_err(store)?;
    let reference =
        serde_json::to_string(&HeadTurnReference::for_request(request, receipt)?).map_err(store)?;
    let rows = outbox::for_command(conn, &record.id)?;
    let claims: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM command_dispatch_claims WHERE command_id=?1",
            [record.id.as_str()],
            |row| row.get(0),
        )
        .map_err(store)?;
    if record.phase != CommandPhase::Applied
        || record.response.as_deref() != Some(&response)
        || claims != 0
        || rows.len() != 1
        || rows[0].kind != HEAD_TURN_OUTBOX_KIND
        || rows[0].payload != reference
        || rows[0].command_id.as_ref() != Some(&record.id)
        || rows[0].phase != CommandPhase::Pending
        || rows[0].delivered_at.is_some()
        || rows[0].acked_at.is_some()
    {
        return Err(store(
            "saved conversation command has conflicting local projection truth",
        ));
    }
    let heads: i64 = conn.query_row(
        "SELECT COUNT(*) FROM conversation_head_requests WHERE turn_id=?1 AND conversation_id=?2
         AND input_message_id=?3 AND input_sequence=?4 AND command_id=?5 AND outbox_sequence=?6 AND requested_at=?7",
        params![receipt.head_turn_id,saved.thread,saved.message,saved.sequence,record.id.as_str(),rows[0].seq,saved.at],
        |row| row.get(0),
    ).map_err(store)?;
    let audit = events::command_projection_events(conn, &record.id)?;
    if heads != 1
        || audit.len() != 2
        || audit[0].kind != "command_submitted"
        || audit[0].body != record.id.as_str()
        || audit[0].seq != saved.event
        || audit[0].at != saved.at
        || audit[1].kind != bullet_application::commands::COMMAND_RECONCILED_EVENT
        || audit[1].body != response
        || audit[1].seq <= audit[0].seq
        || audit.iter().any(|event| {
            event.stream_id.as_deref() != Some(record.id.as_str())
                || event.correlation_id.as_deref() != Some(record.id.as_str())
                || chrono::DateTime::parse_from_rfc3339(&event.at).is_err()
        })
    {
        return Err(store(
            "saved conversation command has incomplete causal audit truth",
        ));
    }
    Ok(())
}
