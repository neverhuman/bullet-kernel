use super::super::{commands, events, operator_commands, outbox, store};
use bullet_application::conversations::{
    conversation_id, ConversationMessagePayload, ConversationMessageReceipt, ConversationRefusal,
    HeadTurnReference, HEAD_TURN_OUTBOX_KIND, MAX_MESSAGE_SEQUENCE,
};
use bullet_application::{CommandRecord, CommandRequest, LedgerError};
use bullet_domain::CommandPhase;
use rusqlite::{params, OptionalExtension, Transaction};

pub(in crate::sqlite) fn submit(
    tx: &Transaction<'_>,
    fail_after: &mut Option<u8>,
    operator: &str,
    request: &CommandRequest,
) -> Result<CommandRecord, LedgerError> {
    operator_commands::require_operator(tx, operator).map_err(store)?;
    let payload = ConversationMessagePayload::parse(&request.payload)?;
    if let Some(record) = commands::get_command(tx, &request.idempotency_key)? {
        request.matches(&record)?;
        super::verify(tx, operator, request, &record)?;
        return Ok(record);
    }
    // The current tip only constrains a fresh append. A settled retry remains valid.
    let (thread, sequence) = position(tx, operator, request, &payload)?;
    let receipt = ConversationMessageReceipt::for_request(request, &thread, sequence)?;
    let reference = HeadTurnReference::for_request(request, &receipt)?;
    commands::record_command(tx, request)?;
    commands::fail_boundary(fail_after)?;
    let id = request.id();
    events::insert_event(
        tx,
        "command_submitted",
        id.as_str(),
        Some(id.as_str()),
        Some(id.as_str()),
        None,
    )?;
    let (event, at): (i64, String) = tx
        .query_row(
            "SELECT seq,at FROM events WHERE seq=last_insert_rowid()",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(store)?;
    commands::fail_boundary(fail_after)?;
    if payload.cursor.is_none() {
        tx.execute(
            "INSERT INTO conversations VALUES (?1,?2,?3,?4,?5)",
            params![thread, operator, id.as_str(), event, at],
        )
        .map_err(store)?;
    }
    commands::fail_boundary(fail_after)?;
    tx.execute(
        "INSERT INTO conversation_messages (message_id,conversation_id,sequence,parent_message_id,
         role,content,content_digest,command_id,head_turn_id,accepted_sequence,accepted_at)
         VALUES (?1,?2,?3,?4,'user',?5,?6,?7,NULL,?8,?9)",
        params![
            receipt.cursor.message_id,
            thread,
            sequence,
            payload.cursor.as_ref().map(|cursor| &cursor.message_id),
            payload.content,
            receipt.content_digest,
            id.as_str(),
            event,
            at
        ],
    )
    .map_err(store)?;
    commands::fail_boundary(fail_after)?;
    let outbox_sequence = outbox::enqueue(
        tx,
        Some(&id),
        HEAD_TURN_OUTBOX_KIND,
        &serde_json::to_string(&reference).map_err(store)?,
    )?;
    commands::fail_boundary(fail_after)?;
    tx.execute(
        "INSERT INTO conversation_head_requests VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            receipt.head_turn_id,
            thread,
            receipt.cursor.message_id,
            sequence,
            id.as_str(),
            outbox_sequence,
            at
        ],
    )
    .map_err(store)?;
    commands::fail_boundary(fail_after)?;
    let response = serde_json::to_string(&receipt).map_err(store)?;
    commands::set_phase(
        tx,
        &request.idempotency_key,
        CommandPhase::Applied,
        Some(&response),
    )?;
    commands::fail_boundary(fail_after)?;
    events::insert_event(
        tx,
        bullet_application::commands::COMMAND_RECONCILED_EVENT,
        &response,
        Some(id.as_str()),
        Some(id.as_str()),
        None,
    )?;
    commands::fail_boundary(fail_after)?;
    commands::get_command_by_id(tx, &id)?.ok_or_else(|| store("saved message command is absent"))
}

fn position(
    tx: &Transaction<'_>,
    operator: &str,
    request: &CommandRequest,
    payload: &ConversationMessagePayload,
) -> Result<(String, u64), LedgerError> {
    let Some(cursor) = &payload.cursor else {
        return Ok((conversation_id(operator, &request.id())?, 1));
    };
    let owned: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id=?1 AND operator_id=?2)",
        params![cursor.conversation_id, operator], |row| row.get(0),
    ).map_err(store)?;
    if !owned {
        return Err(ConversationRefusal::NotFound.into());
    }
    let tip: Option<(String, u64)> = tx.query_row(
        "SELECT message_id,sequence FROM conversation_messages WHERE conversation_id=?1 ORDER BY sequence DESC LIMIT 1",
        [&cursor.conversation_id], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(store)?;
    let tip = tip.ok_or_else(|| store("persisted conversation has no first message"))?;
    if tip != (cursor.message_id.clone(), cursor.sequence) {
        return Err(ConversationRefusal::CursorConflict.into());
    }
    let sequence = cursor
        .sequence
        .checked_add(1)
        .filter(|value| *value <= MAX_MESSAGE_SEQUENCE)
        .ok_or(ConversationRefusal::SequenceExhausted)?;
    Ok((cursor.conversation_id.clone(), sequence))
}
