//! One interpretation of persisted command/outbox/claim/audit truth.
use crate::commands::COMMAND_RECONCILED_EVENT;
use crate::{
    CommandDispatchClaim, CommandDispatchDisposition, CommandRecord, LedgerError, LedgerEvent,
    OutboxItem,
};
use bullet_domain::CommandPhase;

/// Require complete, exactly correlated durable command projection truth.
/// # Errors
/// Any missing/conflicting row, phase, receipt or audit subject is a store error.
pub fn validate_projection(
    record: &CommandRecord,
    dispatch: &str,
    claim: Option<&CommandDispatchClaim>,
    outbox: &[OutboxItem],
    events: &[LedgerEvent],
) -> Result<(), LedgerError> {
    if outbox.len() != 1
        || outbox[0].command_id.as_ref() != Some(&record.id)
        || outbox[0].kind != "command_dispatch"
        || outbox[0].payload != dispatch
    {
        return Err(LedgerError::Store(
            "command has incomplete or conflicting dispatch truth".into(),
        ));
    }
    let id = record.id.as_str();
    let submitted: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == "command_submitted"
                && (event.stream_id.as_deref() == Some(id)
                    || event.correlation_id.as_deref() == Some(id))
        })
        .collect();
    if submitted.len() != 1
        || submitted[0].body != id
        || submitted[0].stream_id.as_deref() != Some(id)
        || submitted[0].correlation_id.as_deref() != Some(id)
    {
        return Err(LedgerError::Store(
            "command has incomplete or conflicting submitted audit truth".into(),
        ));
    }
    let reconciled: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == COMMAND_RECONCILED_EVENT
                && (event.stream_id.as_deref() == Some(id)
                    || event.correlation_id.as_deref() == Some(id))
        })
        .collect();
    let claimed: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == "command_dispatch_claimed"
                && (event.stream_id.as_deref() == Some(id)
                    || event.correlation_id.as_deref() == Some(id))
        })
        .collect();
    let row = &outbox[0];
    if let Some(claim) = claim {
        claim
            .validate()
            .map_err(|error| LedgerError::Store(error.to_string()))?;
        if claim.command_id != record.id
            || claim.outbox_sequence != row.seq
            || claim.request_digest != record.payload_digest
        {
            return Err(LedgerError::Store(
                "command dispatch claim is bound to another subject".into(),
            ));
        }
    }
    let exact_claimed = |claim: &CommandDispatchClaim| {
        claimed.len() == 1
            && claimed[0].body == claim.claim_id
            && claimed[0].stream_id.as_deref() == Some(id)
            && claimed[0].correlation_id.as_deref() == Some(id)
    };
    let pending = match claim {
        None => {
            row.phase == CommandPhase::Pending
                && row.delivered_at.is_none()
                && row.acked_at.is_none()
                && claimed.is_empty()
                && reconciled.is_empty()
        }
        Some(value)
            if matches!(
                value.disposition,
                CommandDispatchDisposition::Claimed | CommandDispatchDisposition::Invalidated
            ) =>
        {
            row.phase == CommandPhase::Applied
                && row.delivered_at.is_some()
                && row.acked_at.is_none()
                && exact_claimed(value)
                && reconciled.is_empty()
        }
        _ => false,
    };
    if record.phase == CommandPhase::Pending {
        return pending.then_some(()).ok_or_else(|| {
            LedgerError::Store("pending command has conflicting projection truth".into())
        });
    }
    let response = record
        .response
        .as_deref()
        .ok_or_else(|| LedgerError::Store("settled command has no exact result truth".into()))?;
    let terminal_claim = match (record.phase, claim) {
        (CommandPhase::Unknown, Some(value))
            if value.disposition == CommandDispatchDisposition::Unknown =>
        {
            row.delivered_at.is_some() && exact_claimed(value)
        }
        (CommandPhase::Failed, Some(value))
            if value.disposition == CommandDispatchDisposition::Failed =>
        {
            row.delivered_at.is_none() && claimed.is_empty()
        }
        _ => false,
    };
    if !terminal_claim
        || row.phase != record.phase
        || row.acked_at.is_none()
        || reconciled.len() != 1
        || reconciled[0].stream_id.as_deref() != Some(id)
        || reconciled[0].correlation_id.as_deref() != Some(id)
        || reconciled[0].body != response
    {
        return Err(LedgerError::Store(
            "settled command has incomplete or conflicting projection truth".into(),
        ));
    }
    Ok(())
}
