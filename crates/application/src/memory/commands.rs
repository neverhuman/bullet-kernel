//! Command identity, exact replay, and command-correlated outbox helpers.

use super::MemoryLedger;
use crate::{CommandRecord, CommandRequest, LedgerError, OutboxItem};
use bullet_domain::{CommandId, CommandPhase, DomainError};

impl MemoryLedger {
    pub(super) fn record_command_impl(
        &mut self,
        request: &CommandRequest,
    ) -> Result<CommandRecord, LedgerError> {
        request.validate()?;
        self.tick()?;
        if let Some(existing) = self.commands.get(&request.idempotency_key) {
            request.matches(existing)?;
            return Ok(existing.clone());
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
        record.validate()?;
        self.commands
            .insert(request.idempotency_key.clone(), record.clone());
        Ok(record)
    }

    pub(super) fn set_command_phase_impl(
        &mut self,
        key: &str,
        phase: CommandPhase,
        response: Option<&str>,
    ) -> Result<(), LedgerError> {
        let mut next = self
            .commands
            .get(key)
            .cloned()
            .ok_or_else(|| LedgerError::Store(format!("unknown command key {key}")))?;
        next.phase = phase;
        if let Some(response) = response {
            next.response = Some(response.to_string());
        }
        next.validate()?;
        self.tick()?;
        self.commands.insert(key.to_string(), next);
        Ok(())
    }

    pub(super) fn get_command_impl(&self, key: &str) -> Result<Option<CommandRecord>, LedgerError> {
        let record = self.commands.get(key).cloned();
        if let Some(record) = &record {
            record.validate()?;
        }
        Ok(record)
    }

    pub(super) fn get_command_by_id_impl(
        &self,
        id: &CommandId,
    ) -> Result<Option<CommandRecord>, LedgerError> {
        let mut matching = self.commands.values().filter(|record| record.id == *id);
        let record = matching.next().cloned();
        if matching.next().is_some() {
            return Err(LedgerError::Store(format!(
                "multiple commands have durable id {id}"
            )));
        }
        if let Some(record) = &record {
            record.validate()?;
        }
        Ok(record)
    }

    pub(super) fn outbox_enqueue_impl(
        &mut self,
        command_id: Option<CommandId>,
        kind: &str,
        payload: &str,
    ) -> Result<u64, LedgerError> {
        if let Some(command_id) = &command_id {
            match self.get_command_by_id_impl(command_id)? {
                Some(_) => {}
                None => {
                    return Err(DomainError::Conflict(format!(
                        "outbox command {command_id} does not exist"
                    ))
                    .into());
                }
            }
        }
        self.tick()?;
        let seq = self.outbox.len() as u64 + 1;
        self.outbox.push(OutboxItem {
            seq,
            command_id,
            kind: kind.to_string(),
            payload: payload.to_string(),
            phase: CommandPhase::Pending,
            delivered_at: None,
            acked_at: None,
        });
        Ok(seq)
    }
}
