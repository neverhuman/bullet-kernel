//! Command identity, exact replay, and command-correlated outbox helpers.

use super::MemoryLedger;
use crate::commands::COMMAND_RECONCILED_EVENT;
use crate::nonce_ledger::NonceState;
use crate::run_coding::{
    plan_run_coding_admission, CodingAdmissionView, RunCodingPayload, RUN_CODING_KIND,
};
use crate::{CommandRecord, CommandRequest, LedgerError, OutboxItem};
use bullet_domain::{CommandId, CommandPhase, DomainError};

impl MemoryLedger {
    pub(super) fn submit_command_impl(
        &mut self,
        request: &CommandRequest,
    ) -> Result<CommandRecord, LedgerError> {
        let before = self.clone();
        let transaction = (|| {
            let existed = self.commands.contains_key(&request.idempotency_key);
            let record = self.record_command_impl(request)?;
            let dispatch = serde_json::to_string(request)
                .map_err(|error| LedgerError::Store(error.to_string()))?;
            if existed {
                let rows = self
                    .outbox
                    .iter()
                    .filter(|item| item.command_id.as_ref() == Some(&record.id))
                    .collect::<Vec<_>>();
                if rows.len() != 1
                    || rows[0].kind != "command_dispatch"
                    || rows[0].payload != dispatch
                {
                    return Err(LedgerError::Store(
                        "public command has incomplete or conflicting outbox truth".into(),
                    ));
                }
                let events = self
                    .events
                    .iter()
                    .filter(|event| {
                        event.kind == "command_submitted"
                            && event.body == record.id.as_str()
                            && event.correlation_id.as_deref() == Some(record.id.as_str())
                    })
                    .count();
                if events != 1 {
                    return Err(LedgerError::Store(
                        "public command has incomplete or conflicting event truth".into(),
                    ));
                }
            } else {
                self.outbox_enqueue_impl(Some(record.id.clone()), "command_dispatch", &dispatch)?;
                self.tick()?;
                self.push_event(
                    "command_submitted",
                    record.id.as_str(),
                    Some(record.id.to_string()),
                    Some(record.id.to_string()),
                    None,
                );
            }
            self.admit_run_coding_impl(request, existed)?;
            Ok(record)
        })();
        match transaction {
            Ok(record) => Ok(record),
            Err(error) => {
                let failpoint = self.fail_after_writes;
                *self = before;
                self.fail_after_writes = failpoint;
                Err(error)
            }
        }
    }

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

    pub(super) fn reconcile_offline_command_impl(
        &mut self,
        id: &CommandId,
        now: &str,
    ) -> Result<CommandRecord, LedgerError> {
        let before = self.clone();
        let transaction = (|| {
            let record = self
                .get_command_by_id_impl(id)?
                .ok_or_else(|| LedgerError::Store(format!("unknown command {id}")))?;
            let request =
                CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)?;
            request.matches(&record)?;
            let dispatch = serde_json::to_string(&request)
                .map_err(|error| LedgerError::Store(error.to_string()))?;
            let rows = self
                .outbox
                .iter()
                .enumerate()
                .filter(|(_, item)| item.command_id.as_ref() == Some(id))
                .collect::<Vec<_>>();
            if rows.len() != 1
                || rows[0].1.kind != "command_dispatch"
                || rows[0].1.payload != dispatch
            {
                return Err(LedgerError::Store(
                    "command has incomplete or conflicting dispatch truth".into(),
                ));
            }
            let submitted = self
                .events
                .iter()
                .filter(|event| {
                    event.kind == "command_submitted"
                        && event.body == id.as_str()
                        && event.correlation_id.as_deref() == Some(id.as_str())
                })
                .count();
            if submitted != 1 {
                return Err(LedgerError::Store(
                    "command has incomplete or conflicting submitted audit truth".into(),
                ));
            }
            let resolution = request.offline_worker_resolution()?;
            let expected = resolution.resolved_record(record.clone())?;
            let reconciled = self
                .events
                .iter()
                .filter(|event| {
                    event.kind == COMMAND_RECONCILED_EVENT
                        && event.correlation_id.as_deref() == Some(id.as_str())
                })
                .collect::<Vec<_>>();
            let (outbox_index, row) = rows[0];
            if record.phase != CommandPhase::Pending {
                if record != expected
                    || row.phase != resolution.phase()
                    || row.delivered_at.is_some()
                    || row.acked_at.is_none()
                    || reconciled.len() != 1
                    || reconciled[0].body != resolution.response()
                {
                    return Err(LedgerError::Store(
                        "command has conflicting reconciled truth".into(),
                    ));
                }
                return Ok(record);
            }
            if row.phase != CommandPhase::Pending
                || row.delivered_at.is_some()
                || row.acked_at.is_some()
                || !reconciled.is_empty()
            {
                return Err(LedgerError::Store(
                    "pending command has conflicting worker truth".into(),
                ));
            }
            self.tick()?;
            self.commands
                .insert(record.idempotency_key.clone(), expected.clone());
            self.tick()?;
            let item = &mut self.outbox[outbox_index];
            item.phase = resolution.phase();
            item.acked_at = Some(now.to_string());
            self.tick()?;
            self.push_event(
                COMMAND_RECONCILED_EVENT,
                resolution.response(),
                Some(id.to_string()),
                Some(id.to_string()),
                None,
            );
            Ok(expected)
        })();
        match transaction {
            Ok(record) => Ok(record),
            Err(error) => {
                let failpoint = self.fail_after_writes;
                *self = before;
                self.fail_after_writes = failpoint;
                Err(error)
            }
        }
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

    pub(super) fn admit_run_coding_impl(
        &mut self,
        request: &CommandRequest,
        existed: bool,
    ) -> Result<(), LedgerError> {
        if request.kind != RUN_CODING_KIND {
            return Ok(());
        }
        let payload = RunCodingPayload::parse(&request.payload)?;
        let authority_epoch = self
            .authority
            .as_ref()
            .map_or(1, crate::NormalizedAuthority::authority_epoch);
        let used_quota = self.budget_reservations.values().copied().sum();
        let existing_reservation = self
            .budget_reservations
            .get(&payload.quota_reservation)
            .map(|amount| (payload.quota_reservation.clone(), *amount));
        if !existed && !self.authority_nonces.contains_key(&payload.launch_nonce) {
            self.authority_nonces.insert(
                payload.launch_nonce.clone(),
                (request.digest().to_hex(), false),
            );
        }
        let nonce = self
            .authority_nonces
            .get(&payload.launch_nonce)
            .map(|(digest, consumed)| {
                (
                    digest.clone(),
                    if *consumed {
                        NonceState::Consumed
                    } else {
                        NonceState::Issued
                    },
                )
            });
        let view = CodingAdmissionView {
            authority_epoch,
            used_quota,
            existing_reservation,
            nonce,
        };
        let Some(plan) = plan_run_coding_admission(request, existed, &view)? else {
            return Ok(());
        };
        let row = self
            .authority_nonces
            .get_mut(&plan.consume_nonce)
            .ok_or_else(|| LedgerError::Store("run_coding launch nonce is absent".into()))?;
        if row.0 != request.digest().to_hex() || row.1 {
            return Err(LedgerError::Store(
                "run_coding launch nonce is not issued for this request".into(),
            ));
        }
        row.1 = true;
        self.budget_reservations
            .insert(plan.reservation.0, plan.reservation.1);
        Ok(())
    }

    /// Issue one authority nonce for in-process coding admission tests.
    pub fn issue_coding_nonce(&mut self, key: &str, digest: &str) -> Result<(), LedgerError> {
        if self.authority_nonces.contains_key(key) {
            return Err(LedgerError::Store("nonce already issued".into()));
        }
        self.authority_nonces
            .insert(key.to_string(), (digest.to_string(), false));
        Ok(())
    }
}
