//! Task intent is committed with public commands; only a separate admission can launch it.
use super::{events, operator_commands, store, ReadTransaction, SqliteLedger};
use bullet_application::coding_tasks::{
    task_payload, CodingQueueBlocker, CodingRunObservation, CodingTaskStore,
};
use bullet_application::operator_commands::OperatorCommandError;
use bullet_application::{CommandRequest, LedgerError};
use bullet_domain::CommandId;
use rusqlite::Connection;

mod admission;
mod storage;
#[cfg(test)]
mod tests;
pub(super) use admission::admit;

pub(super) fn verify(conn: &Connection, request: &CommandRequest) -> Result<(), LedgerError> {
    if task_payload(request).map_err(store)?.is_some() {
        storage::run(conn, request)?;
    }
    Ok(())
}

impl CodingTaskStore for SqliteLedger {
    fn get_operator_coding(
        &self,
        operator: &str,
        id: &CommandId,
    ) -> Result<Option<CodingRunObservation>, OperatorCommandError> {
        let tx = ReadTransaction::begin(&self.conn)?;
        operator_commands::require_operator(&self.conn, operator)?;
        if operator_commands::owner(&self.conn, id)?.as_deref() != Some(operator) {
            tx.commit()?;
            return Ok(None);
        }
        let command = operator_commands::checked_record(&self.conn, id)?;
        let request =
            CommandRequest::from_json(&command.idempotency_key, &command.kind, &command.payload)
                .map_err(LedgerError::from)?;
        if task_payload(&request).map_err(LedgerError::from)?.is_none() {
            tx.commit()?;
            return Ok(None);
        }
        let run = storage::run(&self.conn, &request)?;
        if run.operator != operator || run.command != command {
            return Err(store("coding observation owner/command differs").into());
        }
        let observed_at: String = self
            .conn
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
                row.get(0)
            })
            .map_err(store)?;
        let now = chrono::DateTime::parse_from_rfc3339(&observed_at)
            .map_err(store)?
            .timestamp_millis();
        let mut blockers = vec![CodingQueueBlocker {
            code: "CODING_BINDING_ADMISSION_UNAVAILABLE".into(),
            subject: None,
        }];
        if run.task.contract.deadline_unix_ms <= u64::try_from(now).map_err(store)? {
            blockers.push(CodingQueueBlocker {
                code: "CODING_TASK_DEADLINE_EXPIRED".into(),
                subject: Some(run.task.revision_id.clone()),
            });
        }
        for dependency in &run.task.contract.dependencies {
            blockers.push(CodingQueueBlocker {
                code: "CODING_DEPENDENCY_EVIDENCE_UNAVAILABLE".into(),
                subject: Some(dependency.clone()),
            });
        }
        let observation = CodingRunObservation {
            command,
            run_id: run.run_id,
            task_revision_id: run.task.revision_id,
            task: run.task.contract,
            selection: run.selection,
            accepted_at: run.accepted_at,
            blockers,
            as_of_sequence: events::latest_sequence(&self.conn)?,
            observed_at,
        };
        tx.commit()?;
        Ok(Some(observation))
    }
}
