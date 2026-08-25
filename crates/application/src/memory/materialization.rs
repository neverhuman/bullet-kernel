//! Snapshot-atomic Mission materialization for the memory ledger.

use super::MemoryLedger;
use crate::commands::CommandRequest;
use crate::materializer::MaterializeCommandResult;
use crate::records::StoredGraph;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{CommandPhase, DomainError, WorkPackageState};

impl MemoryLedger {
    pub(super) fn materialize_plan_command_impl(
        &mut self,
        request: &CommandRequest,
        graph: &StoredGraph,
        now: &str,
    ) -> Result<StoredGraph, LedgerError> {
        let before = self.clone();
        let transaction = (|| -> Result<StoredGraph, LedgerError> {
            let record = self.record_command(request)?;
            match record.phase {
                CommandPhase::Applied | CommandPhase::Verified => {
                    let response = record.response.ok_or_else(|| {
                        LedgerError::Store(
                            "applied materialization command has no stored result".into(),
                        )
                    })?;
                    let graph = MaterializeCommandResult::decode(&response)?.graph_for(graph)?;
                    self.require_initial_contexts(&graph)?;
                    return Ok(graph);
                }
                CommandPhase::Failed | CommandPhase::Unknown => {
                    return Err(LedgerError::Store(format!(
                        "materialization command is {}",
                        record.phase.as_str()
                    )));
                }
                CommandPhase::Pending => {
                    if record.response.is_some() {
                        return Err(LedgerError::Store(
                            "pending materialization command has a stored result".into(),
                        ));
                    }
                }
            }

            let key = graph.mission.id.to_string();
            if self.graphs.contains_key(&key) {
                return Err(
                    DomainError::Conflict(format!("graph {key} already materialized")).into(),
                );
            }
            let response = MaterializeCommandResult::applied(graph)?;

            self.tick()?;
            self.graphs.insert(key.clone(), graph.clone());
            self.tick()?;
            self.insert_initial_contexts(graph, now)?;
            for variant in &graph.variants {
                self.tick()?;
                self.fences.entry(variant.id.to_string()).or_insert(0);
            }
            for package in &graph.packages {
                if package.state == WorkPackageState::Ready {
                    self.tick()?;
                    self.ready
                        .entry(package.id.to_string())
                        .or_insert_with(|| now.to_string());
                }
            }
            self.tick()?;
            self.push_event(
                "graph_materialized",
                graph.mission.id.as_str(),
                Some(key),
                Some(request.idempotency_key.clone()),
                None,
            );
            self.tick()?;
            let command = self
                .commands
                .get_mut(&request.idempotency_key)
                .ok_or_else(|| LedgerError::Store("materialization command missing".into()))?;
            command.phase = CommandPhase::Applied;
            command.response = Some(response);
            self.tick()?;
            Ok(graph.clone())
        })();

        let outcome = match transaction {
            Ok(outcome) => outcome,
            Err(error) => {
                let failpoint = self.fail_after_writes;
                *self = before;
                self.fail_after_writes = failpoint;
                return Err(error);
            }
        };
        self.tick()?;
        Ok(outcome)
    }
}
