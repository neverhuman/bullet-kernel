//! In-process ledger for tests and the first-slice demo.

use crate::commands::{CommandRecord, CommandRequest};
use crate::store::{Ledger, LedgerError, StoredGraph};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, Candidate, CommandId, CommandPhase, DomainError, Effect,
    Evidence, Mission, MissionId, WorkPackageId,
};
use std::collections::BTreeMap;

/// Memory ledger.
#[derive(Default)]
pub struct MemoryLedger {
    commands: BTreeMap<String, CommandRecord>,
    graphs: BTreeMap<String, StoredGraph>,
    attempts: BTreeMap<String, Attempt>,
    candidates: BTreeMap<String, Candidate>,
    evidence: Vec<Evidence>,
    effects: Vec<Effect>,
    events: Vec<(String, String)>,
}

impl MemoryLedger {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Ledger for MemoryLedger {
    fn record_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError> {
        if let Some(existing) = self.commands.get(&request.idempotency_key) {
            if existing.payload_digest != request.digest() {
                return Err(DomainError::Idempotency(request.idempotency_key.clone()).into());
            }
            return Ok(existing.clone());
        }
        let record = CommandRecord {
            id: CommandId::from_seed(&request.idempotency_key),
            idempotency_key: request.idempotency_key.clone(),
            kind: request.kind.clone(),
            payload: request.payload.clone(),
            payload_digest: request.digest(),
            phase: CommandPhase::Applied,
        };
        self.commands
            .insert(request.idempotency_key.clone(), record.clone());
        Ok(record)
    }

    fn put_graph(&mut self, graph: &StoredGraph) -> Result<(), LedgerError> {
        self.graphs
            .insert(graph.mission.id.to_string(), graph.clone());
        Ok(())
    }

    fn get_graph(&self, mission: &MissionId) -> Result<Option<StoredGraph>, LedgerError> {
        Ok(self.graphs.get(&mission.to_string()).cloned())
    }

    fn list_missions(&self) -> Result<Vec<Mission>, LedgerError> {
        Ok(self.graphs.values().map(|g| g.mission.clone()).collect())
    }

    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError> {
        self.attempts
            .insert(attempt.id.to_string(), attempt.clone());
        Ok(())
    }

    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError> {
        Ok(self.attempts.get(&id.to_string()).cloned())
    }

    fn active_attempt(&self, package: &WorkPackageId) -> Result<Option<Attempt>, LedgerError> {
        Ok(self
            .attempts
            .values()
            .find(|a| {
                a.state.may_mutate()
                    && self.graphs.values().any(|g| {
                        g.packages.iter().any(|p| p.id == *package)
                            && g.variants.iter().any(|v| v.id == a.variant_id)
                    })
            })
            .cloned())
    }

    fn put_candidate(&mut self, candidate: &Candidate) -> Result<(), LedgerError> {
        self.candidates
            .insert(candidate.id.to_string(), candidate.clone());
        Ok(())
    }

    fn put_evidence(&mut self, evidence: &Evidence) -> Result<(), LedgerError> {
        self.evidence.push(evidence.clone());
        Ok(())
    }

    fn put_effect(&mut self, effect: &Effect) -> Result<(), LedgerError> {
        self.effects.push(effect.clone());
        Ok(())
    }

    fn append_event(&mut self, kind: &str, body: &str) -> Result<(), LedgerError> {
        self.events.push((kind.to_string(), body.to_string()));
        Ok(())
    }

    fn pending_outbox(&self) -> Result<Vec<CommandRecord>, LedgerError> {
        Ok(self
            .commands
            .values()
            .filter(|c| c.phase != CommandPhase::Verified)
            .cloned()
            .collect())
    }

    fn list_events(&self) -> Result<Vec<crate::store::LedgerEvent>, LedgerError> {
        Ok(self
            .events
            .iter()
            .enumerate()
            .map(|(idx, (kind, body))| crate::store::LedgerEvent {
                seq: (idx as u64) + 1,
                kind: kind.clone(),
                body: body.clone(),
            })
            .collect())
    }

    fn list_attempts(&self, mission: &MissionId) -> Result<Vec<Attempt>, LedgerError> {
        let Some(graph) = self.get_graph(mission)? else {
            return Ok(Vec::new());
        };
        let variants: Vec<_> = graph
            .variants
            .iter()
            .map(|variant| variant.id.clone())
            .collect();
        Ok(self
            .attempts
            .values()
            .filter(|attempt| variants.contains(&attempt.variant_id))
            .cloned()
            .collect())
    }
}

impl MemoryLedger {
    /// Mark an attempt stale. Used when a successor is created.
    pub fn mark_stale(&mut self, id: &AttemptId) -> Result<(), LedgerError> {
        if let Some(attempt) = self.attempts.get_mut(&id.to_string()) {
            attempt.state = AttemptState::Stale;
        }
        Ok(())
    }
}
