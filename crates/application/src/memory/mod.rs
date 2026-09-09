//! In-process ledger for tests and the first-slice demo. Behavioral parity
//! with the SQLite adapter is enforced by the shared conformance suite.

mod authority;
mod clock;
mod commands;
mod context;
mod effects;
mod launch_grant;
mod materialization;
mod projections;

use crate::authority::ActiveLeaseSubject;
use crate::authority_revision::NormalizedAuthority;
use crate::commands::{CommandRecord, CommandRequest};
use crate::effect_state::EffectState;
use crate::effects::{EffectIntentRecord, EffectReceiptRecord};
use crate::graph_delta::{evaluate_graph_delta, GraphDelta, GraphDeltaCommandResult};
use crate::launch_grant::StoredLaunchGrantNonce;
use crate::records::{
    ActiveLease, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerEvent, OutboxItem,
    ReadyRow, ReleaseRequest, StoredGraph,
};
use crate::store::{incarnation_subject, CurrentPackage, LeaseTransportTxn, Ledger, LedgerError};
use crate::ContextCapsule;
use bullet_domain::{
    Attempt, AttemptId, Candidate, CandidateId, CommandId, CommandPhase, DomainError, Effect,
    EffectId, Evidence, EvidenceId, Mission, MissionId, VariantId, WorkPackageId,
};
use bullet_harness_core::launch_grant::NonceConsumption;
use std::collections::BTreeMap;

/// Memory ledger.
#[derive(Clone, Default)]
pub struct MemoryLedger {
    commands: BTreeMap<String, CommandRecord>,
    context_capsules: BTreeMap<String, ContextCapsule>,
    graphs: BTreeMap<String, StoredGraph>,
    attempts: BTreeMap<String, Attempt>,
    candidates: BTreeMap<String, Candidate>,
    evidence: BTreeMap<String, Evidence>,
    effects: BTreeMap<String, Effect>,
    events: Vec<LedgerEvent>,
    leases: BTreeMap<String, ActiveLease>,
    fences: BTreeMap<String, u64>,
    ready: BTreeMap<String, String>,
    outbox: Vec<OutboxItem>,
    effect_intents: BTreeMap<String, EffectIntentRecord>,
    effect_keys: BTreeMap<String, String>,
    effect_receipts: Vec<EffectReceiptRecord>,
    launch_grant_nonces: BTreeMap<String, StoredLaunchGrantNonce>,
    lease_transport_grants: BTreeMap<String, String>,
    lease_transport_settlements: BTreeMap<String, String>,
    lease_transport_nonces: BTreeMap<String, MemoryTransportNonce>,
    authority: Option<NormalizedAuthority>,
    fail_after_writes: Option<u32>,
    simulation_clock_millis: i64,
}

#[derive(Clone, Debug)]
struct MemoryTransportNonce {
    binding: String,
    expires_at_unix_ms: u64,
    consumed: bool,
}

include!("support.rs");

impl Ledger for MemoryLedger {
    fn record_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError> {
        self.record_command_impl(request)
    }

    fn submit_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError> {
        self.submit_command_impl(request)
    }

    fn reconcile_offline_command(
        &mut self,
        id: &CommandId,
        now: &str,
    ) -> Result<CommandRecord, LedgerError> {
        self.reconcile_offline_command_impl(id, now)
    }

    fn set_command_phase(
        &mut self,
        key: &str,
        phase: CommandPhase,
        response: Option<&str>,
    ) -> Result<(), LedgerError> {
        self.set_command_phase_impl(key, phase, response)
    }

    fn get_command(&self, key: &str) -> Result<Option<CommandRecord>, LedgerError> {
        self.get_command_impl(key)
    }

    fn get_command_by_id(&self, id: &CommandId) -> Result<Option<CommandRecord>, LedgerError> {
        self.get_command_by_id_impl(id)
    }

    fn materialize_plan_command(
        &mut self,
        request: &CommandRequest,
        graph: &StoredGraph,
        now: &str,
    ) -> Result<StoredGraph, LedgerError> {
        self.materialize_plan_command_impl(request, graph, now)
    }

    fn materialize_graph(&mut self, graph: &StoredGraph, now: &str) -> Result<(), LedgerError> {
        self.materialize_graph_impl(graph, now)
    }

    fn put_graph(&mut self, graph: &StoredGraph) -> Result<(), LedgerError> {
        self.tick()?;
        let key = graph.mission.id.to_string();
        if !self.graphs.contains_key(&key) {
            return Err(LedgerError::Store(format!(
                "graph {key} was never materialized"
            )));
        }
        self.graphs.insert(key, graph.clone());
        Ok(())
    }

    fn get_graph(&self, mission: &MissionId) -> Result<Option<StoredGraph>, LedgerError> {
        Ok(self.graphs.get(&mission.to_string()).cloned())
    }

    fn apply_graph_delta_command(
        &mut self,
        request: &CommandRequest,
        mission: &MissionId,
        delta: &GraphDelta,
    ) -> Result<StoredGraph, LedgerError> {
        let before = self.clone();
        let transaction = (|| -> Result<Result<StoredGraph, LedgerError>, LedgerError> {
            let record = self.record_command(request)?;
            match record.phase {
                CommandPhase::Applied | CommandPhase::Verified => {
                    let response = record.response.ok_or_else(|| {
                        LedgerError::Store("applied delta command has no stored result".into())
                    })?;
                    return match GraphDeltaCommandResult::decode(&response)? {
                        GraphDeltaCommandResult::Applied { graph }
                            if graph.mission.id == *mission =>
                        {
                            Ok(Ok(*graph))
                        }
                        GraphDeltaCommandResult::Applied { .. } => Err(LedgerError::Store(
                            "applied delta result belongs to another mission".into(),
                        )),
                        GraphDeltaCommandResult::Failed { .. } => Err(LedgerError::Store(
                            "applied delta command stores a failed result".into(),
                        )),
                    };
                }
                CommandPhase::Failed => {
                    let response = record.response.ok_or_else(|| {
                        LedgerError::Store("failed delta command has no stored result".into())
                    })?;
                    return match GraphDeltaCommandResult::decode(&response)? {
                        GraphDeltaCommandResult::Failed { error } => Ok(Err(error.into_error())),
                        GraphDeltaCommandResult::Applied { .. } => Err(LedgerError::Store(
                            "failed delta command stores an applied result".into(),
                        )),
                    };
                }
                CommandPhase::Pending | CommandPhase::Unknown => {}
            }

            let graph = self
                .get_graph(mission)?
                .ok_or_else(|| LedgerError::Store("graph missing".into()));
            let next = match graph.and_then(|graph| evaluate_graph_delta(&graph, delta)) {
                Ok(next) => next,
                Err(error) => {
                    let response = GraphDeltaCommandResult::failed(&error)?;
                    self.tick()?;
                    let command = self
                        .commands
                        .get_mut(&request.idempotency_key)
                        .ok_or_else(|| LedgerError::Store("delta command missing".into()))?;
                    command.phase = CommandPhase::Failed;
                    command.response = Some(response);
                    self.tick()?;
                    return Ok(Err(error));
                }
            };

            let response = GraphDeltaCommandResult::applied(&next)?;
            let event_body = delta.digest()?.to_hex();
            self.tick()?;
            self.graphs.insert(mission.to_string(), next.clone());
            self.tick()?;
            self.push_event("graph_delta", &event_body, None, None, None);
            self.tick()?;
            let command = self
                .commands
                .get_mut(&request.idempotency_key)
                .ok_or_else(|| LedgerError::Store("delta command missing".into()))?;
            command.phase = CommandPhase::Applied;
            command.response = Some(response);
            self.tick()?;
            Ok(Ok(next))
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
        outcome
    }

    fn list_missions(&self) -> Result<Vec<Mission>, LedgerError> {
        Ok(self.graphs.values().map(|g| g.mission.clone()).collect())
    }

    fn acquire_lease(&mut self, request: &LeaseRequest) -> Result<LeaseGrant, LedgerError> {
        self.acquire_lease_impl(request)
    }

    fn heartbeat(&mut self, request: &HeartbeatRequest) -> Result<(), LedgerError> {
        self.heartbeat_impl(request)
    }

    fn expire_leases(&mut self) -> Result<Vec<ExpiredLease>, LedgerError> {
        self.expire_leases_impl()
    }

    fn release_lease(&mut self, request: &ReleaseRequest) -> Result<(), LedgerError> {
        self.release_lease_impl(request)
    }

    fn get_lease(&self, variant: &VariantId) -> Result<Option<ActiveLease>, LedgerError> {
        Ok(self.leases.get(&variant.to_string()).cloned())
    }

    fn check_active_lease(&mut self, subject: &ActiveLeaseSubject) -> Result<(), LedgerError> {
        self.check_active_lease_impl(subject)
    }

    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError> {
        self.put_attempt_impl(attempt)
    }

    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError> {
        Ok(self.attempts.get(&id.to_string()).cloned())
    }

    fn active_attempt(&self, package: &WorkPackageId) -> Result<Option<Attempt>, LedgerError> {
        Ok(self
            .attempts
            .values()
            .find(|attempt| {
                attempt.work_package_id == *package
                    && attempt.state.appears_in_active_attempt_projection()
            })
            .cloned())
    }

    fn list_attempts(&self, mission: &MissionId) -> Result<Vec<Attempt>, LedgerError> {
        let Some(graph) = self.graphs.get(&mission.to_string()) else {
            return Ok(Vec::new());
        };
        Ok(self
            .attempts
            .values()
            .filter(|attempt| {
                graph
                    .variants
                    .iter()
                    .any(|variant| variant.id == attempt.variant_id)
            })
            .cloned()
            .collect())
    }

    fn put_candidate(&mut self, candidate: &Candidate) -> Result<bool, LedgerError> {
        self.tick()?;
        append_only(
            &mut self.candidates,
            candidate.id.to_string(),
            candidate,
            "candidate",
        )
    }

    fn get_candidate(&self, id: &CandidateId) -> Result<Option<Candidate>, LedgerError> {
        Ok(self.candidates.get(&id.to_string()).cloned())
    }

    fn put_evidence(&mut self, evidence: &Evidence) -> Result<bool, LedgerError> {
        self.tick()?;
        append_only(
            &mut self.evidence,
            evidence.id.to_string(),
            evidence,
            "evidence",
        )
    }

    fn get_evidence(&self, id: &EvidenceId) -> Result<Option<Evidence>, LedgerError> {
        Ok(self.evidence.get(&id.to_string()).cloned())
    }

    fn put_effect(&mut self, effect: &Effect) -> Result<bool, LedgerError> {
        self.tick()?;
        append_only(&mut self.effects, effect.id.to_string(), effect, "effect")
    }

    fn get_effect(&self, id: &EffectId) -> Result<Option<Effect>, LedgerError> {
        Ok(self.effects.get(&id.to_string()).cloned())
    }

    fn append_event(&mut self, kind: &str, body: &str) -> Result<(), LedgerError> {
        self.tick()?;
        self.push_event(kind, body, None, None, None);
        Ok(())
    }

    fn list_events(&self) -> Result<Vec<LedgerEvent>, LedgerError> {
        Ok(self.events.clone())
    }

    fn list_events_after(&self, after: u64, limit: usize) -> Result<Vec<LedgerEvent>, LedgerError> {
        Ok(self
            .events
            .iter()
            .filter(|event| event.seq > after)
            .take(limit)
            .cloned()
            .collect())
    }

    fn latest_event_sequence(&self) -> Result<u64, LedgerError> {
        Ok(self.events.last().map_or(0, |event| event.seq))
    }

    fn ready_rows(&self) -> Result<Vec<ReadyRow>, LedgerError> {
        let mut out = Vec::new();
        for (key, enqueued_at) in &self.ready {
            out.push(ReadyRow {
                work_package_id: WorkPackageId::parse(key)?,
                enqueued_at: enqueued_at.clone(),
            });
        }
        Ok(out)
    }

    fn enqueue_ready(&mut self, package: &WorkPackageId, now: &str) -> Result<(), LedgerError> {
        self.tick()?;
        self.ready
            .entry(package.to_string())
            .or_insert_with(|| now.to_string());
        Ok(())
    }

    fn outbox_enqueue(&mut self, kind: &str, payload: &str) -> Result<u64, LedgerError> {
        self.outbox_enqueue_impl(None, kind, payload)
    }

    fn outbox_pending(&self) -> Result<Vec<OutboxItem>, LedgerError> {
        Ok(self
            .outbox
            .iter()
            .filter(|item| matches!(item.phase, CommandPhase::Pending | CommandPhase::Applied))
            .cloned()
            .collect())
    }

    fn outbox_all(&self) -> Result<Vec<OutboxItem>, LedgerError> {
        Ok(self.outbox.clone())
    }

    fn outbox_for_command(&self, command: &CommandId) -> Result<Vec<OutboxItem>, LedgerError> {
        Ok(self
            .outbox
            .iter()
            .filter(|item| item.command_id.as_ref() == Some(command))
            .cloned()
            .collect())
    }

    fn outbox_mark(&mut self, seq: u64, phase: CommandPhase, now: &str) -> Result<(), LedgerError> {
        self.tick()?;
        let item = self
            .outbox
            .iter_mut()
            .find(|item| item.seq == seq)
            .ok_or_else(|| LedgerError::Store(format!("unknown outbox seq {seq}")))?;
        item.phase = phase;
        match phase {
            CommandPhase::Applied => item.delivered_at = Some(now.to_string()),
            CommandPhase::Verified | CommandPhase::Failed | CommandPhase::Unknown => {
                item.acked_at = Some(now.to_string());
            }
            CommandPhase::Pending => {}
        }
        Ok(())
    }

    fn record_effect_intent(
        &mut self,
        intent: &EffectIntentRecord,
    ) -> Result<(EffectIntentRecord, bool), LedgerError> {
        self.record_effect_intent_impl(intent)
    }

    fn get_effect_intent(
        &self,
        provider: &str,
        logical_key: &str,
    ) -> Result<Option<EffectIntentRecord>, LedgerError> {
        self.get_effect_intent_impl(provider, logical_key)
    }

    fn get_effect_intent_by_id(
        &self,
        id: &EffectId,
    ) -> Result<Option<EffectIntentRecord>, LedgerError> {
        Ok(self.effect_intents.get(id.as_str()).cloned())
    }

    fn transition_effect(
        &mut self,
        id: &EffectId,
        to: EffectState,
    ) -> Result<EffectIntentRecord, LedgerError> {
        self.transition_effect_impl(id, to)
    }

    fn record_effect_receipt(
        &mut self,
        receipt: &EffectReceiptRecord,
    ) -> Result<bool, LedgerError> {
        self.record_effect_receipt_impl(receipt)
    }

    fn effect_receipts(&self, intent: &EffectId) -> Result<Vec<EffectReceiptRecord>, LedgerError> {
        self.effect_receipts_impl(intent)
    }

    fn current_authority(&self) -> Result<NormalizedAuthority, LedgerError> {
        Ok(self
            .authority
            .clone()
            .unwrap_or_else(NormalizedAuthority::genesis))
    }

    fn unresolved_effects(&self) -> Result<Vec<EffectIntentRecord>, LedgerError> {
        self.unresolved_effects_impl()
    }

    fn with_lease_transport<T, E, F>(&mut self, f: F) -> Result<T, E>
    where
        Self: Sized,
        F: FnOnce(&mut dyn LeaseTransportTxn) -> Result<T, E>,
        E: From<LedgerError>,
    {
        self.tick().map_err(E::from)?;
        let mut copy = self.clone();
        let result = f(&mut copy)?;
        *self = copy;
        Ok(result)
    }
}

include!("lease_transport.rs");
