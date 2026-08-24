//! SQLite WAL ledger, split by table group. Migrations are embedded and
//! applied in order through a `schema_version` table.

mod commands;
mod effects;
mod events;
mod graph;
mod lease_time;
mod leases;
mod materialization;
mod migrations;
mod outbox;

use bullet_application::{
    ActiveLease, ActiveLeaseSubject, CommandRecord, CommandRequest, EffectIntentRecord,
    EffectReceiptRecord, EffectState, ExpiredLease, GraphDelta, HeartbeatRequest, LeaseGrant,
    LeaseRequest, Ledger, LedgerError, LedgerEvent, OutboxItem, ReadyRow, ReleaseRequest,
    StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, Candidate, CandidateId, CommandPhase, Effect, EffectId, Evidence,
    EvidenceId, Mission, MissionId, VariantId, WorkPackageId,
};
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

/// SQLite-backed ledger.
pub struct SqliteLedger {
    conn: Connection,
    materialization_fail_after: Option<u8>,
    graph_delta_fail_after: Option<u8>,
    lease_acquisition_fail_after: Option<u8>,
}

impl SqliteLedger {
    /// Open or create a database at `path` with enforced foreign keys, WAL,
    /// a busy timeout, and an exactly verified schema.
    ///
    /// # Errors
    ///
    /// Returns `UNSUPPORTED_SCHEMA` before mutating legacy or unrecognized
    /// pre-1.0 databases; other SQLite failures are store errors.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let mut conn = Connection::open(path.as_ref()).map_err(store)?;
        conn.busy_timeout(Duration::from_millis(5_000))
            .map_err(store)?;
        migrations::enable_foreign_keys(&conn)?;
        migrations::verify_or_initialize(&mut conn)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(store)?;
        Ok(Self {
            conn,
            materialization_fail_after: None,
            graph_delta_fail_after: None,
            lease_acquisition_fail_after: None,
        })
    }

    /// Inject a one-shot materialization failure after `allowed` successful
    /// transaction boundaries. Used by crash-atomicity integration tests.
    pub fn set_materialization_failpoint(&mut self, allowed: u8) {
        self.materialization_fail_after = Some(allowed);
    }

    /// Inject a one-shot graph-delta failure after `allowed` successful
    /// transaction boundaries. Used by crash-atomicity integration tests.
    pub fn set_graph_delta_failpoint(&mut self, allowed: u8) {
        self.graph_delta_fail_after = Some(allowed);
    }

    /// Inject a one-shot lease acquisition failure after `allowed` successful
    /// transaction boundaries. Used by crash-atomicity integration tests.
    pub fn set_lease_acquisition_failpoint(&mut self, allowed: u8) {
        self.lease_acquisition_fail_after = Some(allowed);
    }
}

pub(crate) fn store(err: impl ToString) -> LedgerError {
    LedgerError::Store(err.to_string())
}

pub(crate) fn json<T: serde::Serialize>(value: &T) -> Result<String, LedgerError> {
    serde_json::to_string(value).map_err(store)
}

pub(crate) fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, LedgerError> {
    serde_json::from_str(text).map_err(store)
}

impl Ledger for SqliteLedger {
    fn record_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError> {
        commands::record_command(&self.conn, request)
    }

    fn set_command_phase(
        &mut self,
        key: &str,
        phase: CommandPhase,
        response: Option<&str>,
    ) -> Result<(), LedgerError> {
        commands::set_phase(&self.conn, key, phase, response)
    }

    fn get_command(&self, key: &str) -> Result<Option<CommandRecord>, LedgerError> {
        commands::get_command(&self.conn, key)
    }

    fn get_command_by_id(
        &self,
        id: &bullet_domain::CommandId,
    ) -> Result<Option<CommandRecord>, LedgerError> {
        commands::get_command_by_id(&self.conn, id)
    }

    fn materialize_plan_command(
        &mut self,
        request: &CommandRequest,
        graph: &StoredGraph,
        now: &str,
    ) -> Result<StoredGraph, LedgerError> {
        materialization::materialize_plan_command(
            &mut self.conn,
            &mut self.materialization_fail_after,
            request,
            graph,
            now,
        )
    }

    fn materialize_graph(&mut self, graph: &StoredGraph, now: &str) -> Result<(), LedgerError> {
        graph::materialize_graph(&mut self.conn, graph, now)
    }

    fn put_graph(&mut self, graph: &StoredGraph) -> Result<(), LedgerError> {
        graph::put_graph(&self.conn, graph)
    }

    fn get_graph(&self, mission: &MissionId) -> Result<Option<StoredGraph>, LedgerError> {
        graph::get_graph(&self.conn, mission)
    }

    fn apply_graph_delta_command(
        &mut self,
        request: &CommandRequest,
        mission: &MissionId,
        delta: &GraphDelta,
    ) -> Result<StoredGraph, LedgerError> {
        graph::apply_graph_delta(
            &mut self.conn,
            &mut self.graph_delta_fail_after,
            request,
            mission,
            delta,
        )
    }

    fn list_missions(&self) -> Result<Vec<Mission>, LedgerError> {
        graph::list_missions(&self.conn)
    }

    fn acquire_lease(&mut self, request: &LeaseRequest) -> Result<LeaseGrant, LedgerError> {
        leases::acquire_lease(
            &mut self.conn,
            &mut self.lease_acquisition_fail_after,
            request,
        )
    }

    fn heartbeat(&mut self, request: &HeartbeatRequest) -> Result<(), LedgerError> {
        leases::heartbeat(&mut self.conn, request)
    }

    fn expire_leases(&mut self) -> Result<Vec<ExpiredLease>, LedgerError> {
        leases::expire_leases(&mut self.conn)
    }

    fn release_lease(&mut self, request: &ReleaseRequest) -> Result<(), LedgerError> {
        leases::release_lease(&mut self.conn, request)
    }

    fn get_lease(&self, variant: &VariantId) -> Result<Option<ActiveLease>, LedgerError> {
        leases::get_lease(&self.conn, variant)
    }

    fn check_active_lease(&mut self, subject: &ActiveLeaseSubject) -> Result<(), LedgerError> {
        leases::check_active_lease(&mut self.conn, subject)
    }

    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError> {
        graph::put_attempt(&mut self.conn, attempt)
    }

    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError> {
        graph::get_attempt(&self.conn, id)
    }

    fn active_attempt(&self, package: &WorkPackageId) -> Result<Option<Attempt>, LedgerError> {
        graph::active_attempt(&self.conn, package)
    }

    fn list_attempts(&self, mission: &MissionId) -> Result<Vec<Attempt>, LedgerError> {
        graph::list_attempts(&self.conn, mission)
    }

    fn put_candidate(&mut self, candidate: &Candidate) -> Result<bool, LedgerError> {
        graph::put_json_row(&self.conn, "candidates", candidate.id.as_str(), candidate)
    }

    fn get_candidate(&self, id: &CandidateId) -> Result<Option<Candidate>, LedgerError> {
        graph::get_json_row(&self.conn, "candidates", id.as_str())
    }

    fn put_evidence(&mut self, evidence: &Evidence) -> Result<bool, LedgerError> {
        graph::put_json_row(&self.conn, "evidence", evidence.id.as_str(), evidence)
    }

    fn get_evidence(&self, id: &EvidenceId) -> Result<Option<Evidence>, LedgerError> {
        graph::get_json_row(&self.conn, "evidence", id.as_str())
    }

    fn put_effect(&mut self, effect: &Effect) -> Result<bool, LedgerError> {
        graph::put_json_row(&self.conn, "effects", effect.id.as_str(), effect)
    }

    fn get_effect(&self, id: &EffectId) -> Result<Option<Effect>, LedgerError> {
        graph::get_json_row(&self.conn, "effects", id.as_str())
    }

    fn append_event(&mut self, kind: &str, body: &str) -> Result<(), LedgerError> {
        events::insert_event(&self.conn, kind, body, None, None, None)
    }

    fn list_events(&self) -> Result<Vec<LedgerEvent>, LedgerError> {
        events::list_events(&self.conn)
    }

    fn list_events_after(&self, after: u64, limit: usize) -> Result<Vec<LedgerEvent>, LedgerError> {
        events::list_events_after(&self.conn, after, limit)
    }

    fn latest_event_sequence(&self) -> Result<u64, LedgerError> {
        events::latest_sequence(&self.conn)
    }

    fn ready_rows(&self) -> Result<Vec<ReadyRow>, LedgerError> {
        leases::ready_rows(&self.conn)
    }

    fn enqueue_ready(&mut self, package: &WorkPackageId, now: &str) -> Result<(), LedgerError> {
        leases::enqueue_ready(&self.conn, package, now)
    }

    fn outbox_enqueue(&mut self, kind: &str, payload: &str) -> Result<u64, LedgerError> {
        outbox::enqueue(&self.conn, None, kind, payload)
    }

    fn outbox_pending(&self) -> Result<Vec<OutboxItem>, LedgerError> {
        outbox::pending(&self.conn)
    }

    fn outbox_all(&self) -> Result<Vec<OutboxItem>, LedgerError> {
        outbox::all(&self.conn)
    }

    fn outbox_for_command(
        &self,
        command: &bullet_domain::CommandId,
    ) -> Result<Vec<OutboxItem>, LedgerError> {
        outbox::for_command(&self.conn, command)
    }

    fn outbox_mark(&mut self, seq: u64, phase: CommandPhase, now: &str) -> Result<(), LedgerError> {
        outbox::mark(&self.conn, seq, phase, now)
    }

    fn record_effect_intent(
        &mut self,
        intent: &EffectIntentRecord,
    ) -> Result<(EffectIntentRecord, bool), LedgerError> {
        effects::record_effect_intent(&mut self.conn, intent)
    }

    fn get_effect_intent(
        &self,
        provider: &str,
        logical_key: &str,
    ) -> Result<Option<EffectIntentRecord>, LedgerError> {
        effects::get_effect_intent(&self.conn, provider, logical_key)
    }

    fn get_effect_intent_by_id(
        &self,
        id: &EffectId,
    ) -> Result<Option<EffectIntentRecord>, LedgerError> {
        effects::get_effect_intent_by_id(&self.conn, id)
    }

    fn transition_effect(
        &mut self,
        id: &EffectId,
        to: EffectState,
    ) -> Result<EffectIntentRecord, LedgerError> {
        effects::transition_effect(&mut self.conn, id, to)
    }

    fn record_effect_receipt(
        &mut self,
        receipt: &EffectReceiptRecord,
    ) -> Result<bool, LedgerError> {
        effects::record_effect_receipt(&mut self.conn, receipt)
    }

    fn effect_receipts(&self, intent: &EffectId) -> Result<Vec<EffectReceiptRecord>, LedgerError> {
        effects::effect_receipts(&self.conn, intent)
    }

    fn unresolved_effects(&self) -> Result<Vec<EffectIntentRecord>, LedgerError> {
        effects::unresolved_effects(&self.conn)
    }
}
