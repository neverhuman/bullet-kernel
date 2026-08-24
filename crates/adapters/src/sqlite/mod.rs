//! SQLite WAL ledger, split by table group. Migrations are embedded and
//! applied in order through a `schema_version` table.

mod commands;
mod events;
mod graph;
mod leases;
mod outbox;

use bullet_application::{
    ActiveLease, CommandRecord, CommandRequest, ExpiredLease, HeartbeatRequest, LeaseGrant,
    LeaseRequest, Ledger, LedgerError, LedgerEvent, OutboxItem, ReadyRow, ReleaseRequest,
    StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, Candidate, CandidateId, CommandPhase, Effect, EffectId, Evidence,
    EvidenceId, Mission, MissionId, VariantId, WorkPackageId,
};
use rusqlite::{params, Connection};
use std::path::Path;
use std::time::Duration;

const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_ledger.sql",
        include_str!("../../../../db/migrations/0001_ledger.sql"),
    ),
    (
        "0002_authority.sql",
        include_str!("../../../../db/migrations/0002_authority.sql"),
    ),
];

/// SQLite-backed ledger.
pub struct SqliteLedger {
    conn: Connection,
}

impl SqliteLedger {
    /// Open or create a database at `path` with WAL, a busy timeout, and all
    /// migrations applied.
    ///
    /// # Errors
    ///
    /// Returns a store error when SQLite cannot open or migrate.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let mut conn = Connection::open(path.as_ref()).map_err(store)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(store)?;
        conn.busy_timeout(Duration::from_millis(5_000))
            .map_err(store)?;
        migrate(&mut conn)?;
        Ok(Self { conn })
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

fn migrate(conn: &mut Connection) -> Result<(), LedgerError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_at TEXT NOT NULL
         );",
    )
    .map_err(store)?;
    for (idx, (name, sql)) in MIGRATIONS.iter().enumerate() {
        let version = i64::try_from(idx).map_err(store)? + 1;
        let applied: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_version WHERE version = ?1)",
                params![version],
                |row| row.get(0),
            )
            .map_err(store)?;
        if applied {
            continue;
        }
        let tx = conn.transaction().map_err(store)?;
        tx.execute_batch(sql).map_err(store)?;
        tx.execute(
            "INSERT INTO schema_version (version, name, applied_at)
             VALUES (?1, ?2, datetime('now'))",
            params![version, name],
        )
        .map_err(store)?;
        tx.commit().map_err(store)?;
    }
    Ok(())
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

    fn materialize_graph(&mut self, graph: &StoredGraph, now: &str) -> Result<(), LedgerError> {
        graph::materialize_graph(&mut self.conn, graph, now)
    }

    fn put_graph(&mut self, graph: &StoredGraph) -> Result<(), LedgerError> {
        graph::put_graph(&self.conn, graph)
    }

    fn get_graph(&self, mission: &MissionId) -> Result<Option<StoredGraph>, LedgerError> {
        graph::get_graph(&self.conn, mission)
    }

    fn list_missions(&self) -> Result<Vec<Mission>, LedgerError> {
        graph::list_missions(&self.conn)
    }

    fn acquire_lease(&mut self, request: &LeaseRequest) -> Result<LeaseGrant, LedgerError> {
        leases::acquire_lease(&mut self.conn, request)
    }

    fn heartbeat(&mut self, request: &HeartbeatRequest) -> Result<(), LedgerError> {
        leases::heartbeat(&self.conn, request)
    }

    fn expire_leases(&mut self, now: &str) -> Result<Vec<ExpiredLease>, LedgerError> {
        leases::expire_leases(&mut self.conn, now)
    }

    fn release_lease(&mut self, request: &ReleaseRequest) -> Result<(), LedgerError> {
        leases::release_lease(&mut self.conn, request)
    }

    fn get_lease(&self, variant: &VariantId) -> Result<Option<ActiveLease>, LedgerError> {
        leases::get_lease(&self.conn, variant)
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

    fn ready_rows(&self) -> Result<Vec<ReadyRow>, LedgerError> {
        leases::ready_rows(&self.conn)
    }

    fn enqueue_ready(&mut self, package: &WorkPackageId, now: &str) -> Result<(), LedgerError> {
        leases::enqueue_ready(&self.conn, package, now)
    }

    fn outbox_enqueue(&mut self, kind: &str, payload: &str) -> Result<u64, LedgerError> {
        outbox::enqueue(&self.conn, kind, payload)
    }

    fn outbox_pending(&self) -> Result<Vec<OutboxItem>, LedgerError> {
        outbox::pending(&self.conn)
    }

    fn outbox_all(&self) -> Result<Vec<OutboxItem>, LedgerError> {
        outbox::all(&self.conn)
    }

    fn outbox_mark(&mut self, seq: u64, phase: CommandPhase, now: &str) -> Result<(), LedgerError> {
        outbox::mark(&self.conn, seq, phase, now)
    }
}
