//! SQLite WAL ledger with ordered, embedded `schema_version` migrations.

mod authority;
mod authority_scope;
mod backup;
mod candidate_preparation;
mod coding_tasks;
mod command_dispatch;
mod commands;
mod context;
mod effect_recovery;
mod effects;
mod events;
mod graph;
mod launch_grants;
mod lease_time;
mod lease_transport;
mod leases;
mod materialization;
mod migrations;
pub mod mutation_authority;
mod mutation_authority_presentation;
mod nonces;
mod open;
mod operator_commands;
mod operator_sessions;
mod outbox;
mod projections;

use bullet_application::launch_grant::{
    LaunchGrantNonceRecord, LaunchGrantNonceStore, NonceConsumption, StoredLaunchGrantNonce,
};
use bullet_application::store::LeaseTransportTxn;
use bullet_application::{
    ActiveLease, ActiveLeaseSubject, CommandRecord, CommandRequest, EffectIntentRecord,
    EffectReceiptRecord, EffectState, ExpiredLease, GraphDelta, HeartbeatRequest, IssuedNonce,
    LeaseGrant, LeaseRequest, Ledger, LedgerError, LedgerEvent, NonceError, NonceLedger,
    NonceState, NormalizedAuthority, OutboxItem, ReadyRow, ReleaseRequest, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, Candidate, CandidateId, CommandPhase, Effect, EffectId, Evidence,
    EvidenceId, Mission, MissionId, VariantId, WorkPackageId,
};
use rusqlite::Connection;
use std::path::Path;

pub use backup::{
    create_backup, restore_backup, BackupReceipt, RestoreReceipt, SqliteMaintenanceError,
};

struct ReadTransaction<'a> {
    conn: &'a Connection,
    active: bool,
}

impl<'a> ReadTransaction<'a> {
    fn begin(conn: &'a Connection) -> Result<Self, LedgerError> {
        conn.execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(store)?;
        Ok(Self { conn, active: true })
    }

    fn commit(mut self) -> Result<(), LedgerError> {
        self.conn.execute_batch("COMMIT").map_err(store)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ReadTransaction<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

/// SQLite-backed ledger.
pub struct SqliteLedger {
    conn: Connection,
    _database_guard: open::AdmissionGuard,
    materialization_fail_after: Option<u8>,
    graph_delta_fail_after: Option<u8>,
    lease_acquisition_fail_after: Option<u8>,
    command_submission_fail_after: Option<u8>,
    command_reconciliation_fail_after: Option<u8>,
    candidate_preparation_fail_after: Option<u8>,
    authority_scope_fail_after: Option<u8>,
    command_dispatch_claim_fail_after: Option<u8>,
    command_dispatch_settlement_fail_after: Option<u8>,
    effect_recovery_claim_fail_after: Option<u8>,
    effect_recovery_apply_fail_after: Option<u8>,
    lease_transport_settlement_fail_after: Option<u8>,
}

impl SqliteLedger {
    /// Checkpoint and close a ledger after its owner has stopped every other writer.
    ///
    /// This prepares a sidecar-free main file for immutable component receipt reads;
    /// it does not establish maintenance custody or authorize a backup/restore.
    /// # Errors
    /// Refuses a busy checkpoint, failed close, substituted path, or remaining sidecar.
    pub fn close_quiescent(self) -> Result<(), LedgerError> {
        open::close_quiescent(open::AdmittedConnection {
            connection: self.conn,
            guard: self._database_guard,
        })
    }

    /// Open or create a database with foreign keys, WAL, bounded waits, and exact schema.
    /// # Errors
    /// Returns `UNSUPPORTED_SCHEMA` before mutating legacy or unrecognized databases.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let admitted = open::initialized(path.as_ref())?;
        let open::AdmittedConnection { connection, guard } = admitted;
        Ok(Self {
            conn: connection,
            _database_guard: guard,
            materialization_fail_after: None,
            graph_delta_fail_after: None,
            lease_acquisition_fail_after: None,
            command_submission_fail_after: None,
            command_reconciliation_fail_after: None,
            candidate_preparation_fail_after: None,
            authority_scope_fail_after: None,
            command_dispatch_claim_fail_after: None,
            command_dispatch_settlement_fail_after: None,
            effect_recovery_claim_fail_after: None,
            effect_recovery_apply_fail_after: None,
            lease_transport_settlement_fail_after: None,
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

    /// Inject a one-shot public-command transaction failure after `allowed`
    /// internal boundaries. Used only by crash-atomicity integration tests.
    pub fn set_command_submission_failpoint(&mut self, allowed: u8) {
        self.command_submission_fail_after = Some(allowed);
    }

    /// Inject a one-shot command-reconciliation transaction failure after
    /// `allowed` internal boundaries. Used only by crash-atomicity tests.
    pub fn set_command_reconciliation_failpoint(&mut self, allowed: u8) {
        self.command_reconciliation_fail_after = Some(allowed);
    }

    /// Inject a one-shot durable dispatch-claim failure.
    pub fn set_command_dispatch_claim_failpoint(&mut self, allowed: u8) {
        self.command_dispatch_claim_fail_after = Some(allowed);
    }

    /// Inject a one-shot component-settlement failure.
    pub fn set_command_dispatch_settlement_failpoint(&mut self, allowed: u8) {
        self.command_dispatch_settlement_fail_after = Some(allowed);
    }

    /// Inject a one-shot durable effect-recovery claim failure.
    pub fn set_effect_recovery_claim_failpoint(&mut self, allowed: u8) {
        self.effect_recovery_claim_fail_after = Some(allowed);
    }

    /// Inject a one-shot effect-recovery transition failure.
    pub fn set_effect_recovery_apply_failpoint(&mut self, allowed: u8) {
        self.effect_recovery_apply_fail_after = Some(allowed);
    }

    /// Inject a one-shot failure after a terminal lease mutation but before
    /// its immutable outcome and correlated event are appended.
    pub fn set_lease_transport_settlement_failpoint(&mut self, allowed: u8) {
        self.lease_transport_settlement_fail_after = Some(allowed);
    }

    /// Read projection data and its event watermark from one SQLite snapshot.
    ///
    /// Data and sequence always describe the same WAL snapshot.
    ///
    /// # Errors
    ///
    /// Returns a store or decoding error and rolls the read transaction back.
    pub fn read_snapshot<T>(
        &self,
        read: impl FnOnce(&Self) -> Result<T, LedgerError>,
    ) -> Result<(T, u64), LedgerError> {
        let transaction = ReadTransaction::begin(&self.conn)?;
        let data = read(self)?;
        let as_of_sequence = self.latest_event_sequence()?;
        transaction.commit()?;
        Ok((data, as_of_sequence))
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

include!("ledger_impl.rs");
impl LaunchGrantNonceStore for SqliteLedger {
    fn record_launch_grant_nonce(
        &mut self,
        record: &LaunchGrantNonceRecord,
    ) -> Result<(), LedgerError> {
        launch_grants::record(&self.conn, record)
    }

    fn consume_launch_grant_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &AttemptId,
    ) -> Result<NonceConsumption, LedgerError> {
        launch_grants::consume(&mut self.conn, nonce, attempt_id)
    }

    fn get_launch_grant_nonce(
        &self,
        nonce: &str,
    ) -> Result<Option<StoredLaunchGrantNonce>, LedgerError> {
        launch_grants::get(&self.conn, nonce)
    }
}

impl NonceLedger for SqliteLedger {
    fn issue(&mut self, key: &str, digest: &str) -> Result<IssuedNonce, NonceError> {
        nonces::issue(&mut self.conn, key, digest)
    }

    fn consume(&mut self, key: &str, digest: &str) -> Result<(), NonceError> {
        nonces::consume(&mut self.conn, key, digest)
    }

    fn state(&self, key: &str) -> Result<Option<NonceState>, NonceError> {
        nonces::state(&self.conn, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_data_and_watermark_share_one_wal_view() {
        let dir = crate::test_support::private_tempdir();
        let path = dir.path().join("snapshot.sqlite");
        let primary = SqliteLedger::open(&path).expect("primary");
        let mut concurrent = SqliteLedger::open(&path).expect("concurrent");
        let ((count, last_kind), sequence) = primary
            .read_snapshot(|ledger| {
                let before = ledger.list_events()?;
                concurrent.append_event("concurrent", "committed after snapshot")?;
                Ok((before.len(), before.last().map(|event| event.kind.clone())))
            })
            .expect("snapshot");
        assert_eq!((count, last_kind, sequence), (0, None, 0));
        assert_eq!(primary.latest_event_sequence().expect("latest"), 1);
        // A retained connection cannot be mistaken for a quiescent snapshot.
        assert!(primary.close_quiescent().is_err());
        let reader = SqliteLedger::open(&path).expect("pinned reader");
        reader.conn.execute_batch("BEGIN").expect("begin read");
        assert_eq!(reader.latest_event_sequence().expect("pin snapshot"), 1);
        concurrent
            .append_event("later", "after pinned read")
            .expect("append");
        concurrent
            .conn
            .busy_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        let error = concurrent
            .close_quiescent()
            .expect_err("reader blocks checkpoint");
        assert!(error.to_string().contains("quiescent checkpoint refused"));
        assert!(
            std::fs::metadata(dir.path().join("snapshot.sqlite-wal"))
                .unwrap()
                .len()
                > 0
        );
        assert_eq!(
            reader
                .latest_event_sequence()
                .expect("old snapshot retained"),
            1
        );
        reader
            .conn
            .execute_batch("COMMIT")
            .expect("release snapshot");
        assert_eq!(
            reader
                .latest_event_sequence()
                .expect("latest event retained"),
            2
        );
        reader.close_quiescent().expect("last connection closes");
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(!dir.path().join(format!("snapshot.sqlite{suffix}")).exists());
        }
        let immutable = Connection::open_with_flags(
            format!("file:{}?mode=ro&immutable=1", path.display()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .expect("immutable snapshot");
        assert_eq!(
            immutable
                .query_row("SELECT count(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .expect("latest committed event survives checkpoint"),
            2
        );
    }
}
