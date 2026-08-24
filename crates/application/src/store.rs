//! Ledger port. Adapters implement this. The portal does not.

use crate::commands::{CommandRecord, CommandRequest};
use bullet_domain::{
    Attempt, AttemptId, Candidate, Effect, Evidence, Mission, MissionId, PlanRevision, Variant,
    WorkPackage, WorkPackageId,
};
use thiserror::Error;

/// Ledger failure.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Durable store failure.
    #[error("ledger: {0}")]
    Store(String),
    /// Domain invariant.
    #[error(transparent)]
    Domain(#[from] bullet_domain::DomainError),
}

/// Materialized graph snapshot.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StoredGraph {
    /// Mission.
    pub mission: Mission,
    /// Plan.
    pub plan: PlanRevision,
    /// Work packages.
    pub packages: Vec<WorkPackage>,
    /// Variants.
    pub variants: Vec<Variant>,
}

/// Transactional authority store.
pub trait Ledger {
    /// Record a command. Same key + same payload is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a store or idempotency error.
    fn record_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError>;

    /// Persist a materialized graph in one transaction.
    ///
    /// # Errors
    ///
    /// Returns a store error when the write fails.
    fn put_graph(&mut self, graph: &StoredGraph) -> Result<(), LedgerError>;

    /// Load a mission graph.
    ///
    /// # Errors
    ///
    /// Returns a store error when the read fails.
    fn get_graph(&self, mission: &MissionId) -> Result<Option<StoredGraph>, LedgerError>;

    /// List missions newest first.
    ///
    /// # Errors
    ///
    /// Returns a store error when the read fails.
    fn list_missions(&self) -> Result<Vec<Mission>, LedgerError>;

    /// Put an attempt.
    ///
    /// # Errors
    ///
    /// Returns a store error when the write fails.
    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError>;

    /// Load an attempt.
    ///
    /// # Errors
    ///
    /// Returns a store error when the read fails.
    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError>;

    /// Active writer for a work package, if any.
    ///
    /// # Errors
    ///
    /// Returns a store error when the read fails.
    fn active_attempt(&self, package: &WorkPackageId) -> Result<Option<Attempt>, LedgerError>;

    /// Put a candidate.
    ///
    /// # Errors
    ///
    /// Returns a store error when the write fails.
    fn put_candidate(&mut self, candidate: &Candidate) -> Result<(), LedgerError>;

    /// Put evidence.
    ///
    /// # Errors
    ///
    /// Returns a store error when the write fails.
    fn put_evidence(&mut self, evidence: &Evidence) -> Result<(), LedgerError>;

    /// Put an effect.
    ///
    /// # Errors
    ///
    /// Returns a store error when the write fails.
    fn put_effect(&mut self, effect: &Effect) -> Result<(), LedgerError>;

    /// Append an audit event.
    ///
    /// # Errors
    ///
    /// Returns a store error when the write fails.
    fn append_event(&mut self, kind: &str, body: &str) -> Result<(), LedgerError>;

    /// Outbox items that are not yet verified.
    ///
    /// # Errors
    ///
    /// Returns a store error when the read fails.
    fn pending_outbox(&self) -> Result<Vec<CommandRecord>, LedgerError>;
}
