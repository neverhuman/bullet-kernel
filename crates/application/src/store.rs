//! Ledger port. Adapters implement this. The portal does not.
//!
//! Times cross this boundary as fixed-width RFC 3339 UTC strings so that
//! implementations can compare them lexically without owning a clock.

use crate::commands::{CommandRecord, CommandRequest};
use crate::records::{
    ActiveLease, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerEvent, OutboxItem,
    ReadyRow, ReleaseRequest, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, Candidate, CandidateId, CommandPhase, Effect, EffectId, Evidence,
    EvidenceId, Mission, MissionId, VariantId, WorkPackageId,
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

impl LedgerError {
    /// Stable machine-readable reason code for APIs and logs.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Store(_) => "STORE_FAILURE",
            Self::Domain(err) => err.reason_code(),
        }
    }
}

/// Transactional authority store.
///
/// Every method that mutates several rows must apply them atomically:
/// either all rows land or none do. Errors are typed; callers never parse
/// message strings.
pub trait Ledger {
    /// Record a command with phase `Pending`. Same key + same payload replays
    /// the stored record; same key + different payload is a typed
    /// `Idempotency` error.
    ///
    /// # Errors
    /// Store or idempotency failure.
    fn record_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError>;

    /// Advance a command phase and optionally store its response.
    ///
    /// # Errors
    /// Store failure or unknown key.
    fn set_command_phase(
        &mut self,
        key: &str,
        phase: CommandPhase,
        response: Option<&str>,
    ) -> Result<(), LedgerError>;

    /// Load a command by idempotency key.
    ///
    /// # Errors
    /// Store failure.
    fn get_command(&self, key: &str) -> Result<Option<CommandRecord>, LedgerError>;

    /// Persist a fresh graph atomically: graph body, one fence counter per
    /// variant, one ready row per `Ready` package, and a
    /// `graph_materialized` event — all in one transaction.
    ///
    /// # Errors
    /// Store failure; no partial rows survive one.
    fn materialize_graph(&mut self, graph: &StoredGraph, now: &str) -> Result<(), LedgerError>;

    /// Update an existing graph body (delta application).
    ///
    /// # Errors
    /// Store failure.
    fn put_graph(&mut self, graph: &StoredGraph) -> Result<(), LedgerError>;

    /// Load a mission graph.
    ///
    /// # Errors
    /// Store failure.
    fn get_graph(&self, mission: &MissionId) -> Result<Option<StoredGraph>, LedgerError>;

    /// List missions.
    ///
    /// # Errors
    /// Store failure.
    fn list_missions(&self) -> Result<Vec<Mission>, LedgerError>;

    /// Spec section 26.3 in one transaction: replay the command if stored,
    /// require the package `Ready` with a ready row, require no active lease,
    /// increment the permanent fence, insert the attempt (`Starting`), insert
    /// the lease, delete the ready row, append `attempt_leased`, enqueue a
    /// dispatch outbox row, and store the command result.
    ///
    /// # Errors
    /// Typed fence/idempotency/stale errors or store failure.
    fn acquire_lease(&mut self, request: &LeaseRequest) -> Result<LeaseGrant, LedgerError>;

    /// Spec section 26.4 six-column conditional update.
    ///
    /// # Errors
    /// `StaleAuthority` when zero rows match; store failure otherwise.
    fn heartbeat(&mut self, request: &HeartbeatRequest) -> Result<(), LedgerError>;

    /// Reclaim every lease with `expires_at < now`: attempt becomes
    /// `Crashed`, the package returns to `Ready` with a ready row, the lease
    /// row is deleted — one transaction per lease.
    ///
    /// # Errors
    /// Store failure.
    fn expire_leases(&mut self, now: &str) -> Result<Vec<ExpiredLease>, LedgerError>;

    /// Close a lease. Idempotent: releasing an attempt already in
    /// `final_state` with no lease row succeeds.
    ///
    /// # Errors
    /// `StaleAuthority` when another attempt holds the lease.
    fn release_lease(&mut self, request: &ReleaseRequest) -> Result<(), LedgerError>;

    /// Load the active lease for a variant.
    ///
    /// # Errors
    /// Store failure.
    fn get_lease(&self, variant: &VariantId) -> Result<Option<ActiveLease>, LedgerError>;

    /// Insert a new attempt, or apply a legal state transition to an
    /// existing one. Identity columns never change.
    ///
    /// # Errors
    /// Typed transition/fence errors or store failure.
    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError>;

    /// Load an attempt.
    ///
    /// # Errors
    /// Store failure.
    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError>;

    /// The live writer for one work package, if any.
    ///
    /// # Errors
    /// Store failure.
    fn active_attempt(&self, package: &WorkPackageId) -> Result<Option<Attempt>, LedgerError>;

    /// Attempts whose variant belongs to `mission`.
    ///
    /// # Errors
    /// Store failure.
    fn list_attempts(&self, mission: &MissionId) -> Result<Vec<Attempt>, LedgerError>;

    /// Append-only candidate insert. Returns `true` when newly inserted,
    /// `false` for an identical replay; a different body under the same id
    /// is a typed `Conflict`.
    ///
    /// # Errors
    /// Conflict or store failure.
    fn put_candidate(&mut self, candidate: &Candidate) -> Result<bool, LedgerError>;

    /// Load a candidate.
    ///
    /// # Errors
    /// Store failure.
    fn get_candidate(&self, id: &CandidateId) -> Result<Option<Candidate>, LedgerError>;

    /// Append-only evidence insert with replay semantics of `put_candidate`.
    ///
    /// # Errors
    /// Conflict or store failure.
    fn put_evidence(&mut self, evidence: &Evidence) -> Result<bool, LedgerError>;

    /// Load evidence.
    ///
    /// # Errors
    /// Store failure.
    fn get_evidence(&self, id: &EvidenceId) -> Result<Option<Evidence>, LedgerError>;

    /// Append-only effect insert with replay semantics of `put_candidate`.
    ///
    /// # Errors
    /// Conflict or store failure.
    fn put_effect(&mut self, effect: &Effect) -> Result<bool, LedgerError>;

    /// Load an effect.
    ///
    /// # Errors
    /// Store failure.
    fn get_effect(&self, id: &EffectId) -> Result<Option<Effect>, LedgerError>;

    /// Append an audit event.
    ///
    /// # Errors
    /// Store failure.
    fn append_event(&mut self, kind: &str, body: &str) -> Result<(), LedgerError>;

    /// Durable events oldest-first.
    ///
    /// # Errors
    /// Store failure.
    fn list_events(&self) -> Result<Vec<LedgerEvent>, LedgerError>;

    /// Events with `seq > after`, capped at `limit`.
    ///
    /// # Errors
    /// Store failure.
    fn list_events_after(&self, after: u64, limit: usize) -> Result<Vec<LedgerEvent>, LedgerError>;

    /// Current push-maintained ready rows.
    ///
    /// # Errors
    /// Store failure.
    fn ready_rows(&self) -> Result<Vec<ReadyRow>, LedgerError>;

    /// Insert a ready row if absent.
    ///
    /// # Errors
    /// Store failure.
    fn enqueue_ready(&mut self, package: &WorkPackageId, now: &str) -> Result<(), LedgerError>;

    /// Append an outbox row with phase `Pending`. Returns its sequence.
    ///
    /// # Errors
    /// Store failure.
    fn outbox_enqueue(&mut self, kind: &str, payload: &str) -> Result<u64, LedgerError>;

    /// Outbox rows not yet verified or unknown.
    ///
    /// # Errors
    /// Store failure.
    fn outbox_pending(&self) -> Result<Vec<OutboxItem>, LedgerError>;

    /// Every outbox row with its real phase, oldest-first.
    ///
    /// # Errors
    /// Store failure.
    fn outbox_all(&self) -> Result<Vec<OutboxItem>, LedgerError>;

    /// Advance one outbox row: `Applied` stamps `delivered_at`,
    /// `Verified`/`Unknown` stamp `acked_at`.
    ///
    /// # Errors
    /// Store failure or unknown sequence.
    fn outbox_mark(&mut self, seq: u64, phase: CommandPhase, now: &str) -> Result<(), LedgerError>;
}
