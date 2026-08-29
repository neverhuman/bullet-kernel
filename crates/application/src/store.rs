//! Ledger port. Adapters implement this. The portal does not.
//!
//! Caller-supplied non-authority timestamps cross this boundary as fixed-width
//! RFC 3339 UTC strings. Lease authority time is owned by each store.

use crate::authority::ActiveLeaseSubject;
use crate::authority_revision::NormalizedAuthority;
use crate::commands::{CommandRecord, CommandRequest};
use crate::effect_state::EffectState;
use crate::effects::{EffectIntentRecord, EffectReceiptRecord};
use crate::graph_delta::GraphDelta;
use crate::records::{
    ActiveLease, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerEvent, OutboxItem,
    ReadyRow, ReleaseRequest, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, Candidate, CandidateId, CommandPhase, Effect, EffectId, Evidence,
    EvidenceId, Mission, MissionId, VariantId, WorkPackageId,
};
use thiserror::Error;

pub use bullet_harness_core::launch_grant::NonceConsumption;

mod lease_txn;
mod projection;

pub use lease_txn::{incarnation_subject, CurrentPackage, LeaseTransportTxn};
pub use projection::ProjectionReader;

/// Ledger failure.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Durable store failure.
    #[error("ledger: {0}")]
    Store(String),
    /// Persisted schema is not the exact disposable pre-1.0 schema this binary owns.
    #[error(
        "unsupported schema: {detail}. Export any data you need before removing the database file and starting fresh; pre-1.0 Bullet Farm databases are not migrated in place"
    )]
    UnsupportedSchema {
        /// Exact fail-closed reason suitable for operator logs.
        detail: String,
    },
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
            Self::UnsupportedSchema { .. } => "UNSUPPORTED_SCHEMA",
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
    /// Record a command with phase `Pending`. Same key + kind + exact payload
    /// replays the stored record; a changed kind or payload under that key is a typed
    /// `Idempotency` error.
    ///
    /// # Errors
    /// Store or idempotency failure.
    fn record_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError>;

    /// Admit one public command and its correlated dispatch outbox row in one
    /// transaction. Exact replay returns the durable command without adding a
    /// second row; conflicting or incomplete prior truth fails closed.
    ///
    /// # Errors
    /// Store or idempotency failure.
    fn submit_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError>;

    /// Settle one exact public command through the bounded internal worker.
    /// The command, its single correlated outbox row, and its one audit event
    /// must commit atomically. Exact replay returns the stored disposition.
    /// This operation cannot produce APPLIED or VERIFIED.
    ///
    /// # Errors
    /// Store failure, missing command, or corrupt/conflicting durable truth.
    fn reconcile_offline_command(
        &mut self,
        id: &bullet_domain::CommandId,
        now: &str,
    ) -> Result<CommandRecord, LedgerError>;

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

    /// Load a command by its durable identity.
    ///
    /// # Errors
    /// Store failure or corrupt persisted command truth.
    fn get_command_by_id(
        &self,
        id: &bullet_domain::CommandId,
    ) -> Result<Option<CommandRecord>, LedgerError>;

    /// Admit and materialize one Mission plan in a single transaction. The
    /// command row, graph, fence counters, ready rows, audit event, and exact
    /// applied result commit together. Identical replay returns the stored
    /// initial graph without appending or changing current graph state.
    ///
    /// # Errors
    /// Typed idempotency/conflict error or durable store failure.
    fn materialize_plan_command(
        &mut self,
        request: &CommandRequest,
        graph: &StoredGraph,
        now: &str,
    ) -> Result<StoredGraph, LedgerError>;

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

    /// Admit and apply one graph delta in a single transaction. Command row,
    /// graph body, audit event, and applied/failed result commit together.
    /// Identical replay never applies the delta or appends its event twice.
    ///
    /// # Errors
    /// Typed graph/idempotency failure or durable store failure.
    fn apply_graph_delta_command(
        &mut self,
        request: &CommandRequest,
        mission: &MissionId,
        delta: &GraphDelta,
    ) -> Result<StoredGraph, LedgerError>;

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

    /// Reclaim every lease with `expires_at <=` the store's current time:
    /// attempt becomes
    /// `Crashed`, the package returns to `Ready` with a ready row, the lease
    /// row is deleted — the complete reclaimed set commits atomically.
    ///
    /// # Errors
    /// Store failure.
    fn expire_leases(&mut self) -> Result<Vec<ExpiredLease>, LedgerError>;

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

    /// Coherently check the exact active lease and linked Attempt using the
    /// store's authoritative clock. Success is not a mutation capability;
    /// permit issuance must repeat this helper inside its reservation write.
    ///
    /// # Errors
    /// `StaleAuthority` for missing, expired, or mismatched state; store
    /// failure for unavailable or corrupt persisted state.
    fn check_active_lease(&mut self, subject: &ActiveLeaseSubject) -> Result<(), LedgerError>;

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

    /// Latest durable event sequence, or zero before the first event.
    ///
    /// # Errors
    /// Store failure.
    fn latest_event_sequence(&self) -> Result<u64, LedgerError>;

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

    /// Outbox rows caused by one durable command, oldest-first.
    ///
    /// # Errors
    /// Store failure or corrupt persisted correlation.
    fn outbox_for_command(
        &self,
        command: &bullet_domain::CommandId,
    ) -> Result<Vec<OutboxItem>, LedgerError>;

    /// Advance one outbox row: `Applied` stamps `delivered_at`,
    /// `Verified`/`Unknown` stamp `acked_at`.
    ///
    /// # Errors
    /// Store failure or unknown sequence.
    fn outbox_mark(&mut self, seq: u64, phase: CommandPhase, now: &str) -> Result<(), LedgerError>;

    /// Record an effect intent with state `Proposed`. Unique on
    /// `(provider, logical_effect_key)`: replaying the same stable identity
    /// returns the stored row with `false`; a differing identity under the
    /// same key is a typed `Idempotency` error. Intents whose state is not
    /// `Proposed` are refused.
    ///
    /// # Errors
    /// Idempotency conflict, refusal, or store failure.
    fn record_effect_intent(
        &mut self,
        intent: &EffectIntentRecord,
    ) -> Result<(EffectIntentRecord, bool), LedgerError>;

    /// Load an effect intent by its unique `(provider, logical_effect_key)`.
    ///
    /// # Errors
    /// Store failure.
    fn get_effect_intent(
        &self,
        provider: &str,
        logical_key: &str,
    ) -> Result<Option<EffectIntentRecord>, LedgerError>;

    /// Load an effect intent by id.
    ///
    /// # Errors
    /// Store failure.
    fn get_effect_intent_by_id(
        &self,
        id: &EffectId,
    ) -> Result<Option<EffectIntentRecord>, LedgerError>;

    /// Apply one legal effect state edge and return the updated row. The
    /// `OutcomeUnknown -> Dispatching` edge increments `unknown_retries`.
    ///
    /// # Errors
    /// Typed `InvalidTransition`, unknown id, or store failure.
    fn transition_effect(
        &mut self,
        id: &EffectId,
        to: EffectState,
    ) -> Result<EffectIntentRecord, LedgerError>;

    /// Append-only effect receipt insert. Returns `true` when newly
    /// inserted, `false` for an identical replay; a different body under
    /// the same id is a typed `Conflict`.
    ///
    /// # Errors
    /// Conflict or store failure.
    fn record_effect_receipt(&mut self, receipt: &EffectReceiptRecord)
        -> Result<bool, LedgerError>;

    /// Receipts for one intent, oldest-first.
    ///
    /// # Errors
    /// Store failure.
    fn effect_receipts(&self, intent: &EffectId) -> Result<Vec<EffectReceiptRecord>, LedgerError>;

    /// Intents that were dispatched (or are mid-dispatch) without a settled
    /// disposition: `Dispatching`, `ReceiptPending`, `OutcomeUnknown`.
    ///
    /// # Errors
    /// Store failure.
    fn unresolved_effects(&self) -> Result<Vec<EffectIntentRecord>, LedgerError>;

    /// Load the singleton normalized authority row.
    ///
    /// Empty stores must seed genesis exactly once. Grant minting reads this
    /// row and must not substitute a compile-time epoch.
    ///
    /// # Errors
    /// Store failure or a missing/invalid durable row.
    fn current_authority(&self) -> Result<NormalizedAuthority, LedgerError>;

    /// Run `f` inside one immediate transaction. Nonce reserve, permit
    /// consumption, the lease mutation, and grant persistence must commit
    /// together or not at all.
    ///
    /// # Errors
    /// Store or domain failure. The transaction rolls back when `f` fails.
    fn with_lease_transport<T, E, F>(&mut self, f: F) -> Result<T, E>
    where
        Self: Sized,
        F: FnOnce(&mut dyn LeaseTransportTxn) -> Result<T, E>,
        E: From<LedgerError>;
}
