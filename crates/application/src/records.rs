//! Durable record shapes shared by every ledger implementation.

use bullet_domain::{
    Attempt, AttemptId, AttemptState, CommandId, CommandPhase, Mission, MissionId, PlanRevision,
    RunnerId, Variant, VariantId, WorkPackage, WorkPackageId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

/// Frozen Phase-1 maximum for every admitted lease and renewal.
pub const MAX_LEASE_TTL_SECONDS: i64 = 15;

/// Materialized graph snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// One durable audit event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEvent {
    /// Monotonic ledger sequence.
    pub seq: u64,
    /// Durable occurrence time (RFC 3339 UTC).
    pub at: String,
    /// Event kind.
    pub kind: String,
    /// Payload body.
    pub body: String,
    /// Globally unique event id.
    pub event_id: Option<String>,
    /// Stream the event belongs to.
    pub stream_id: Option<String>,
    /// Per-stream sequence.
    pub sequence: Option<u64>,
    /// Event that caused this one.
    pub causation_id: Option<String>,
    /// Correlation across a command's effects.
    pub correlation_id: Option<String>,
    /// Digest of the authority token that produced the event.
    pub authority_token_hash: Option<String>,
}

/// One push-maintained ready row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyRow {
    /// Dispatchable work package.
    pub work_package_id: WorkPackageId,
    /// When the row was enqueued (RFC 3339 UTC).
    pub enqueued_at: String,
}

/// One durable outbox row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxItem {
    /// Monotonic outbox sequence.
    pub seq: u64,
    /// Durable command that caused this row, when the outbox item belongs to
    /// a command transaction. Kept off the pre-contract HTTP shape until the
    /// generated public command DTO is consumed.
    #[serde(skip)]
    pub command_id: Option<CommandId>,
    /// Message kind.
    pub kind: String,
    /// Message payload.
    pub payload: String,
    /// Delivery phase. Verified only after postcondition read-back.
    pub phase: CommandPhase,
    /// When delivery was applied (RFC 3339 UTC).
    pub delivered_at: Option<String>,
    /// When the receiver acknowledged (RFC 3339 UTC).
    pub acked_at: Option<String>,
}

/// The single authoritative writer lease for a Variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveLease {
    /// Variant that owns the writer.
    pub variant_id: VariantId,
    /// Attempt incarnation holding the lease.
    pub attempt_id: AttemptId,
    /// Permanent fence epoch.
    pub fence: u64,
    /// Runner holding the lease.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Workspace nonce bound at grant.
    pub workspace_nonce: [u8; 32],
    /// Last heartbeat (RFC 3339 UTC).
    pub heartbeat_at: String,
    /// Expiry deadline (RFC 3339 UTC).
    pub expires_at: String,
    /// Exact TTL admitted at acquisition.
    pub ttl_seconds: i64,
}

/// Input to the single-transaction lease acquisition (spec section 26.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    /// Idempotent command key. Replays return the stored grant.
    pub idempotency_key: String,
    /// Mission whose graph holds the variant.
    pub mission_id: MissionId,
    /// Variant to lease.
    pub variant_id: VariantId,
    /// Deterministic seed for the new attempt id.
    pub attempt_seed: String,
    /// Runner requesting authority.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Private workspace.
    pub workspace_id: WorkspaceId,
    /// Workspace nonce.
    pub workspace_nonce: [u8; 32],
    /// Scope grant revision.
    pub scope_revision: u64,
    /// Context capsule revision.
    pub context_revision: u64,
    /// Requested lease lifetime. Valid Phase-1 range is 1..=15 seconds.
    pub ttl_seconds: i64,
}

impl LeaseRequest {
    /// Validate and return the requested TTL.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_LEASE_TTL` outside 1..=15 seconds.
    pub fn validated_ttl(&self) -> Result<i64, bullet_domain::DomainError> {
        validate_lease_ttl(self.ttl_seconds)
    }

    /// Canonical payload for idempotency comparison. The admitted TTL is
    /// authority and therefore conflicts when changed under the same key.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` when serialization fails.
    pub fn stable_payload(&self) -> Result<String, bullet_domain::DomainError> {
        self.validated_ttl()?;
        let value = serde_json::json!({
            "mission_id": self.mission_id.as_str(),
            "variant_id": self.variant_id.as_str(),
            "attempt_seed": self.attempt_seed,
            "runner_id": self.runner_id.as_str(),
            "runner_epoch": self.runner_epoch,
            "workspace_id": self.workspace_id.as_str(),
            "workspace_nonce": self.workspace_nonce.to_vec(),
            "scope_revision": self.scope_revision,
            "context_revision": self.context_revision,
            "ttl_seconds": self.ttl_seconds,
        });
        serde_json::to_string(&value)
            .map_err(|err| bullet_domain::DomainError::Encoding(err.to_string()))
    }
}

/// Result of a lease acquisition. Stored as the idempotent command response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    /// The fenced attempt created in the grant transaction.
    pub attempt: Attempt,
    /// The active lease row.
    pub lease: ActiveLease,
}

/// Six-column heartbeat per spec section 26.4. Zero matched rows is stale.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// Variant under lease.
    pub variant_id: VariantId,
    /// Attempt incarnation.
    pub attempt_id: AttemptId,
    /// Fence epoch.
    pub fence: u64,
    /// Runner identity.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Workspace nonce.
    pub workspace_nonce: [u8; 32],
    /// Exact admitted lease lifetime. Valid Phase-1 range is 1..=15 seconds.
    pub ttl_seconds: i64,
}

impl HeartbeatRequest {
    /// Validate and return the renewal TTL.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_LEASE_TTL` outside 1..=15 seconds.
    pub fn validated_ttl(&self) -> Result<i64, bullet_domain::DomainError> {
        validate_lease_ttl(self.ttl_seconds)
    }
}

/// Close one lease and optionally requeue the work package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// Variant under lease.
    pub variant_id: VariantId,
    /// Attempt that must hold the lease.
    pub attempt_id: AttemptId,
    /// Terminal state for the attempt.
    pub final_state: AttemptState,
    /// Whether the work package returns to the ready queue.
    pub requeue: bool,
}

/// Validate a requested lease lifetime without granting authority.
///
/// # Errors
///
/// Returns `INVALID_LEASE_TTL` outside 1..=15 seconds.
pub fn validate_lease_ttl(ttl_seconds: i64) -> Result<i64, bullet_domain::DomainError> {
    if (1..=MAX_LEASE_TTL_SECONDS).contains(&ttl_seconds) {
        Ok(ttl_seconds)
    } else {
        Err(bullet_domain::DomainError::InvalidLeaseTtl(ttl_seconds))
    }
}

/// One lease reclaimed by expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpiredLease {
    /// Variant whose lease expired.
    pub variant_id: VariantId,
    /// Attempt moved to crashed.
    pub attempt_id: AttemptId,
    /// Work package returned to ready.
    pub work_package_id: WorkPackageId,
    /// Fence of the expired incarnation.
    pub fence: u64,
}
