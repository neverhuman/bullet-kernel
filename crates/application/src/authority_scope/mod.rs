//! Validated, idempotent admission of one generated scope grant into normalized authority.

mod validation;

use crate::{CommandRequest, LedgerError};
use bullet_domain::schema_bundle::ScopeGrantV1;
use bullet_domain::CommandId;
use serde::{Deserialize, Serialize};

pub use validation::{prepare_authority_scope_admission, AUTHORITY_SCOPE_ENVELOPE_CLASS};

/// Durable scope-admission failure.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityScopeError {
    /// Input did not satisfy the closed scope-admission contract.
    #[error("invalid authority scope admission: {0}")]
    Invalid(String),
    /// An idempotency or immutable subject was reused with different bytes.
    #[error("authority scope admission conflict: {0}")]
    Conflict(String),
    /// The expected normalized-authority epoch is stale.
    #[error("stale authority scope epoch: expected {expected}, current {current}")]
    StaleAuthority {
        /// Caller-presented epoch.
        expected: u64,
        /// Durable current epoch.
        current: u64,
    },
    /// Scope cannot change while the normalized authority is frozen.
    #[error("authority scope is frozen at generation {0}")]
    Frozen(u64),
    /// Durable adapter failure.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
}

impl AuthorityScopeError {
    /// Stable machine reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "AUTHORITY_SCOPE_INVALID",
            Self::Conflict(_) => "IDEMPOTENCY_CONFLICT",
            Self::StaleAuthority { .. } => "STALE_AUTHORITY",
            Self::Frozen(_) => "AUTHORITY_FROZEN",
            Self::Ledger(error) => error.reason_code(),
        }
    }
}

/// Validated exact request passed to the durable adapter.
#[derive(Clone, Debug)]
pub struct PreparedAuthorityScopeAdmission {
    grant: ScopeGrantV1,
    command: CommandRequest,
    grant_bytes: Vec<u8>,
    scope_paths_digest: String,
    expected_authority_epoch: u64,
    admitted_at: String,
}

impl PreparedAuthorityScopeAdmission {
    /// Exact generated grant.
    #[must_use]
    pub const fn grant(&self) -> &ScopeGrantV1 {
        &self.grant
    }

    /// Derived idempotent command identity and request digest.
    #[must_use]
    pub const fn command(&self) -> &CommandRequest {
        &self.command
    }

    /// RFC 8785 grant bytes.
    #[must_use]
    pub fn grant_bytes(&self) -> &[u8] {
        &self.grant_bytes
    }

    /// Shared ordered-path digest consumed by Candidate preparation.
    #[must_use]
    pub fn scope_paths_digest(&self) -> &str {
        &self.scope_paths_digest
    }

    /// Caller-presented current authority epoch.
    #[must_use]
    pub const fn expected_authority_epoch(&self) -> u64 {
        self.expected_authority_epoch
    }

    /// Exact bounded UTC timestamp bound into the command.
    #[must_use]
    pub fn admitted_at(&self) -> &str {
        &self.admitted_at
    }

    pub(super) fn new(
        grant: ScopeGrantV1,
        command: CommandRequest,
        grant_bytes: Vec<u8>,
        scope_paths_digest: String,
        expected_authority_epoch: u64,
        admitted_at: String,
    ) -> Self {
        Self {
            grant,
            command,
            grant_bytes,
            scope_paths_digest,
            expected_authority_epoch,
            admitted_at,
        }
    }
}

/// Immutable durable result. Epochs and event sequence are store-selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScopeAdmission {
    /// Frozen component schema.
    pub schema_version: String,
    /// Derived command identity.
    pub command_id: CommandId,
    /// Exact idempotency key.
    pub idempotency_key: String,
    /// Digest of the exact command payload.
    pub request_digest: String,
    /// Admitted generated grant identity.
    pub scope_grant_id: String,
    /// Admitted scope revision.
    pub scope_revision: u64,
    /// Shared ordered-path digest.
    pub scope_paths_digest: String,
    /// Durable epoch before admission.
    pub previous_authority_epoch: u64,
    /// Durable epoch selected by the store.
    pub new_authority_epoch: u64,
    /// Durable freeze generation observed by the store.
    pub freeze_generation: u64,
    /// Exact caller timestamp bound into the command.
    pub admitted_at: String,
    /// Atomically correlated audit-event sequence.
    pub event_sequence: u64,
}

/// Narrow durable scope-admission port.
pub trait AuthorityScopeStore {
    /// Validate and admit one scope grant, or return its exact durable replay.
    fn admit_scope_grant(
        &mut self,
        grant: &ScopeGrantV1,
        expected_authority_epoch: u64,
        idempotency_key: &str,
        now: &str,
    ) -> Result<AuthorityScopeAdmission, AuthorityScopeError>;
}
