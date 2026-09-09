//! Normalized authority counters and exact scope digest. Required counters
//! refuse zero and every counter is bounded by SQLite's signed integer range.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Largest authority counter representable by the SQLite persistence boundary.
pub const MAX_SQLITE_INTEGER: u64 = i64::MAX as u64;

/// Fail-closed authority-revision error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorityRevisionError {
    /// A required counter was zero or otherwise illegal.
    #[error("invalid authority revision: {0}")]
    Invalid(String),
}

impl AuthorityRevisionError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "AUTHORITY_REVISION_INVALID",
        }
    }
}

/// One normalized authority row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NormalizedAuthority {
    /// Graph revision at grant time.
    graph_revision: u64,
    /// Workspace generation.
    workspace_generation: u64,
    /// Scope digest (64 lowercase hex).
    scope_digest: String,
    /// Policy generation.
    policy_generation: u64,
    /// Routing generation.
    routing_generation: u64,
    /// Authority epoch. Must be ≥ 1.
    authority_epoch: u64,
    /// Freeze generation. 0 means no freeze has been recorded.
    freeze_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalizedAuthorityWire {
    graph_revision: u64,
    workspace_generation: u64,
    scope_digest: String,
    policy_generation: u64,
    routing_generation: u64,
    authority_epoch: u64,
    freeze_generation: u64,
}

impl<'de> Deserialize<'de> for NormalizedAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = NormalizedAuthorityWire::deserialize(deserializer)?;
        Self::new(
            wire.graph_revision,
            wire.workspace_generation,
            wire.scope_digest,
            wire.policy_generation,
            wire.routing_generation,
            wire.authority_epoch,
            wire.freeze_generation,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl NormalizedAuthority {
    /// Construct a row after validating counters.
    ///
    /// # Errors
    ///
    /// `AUTHORITY_REVISION_INVALID` when a required counter is zero, any
    /// counter exceeds [`MAX_SQLITE_INTEGER`], or the digest is not 64
    /// lowercase hex characters.
    pub fn new(
        graph_revision: u64,
        workspace_generation: u64,
        scope_digest: impl Into<String>,
        policy_generation: u64,
        routing_generation: u64,
        authority_epoch: u64,
        freeze_generation: u64,
    ) -> Result<Self, AuthorityRevisionError> {
        let scope_digest = scope_digest.into();
        let counters = [
            graph_revision,
            workspace_generation,
            policy_generation,
            routing_generation,
            authority_epoch,
            freeze_generation,
        ];
        if graph_revision == 0
            || workspace_generation == 0
            || policy_generation == 0
            || routing_generation == 0
            || authority_epoch == 0
        {
            return Err(AuthorityRevisionError::Invalid(
                "authority counters cannot be zero".into(),
            ));
        }
        if counters.into_iter().any(|value| value > MAX_SQLITE_INTEGER) {
            return Err(AuthorityRevisionError::Invalid(format!(
                "authority counters cannot exceed {MAX_SQLITE_INTEGER}"
            )));
        }
        if scope_digest.len() != 64
            || !scope_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthorityRevisionError::Invalid(
                "scope digest must be 64 lowercase hex characters".into(),
            ));
        }
        Ok(Self {
            graph_revision,
            workspace_generation,
            scope_digest,
            policy_generation,
            routing_generation,
            authority_epoch,
            freeze_generation,
        })
    }

    /// Graph revision at grant time.
    #[must_use]
    pub const fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    /// Workspace generation at grant time.
    #[must_use]
    pub const fn workspace_generation(&self) -> u64 {
        self.workspace_generation
    }

    /// Exact lowercase-hex scope digest.
    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    /// Policy generation at grant time.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Routing generation at grant time.
    #[must_use]
    pub const fn routing_generation(&self) -> u64 {
        self.routing_generation
    }

    /// Authority epoch at grant time.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    /// Freeze generation at grant time.
    #[must_use]
    pub const fn freeze_generation(&self) -> u64 {
        self.freeze_generation
    }

    /// First durable singleton written once into an empty authority table.
    ///
    /// Grants must read the stored row, not this constructor, after the
    /// ledger has been opened.
    #[must_use]
    pub fn genesis() -> Self {
        Self::new(1, 1, "0".repeat(64), 1, 1, 1, 0)
            .expect("genesis authority counters are representable")
    }
}
