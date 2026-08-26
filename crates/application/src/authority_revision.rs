//! Normalized authority counters. Epoch 0 is refused. Rows are inserted
//! once and then updated; callers never emit `INSERT OR REPLACE`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedAuthority {
    /// Graph revision at grant time.
    pub graph_revision: u64,
    /// Workspace generation.
    pub workspace_generation: u64,
    /// Scope digest (64 lowercase hex).
    pub scope_digest: String,
    /// Policy generation.
    pub policy_generation: u64,
    /// Routing generation.
    pub routing_generation: u64,
    /// Authority epoch. Must be ≥ 1.
    pub authority_epoch: u64,
    /// Freeze generation. 0 means no freeze has been recorded.
    pub freeze_generation: u64,
}

impl NormalizedAuthority {
    /// Construct a row after validating counters.
    ///
    /// # Errors
    ///
    /// `AUTHORITY_REVISION_INVALID` when an epoch is 0 or a digest is not
    /// 64 lowercase hex characters.
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

    /// SQL used to insert the singleton row. Never `INSERT OR REPLACE`.
    #[must_use]
    pub const fn insert_sql() -> &'static str {
        "INSERT INTO authority_revisions (
            singleton, graph_revision, workspace_generation, scope_digest,
            policy_generation, routing_generation, authority_epoch, freeze_generation
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    }

    /// SQL used to advance an existing singleton. Never `INSERT OR REPLACE`.
    #[must_use]
    pub const fn update_sql() -> &'static str {
        "UPDATE authority_revisions SET
            graph_revision = ?1,
            workspace_generation = ?2,
            scope_digest = ?3,
            policy_generation = ?4,
            routing_generation = ?5,
            authority_epoch = ?6,
            freeze_generation = ?7
         WHERE singleton = 1"
    }
}
