//! Pure operation guard for the modeled fence/scope/freeze/restore protocol.

use thiserror::Error;

/// Authority values carried by one mutation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationContext {
    /// Permanent Attempt fence.
    pub fence: u64,
    /// Writer-acknowledged scope revision.
    pub scope_revision: u64,
    /// Authority epoch invalidated by restore.
    pub authority_epoch: u64,
    /// Freeze generation observed by the caller.
    pub freeze_generation: u64,
}

/// Pure state owned by the mutation gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationGuard {
    fence: u64,
    scope_revision: u64,
    acknowledged_scope: u64,
    authority_epoch: u64,
    freeze_generation: u64,
    barrier: bool,
    frozen: bool,
}

/// Typed refusal emitted before any mutation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MutationRefusal {
    /// Attempt fence no longer owns the writer.
    #[error("attempt fence is stale")]
    Fence,
    /// Scope revision is not current or acknowledged.
    #[error("scope revision is stale or unacknowledged")]
    ScopeRevision,
    /// Track-A scope amendment has stopped writes.
    #[error("mutation barrier is active")]
    Barrier,
    /// Fleet freeze has stopped writes.
    #[error("freeze is active")]
    Frozen,
    /// Restore invalidated the authority epoch.
    #[error("authority epoch is stale")]
    AuthorityEpoch,
    /// Caller predates the current freeze generation.
    #[error("freeze generation is stale")]
    FreezeGeneration,
}

impl MutationRefusal {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Fence => "STALE_FENCE",
            Self::ScopeRevision => "STALE_SCOPE_REVISION",
            Self::Barrier => "MUTATION_BARRIER",
            Self::Frozen => "FROZEN",
            Self::AuthorityEpoch => "STALE_AUTHORITY_EPOCH",
            Self::FreezeGeneration => "STALE_FREEZE_GENERATION",
        }
    }
}

impl MutationGuard {
    /// Start a guard from durable high-water values.
    #[must_use]
    pub const fn new(
        fence: u64,
        scope_revision: u64,
        authority_epoch: u64,
        freeze_generation: u64,
    ) -> Self {
        Self {
            fence,
            scope_revision,
            acknowledged_scope: scope_revision,
            authority_epoch,
            freeze_generation,
            barrier: false,
            frozen: false,
        }
    }

    /// Refuse or accept an Apply request without side effects.
    pub fn authorize_apply(&self, request: MutationContext) -> Result<(), MutationRefusal> {
        if self.frozen {
            return Err(MutationRefusal::Frozen);
        }
        if request.fence != self.fence {
            return Err(MutationRefusal::Fence);
        }
        if request.scope_revision != self.scope_revision
            || self.acknowledged_scope != self.scope_revision
        {
            return Err(MutationRefusal::ScopeRevision);
        }
        if self.barrier {
            return Err(MutationRefusal::Barrier);
        }
        if request.authority_epoch != self.authority_epoch {
            return Err(MutationRefusal::AuthorityEpoch);
        }
        if request.freeze_generation != self.freeze_generation {
            return Err(MutationRefusal::FreezeGeneration);
        }
        Ok(())
    }

    /// Enter Track A's zero-apply barrier.
    pub fn enter_barrier(&mut self) -> Result<(), MutationRefusal> {
        if self.frozen {
            return Err(MutationRefusal::Frozen);
        }
        self.barrier = true;
        Ok(())
    }

    /// Append and revoke to the next scope revision while barred.
    pub fn append_scope_revision(&mut self) -> Result<u64, MutationRefusal> {
        if !self.barrier {
            return Err(MutationRefusal::Barrier);
        }
        self.scope_revision += 1;
        Ok(self.scope_revision)
    }

    /// Record the sole writer's acknowledgement.
    pub fn acknowledge_scope(&mut self, revision: u64) -> Result<(), MutationRefusal> {
        if revision != self.scope_revision {
            return Err(MutationRefusal::ScopeRevision);
        }
        self.acknowledged_scope = revision;
        Ok(())
    }

    /// Resume after the current revision is acknowledged.
    pub fn resume(&mut self) -> Result<(), MutationRefusal> {
        if self.acknowledged_scope != self.scope_revision {
            return Err(MutationRefusal::ScopeRevision);
        }
        self.barrier = false;
        Ok(())
    }

    /// Persist the next freeze generation and stop mutations.
    pub fn freeze(&mut self) -> u64 {
        self.freeze_generation += 1;
        self.frozen = true;
        self.freeze_generation
    }

    /// Rotate the authority epoch after restore while staying frozen.
    pub fn restore(&mut self) -> u64 {
        self.authority_epoch += 1;
        self.frozen = true;
        self.authority_epoch
    }

    /// Independently authorize recovery into active service.
    pub fn recover_active(&mut self) -> Result<(), MutationRefusal> {
        if !self.frozen {
            return Err(MutationRefusal::Frozen);
        }
        self.frozen = false;
        Ok(())
    }
}
