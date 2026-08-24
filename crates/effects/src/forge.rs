//! Forge port. LocalBareForge is the offline oracle. No network.

use std::collections::BTreeMap;

/// Desired remote mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectIntent {
    /// Idempotency key. Replay uses this, never a new remote object.
    pub logical_key: String,
    /// Target ref or resource.
    pub target: String,
    /// Expected current remote value. Empty means create.
    pub expected: String,
    /// Desired remote value.
    pub desired: String,
}

/// Read-back of remote state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteState {
    /// Target.
    pub target: String,
    /// Observed value, if any.
    pub value: Option<String>,
}

/// In-memory GitHub-shaped forge. Unit tests only.
#[derive(Default)]
pub struct LocalBareForge {
    refs: BTreeMap<String, String>,
    /// When set, the next push applies then reports timeout.
    pub timeout_next_push: bool,
    /// How many successful (or timeout-after-apply) writes occurred.
    pub write_count: u32,
}

impl LocalBareForge {
    /// Empty forge.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current ref value.
    #[must_use]
    pub fn get(&self, target: &str) -> Option<&str> {
        self.refs.get(target).map(String::as_str)
    }

    /// Apply `intent` if the precondition matches.
    ///
    /// # Errors
    ///
    /// Returns `conflict` when expected does not match, or `timeout` after apply.
    pub fn push(&mut self, intent: &EffectIntent) -> Result<(), &'static str> {
        let current = self.refs.get(&intent.target).cloned().unwrap_or_default();
        if current != intent.expected {
            return Err("conflict");
        }
        self.refs
            .insert(intent.target.clone(), intent.desired.clone());
        self.write_count += 1;
        if self.timeout_next_push {
            self.timeout_next_push = false;
            return Err("timeout");
        }
        Ok(())
    }

    /// Authoritative read-back.
    #[must_use]
    pub fn read_back(&self, target: &str) -> RemoteState {
        RemoteState {
            target: target.to_string(),
            value: self.refs.get(target).cloned(),
        }
    }
}
