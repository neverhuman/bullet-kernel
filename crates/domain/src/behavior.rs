//! Machine-enforceable behavior catalog. Models cannot downgrade events.

use serde::{Deserialize, Serialize};

/// Enforcement when a rule fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Prevent the action.
    Block,
    /// Pause for a human or policy decision.
    Pause,
    /// Quarantine the Candidate.
    Quarantine,
    /// Terminate the Attempt.
    Terminate,
}

/// One versioned rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorRule {
    /// Stable identifier such as `CD001`.
    pub id: String,
    /// Catalog version.
    pub version: String,
    /// Short title.
    pub title: String,
    /// Enforcement.
    pub action: Enforcement,
    /// Whether unknown state fail-closes.
    pub fail_closed: bool,
}

/// Default first-slice catalog.
#[must_use]
pub fn default_catalog() -> Vec<BehaviorRule> {
    vec![
        BehaviorRule {
            id: "CD001".into(),
            version: "v1".into(),
            title: "No writable Git worktrees".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "CD002".into(),
            version: "v1".into(),
            title: "No cleanup without preservation receipt".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "CD003".into(),
            version: "v1".into(),
            title: "No completion claim without Candidate evidence".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "CD004".into(),
            version: "v1".into(),
            title: "Unknown destructive state blocks".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "CD005".into(),
            version: "v1".into(),
            title: "Runtime files stay outside the product repository".into(),
            action: Enforcement::Quarantine,
            fail_closed: true,
        },
    ]
}

/// Decide whether an observed workspace kind is allowed for a writer.
#[must_use]
pub fn reject_worktree(is_worktree: Option<bool>) -> bool {
    match is_worktree {
        Some(true) => true,
        Some(false) => false,
        None => true,
    }
}
