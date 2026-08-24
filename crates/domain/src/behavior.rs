//! Behavior policy primitives. Catalog membership alone does not prove that a
//! gateway is wired; enforcement evidence is tracked separately.

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
    /// Stable spec catalog identifier such as `GT001`.
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

/// Default first-slice catalog. Identifiers match spec section 17.
#[must_use]
pub fn default_catalog() -> Vec<BehaviorRule> {
    vec![
        BehaviorRule {
            id: "GT001".into(),
            version: "v1".into(),
            title: "Uses Git worktree for writable task".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "CL001".into(),
            version: "v1".into(),
            title: "Deletes workspace before verified preservation".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "CP002".into(),
            version: "v1".into(),
            title: "Emits done without exact Candidate".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "CL002".into(),
            version: "v1".into(),
            title: "Treats failed observation as empty or clean".into(),
            action: Enforcement::Block,
            fail_closed: true,
        },
        BehaviorRule {
            id: "FS004".into(),
            version: "v1".into(),
            title: "Writes runtime/provider configuration into product repository".into(),
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
