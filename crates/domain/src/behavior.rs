//! Machine-enforceable behavior catalog. Models cannot downgrade events.
//! Rule identifiers follow the spec section 17 catalog.

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
            id: "CP001".into(),
            version: "v1".into(),
            title: "Completion claim without exact Candidate evidence".into(),
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
            id: "FS001".into(),
            version: "v1".into(),
            title: "Runtime files written into the product repository".into(),
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
