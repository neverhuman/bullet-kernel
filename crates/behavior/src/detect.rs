//! Non-authoritative detector scaffolds for selected §17 rows. A hit proposes
//! policy evidence; this crate is not yet wired as a mutation gateway.

use crate::catalog::{row_by_id, CatalogRow};
use serde::{Deserialize, Serialize};

/// Rows that currently have detector scaffolds. This is not an enforcement
/// claim; all other catalog rows remain visibly planned.
pub const DETECTOR_SCAFFOLD_IDS: &[&str] = &[
    "CL001", "CL002", "CP001", "CP002", "FS004", "GT001", "GT002", "GT005", "TS001", "TS003",
];

/// An observed action the kernel can classify.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedAction {
    /// Relative path under consideration.
    pub path: Option<String>,
    /// Whether the workspace is a git worktree.
    pub is_worktree: Option<bool>,
    /// Whether a bound preservation receipt exists.
    pub has_preservation_receipt: Option<bool>,
    /// Exact Candidate id when one exists.
    pub candidate_id: Option<String>,
    /// Provider claimed completion.
    pub done: bool,
    /// Workspace dirtiness if known.
    pub dirty_workspace: Option<bool>,
    /// Observation kind: value | empty | unknown | contradictory.
    pub observation_kind: Option<String>,
    /// Raw command line if intercepted.
    pub command: Option<String>,
    /// Whether cleanup was requested.
    pub cleanup: bool,
    /// Whether the writer produced the only evidence.
    pub writer_only_evidence: bool,
    /// Gate result string if any.
    pub gate_result: Option<String>,
}

/// One fired catalog hit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorEvent {
    /// Rule identifier.
    pub rule_id: String,
    /// Detector name.
    pub detector: String,
    /// Observed action summary.
    pub observed_action: String,
    /// Enforcement name.
    pub enforcement_action: String,
}

/// Run the shipped detectors. Unknown facts fail closed.
#[must_use]
pub fn detect(action: &ObservedAction) -> Vec<BehaviorEvent> {
    let mut hits = Vec::new();
    if action.is_worktree == Some(true) || action.command.as_deref().is_some_and(is_worktree_cmd) {
        push(&mut hits, "GT001", "worktree_guard", "writable worktree");
    }
    if action.cleanup && action.has_preservation_receipt != Some(true) {
        push(
            &mut hits,
            "CL001",
            "cleanup_service",
            "delete without receipt",
        );
    }
    if action
        .observation_kind
        .as_deref()
        .is_some_and(|kind| kind == "unknown" || kind == "contradictory")
        && action.cleanup
    {
        push(
            &mut hits,
            "CL002",
            "observation_guard",
            "unknown treated as clean",
        );
    }
    if action.done && action.dirty_workspace != Some(false) {
        push(
            &mut hits,
            "CP001",
            "git_reconciler",
            "done with dirty workspace",
        );
    }
    if action.done && action.candidate_id.as_deref().unwrap_or("").is_empty() {
        push(
            &mut hits,
            "CP002",
            "candidate_service",
            "done without candidate",
        );
    }
    if action
        .path
        .as_deref()
        .is_some_and(|path| path.contains(".git/") || path.ends_with(".git"))
    {
        push(
            &mut hits,
            "GT002",
            "filesystem_boundary",
            "direct .git write",
        );
    }
    if action
        .command
        .as_deref()
        .is_some_and(|cmd| cmd.contains("git push") || cmd.contains("git push --force"))
    {
        push(&mut hits, "GT005", "sandbox_egress", "push from sandbox");
    }
    if action
        .gate_result
        .as_deref()
        .is_some_and(|result| matches!(result, "FLAKY" | "TIMED_OUT" | "INFRA_ERROR" | "UNKNOWN"))
        && action.done
    {
        push(&mut hits, "TS003", "typed_gate", "non-pass treated as pass");
    }
    if action.writer_only_evidence && action.done {
        push(
            &mut hits,
            "TS001",
            "completion_evaluator",
            "writer claim without independent evidence",
        );
    }
    if action.path.as_deref().is_some_and(is_runtime_artifact) {
        push(
            &mut hits,
            "FS004",
            "artifact_manifest",
            "runtime file in product repo",
        );
    }
    hits
}

fn push(hits: &mut Vec<BehaviorEvent>, id: &str, detector: &str, observed: &str) {
    let row: &CatalogRow = row_by_id(id).expect("catalog id");
    hits.push(BehaviorEvent {
        rule_id: id.to_string(),
        detector: detector.to_string(),
        observed_action: observed.to_string(),
        enforcement_action: format!("{:?}", row.action).to_ascii_lowercase(),
    });
}

fn is_worktree_cmd(command: &str) -> bool {
    command.contains("git worktree") || command.contains("--worktree")
}

fn is_runtime_artifact(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        ".claude" | ".codex" | ".cursor" | "CLAUDE.md" | "agent-transcript.jsonl"
    ) || path.contains("/.claude/")
        || path.contains("/.codex/")
}
