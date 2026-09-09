//! Clean-room pipeline against real git repositories: every typed outcome,
//! the exact-subject invalidations, and the author-overlap refusal.

use bullet_verifier_core::{execute, EvidenceTier, GateId, GateOutcome, VerifierRequest};
use std::path::Path;
use std::process::Command;

fn sh(dir: &Path, script: &str) {
    // Fixture helpers strip repo-redirection variables themselves so the
    // hostile-GIT_DIR test cannot race concurrently running fixtures; the
    // verifier under test clears its child environment on its own.
    let out = Command::new("sh")
        .arg("-ec")
        .arg(script)
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("run fixture script");
    assert!(
        out.status.success(),
        "fixture failed: {script}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Build a two-commit source repo; returns (base, head, tree).
fn source_repo(dir: &Path) -> (String, String, String) {
    sh(
        dir,
        "git init -q -b main . && \
         git config user.name bullet && git config user.email bullet@test && \
         echo PONG > PONG.txt && echo base > file.txt && git add . && git commit -qm base && \
         echo head > file.txt && git add . && git commit -qm head",
    );
    let base = git_out(dir, &["rev-parse", "HEAD~1"]);
    let head = git_out(dir, &["rev-parse", "HEAD"]);
    let tree = git_out(dir, &["rev-parse", "HEAD^{tree}"]);
    (base, head, tree)
}

fn request(dir: &Path, base: &str, head: &str, tree: &str) -> VerifierRequest {
    VerifierRequest {
        workspace_repo_path: dir.display().to_string(),
        base_sha: base.into(),
        head_sha: head.into(),
        tree_sha: tree.into(),
        gate_id: GateId::parse(bullet_domain::REPOSITORY_GATE_ID).unwrap(),
        author_attempt_id: concat!(
            "atm_",
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .into(),
    }
}

#[tokio::test]
async fn pass_produces_e2_evidence_with_exact_subject() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, head, tree) = source_repo(dir.path());
    let record = execute(&request(dir.path(), &base, &head, &tree), false)
        .await
        .expect("record");
    assert_eq!(record.outcome, GateOutcome::Pass);
    assert_eq!(record.tier, EvidenceTier::E2);
    assert_eq!(record.exit_code, Some(0));
    assert_eq!(record.subject.base_sha, base);
    assert_eq!(record.subject.head_sha, head);
    assert_eq!(record.subject.tree_sha, tree);
    assert_eq!(record.gate_id.as_str(), bullet_domain::REPOSITORY_GATE_ID);
    assert_eq!(record.argv, ["/usr/bin/grep", "-qx", "PONG", "PONG.txt"]);
    assert_eq!(record.timeout_secs, 2);
    assert_eq!(record.produced_by, "bullet-verifier");
    assert!(record.environment.contains_key("git"));
    assert!(record.outcome.satisfies_requirement());
}

#[tokio::test]
async fn hostile_inherited_git_dir_does_not_leak_into_clone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, head, tree) = source_repo(dir.path());
    // The clean clone must ignore a hostile inherited GIT_DIR entirely.
    std::env::set_var("GIT_DIR", "/nonexistent-bullet-hostile");
    let record = execute(&request(dir.path(), &base, &head, &tree), false)
        .await
        .expect("record");
    std::env::remove_var("GIT_DIR");
    assert_eq!(record.outcome, GateOutcome::Pass);
}

#[tokio::test]
async fn failing_gate_is_fail_with_exit_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_base, prior, _tree) = source_repo(dir.path());
    sh(
        dir.path(),
        "echo 'NOT PONG' > PONG.txt && git add PONG.txt && git commit -qm fail-gate",
    );
    let head = git_out(dir.path(), &["rev-parse", "HEAD"]);
    let tree = git_out(dir.path(), &["rev-parse", "HEAD^{tree}"]);
    let record = execute(&request(dir.path(), &prior, &head, &tree), false)
        .await
        .expect("record");
    assert_eq!(record.outcome, GateOutcome::Fail);
    assert_eq!(record.exit_code, Some(1));
    assert_eq!(record.reason.as_deref(), Some("GATE_NONZERO_EXIT"));
    assert!(!record.outcome.satisfies_requirement());
}

#[tokio::test]
async fn tree_mismatch_is_invalidated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, head, _tree) = source_repo(dir.path());
    let wrong_tree = "d".repeat(40);
    let record = execute(&request(dir.path(), &base, &head, &wrong_tree), false)
        .await
        .expect("record");
    assert_eq!(record.outcome, GateOutcome::Invalidated);
    assert_eq!(record.reason.as_deref(), Some("TREE_MISMATCH"));
}

#[tokio::test]
async fn base_outside_ancestry_is_invalidated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_base, head, tree) = source_repo(dir.path());
    let foreign = "e".repeat(40);
    let record = execute(&request(dir.path(), &foreign, &head, &tree), false)
        .await
        .expect("record");
    assert_eq!(record.outcome, GateOutcome::Invalidated);
    assert_eq!(record.reason.as_deref(), Some("BASE_NOT_ANCESTOR"));
}

#[tokio::test]
async fn unreachable_head_is_invalidated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, _head, tree) = source_repo(dir.path());
    let ghost = "f".repeat(40);
    let record = execute(&request(dir.path(), &base, &ghost, &tree), false)
        .await
        .expect("record");
    assert_eq!(record.outcome, GateOutcome::Invalidated);
    assert_eq!(record.reason.as_deref(), Some("HEAD_UNREACHABLE"));
}

#[tokio::test]
async fn author_overlap_is_refused_before_any_work() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, head, tree) = source_repo(dir.path());
    let err = execute(&request(dir.path(), &base, &head, &tree), true)
        .await
        .expect_err("refused");
    assert_eq!(err.reason_code(), "VERIFIER_IS_AUTHOR");
}

#[tokio::test]
async fn unclonable_source_is_infra_error_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("nope");
    let record = execute(
        &request(&missing, &"a".repeat(40), &"b".repeat(40), &"c".repeat(40)),
        false,
    )
    .await
    .expect("record");
    assert_eq!(record.outcome, GateOutcome::InfraError);
    assert_eq!(record.reason.as_deref(), Some("CLONE_FAILED"));
}
