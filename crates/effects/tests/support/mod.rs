//! Shared fixtures: real git repositories and a leased authority token.
#![allow(dead_code)]

use bullet_application::{
    materialize_plan, LeaseGrant, LeaseService, MemoryLedger, PlanInput, StoredGraph, ZERO_OID,
};
use bullet_domain::{AuthorityToken, TaskClass};
use bullet_effects_core::IntentInput;
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn sh(dir: &Path, script: &str) {
    let out = Command::new("sh")
        .arg("-ec")
        .arg(script)
        .current_dir(dir)
        .output()
        .expect("fixture script");
    assert!(
        out.status.success(),
        "fixture failed: {script}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

pub fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Real repositories for one test: a two-commit workspace and a bare target.
pub struct Repos {
    pub tmp: tempfile::TempDir,
    pub workspace: PathBuf,
    pub bare: PathBuf,
    pub base: String,
    pub head: String,
}

pub fn repos() -> Repos {
    let tmp = tempfile::tempdir().expect("tempdir");
    let workspace = tmp.path().join("workspace");
    let bare = tmp.path().join("target.git");
    std::fs::create_dir_all(&workspace).expect("mkdir");
    sh(
        &workspace,
        "git init -q -b main . && \
         git config user.name bullet && git config user.email bullet@test && \
         echo base > f && git add . && git commit -qm base && \
         echo head > f && git add . && git commit -qm head",
    );
    let base = git_out(&workspace, &["rev-parse", "HEAD~1"]);
    let head = git_out(&workspace, &["rev-parse", "HEAD"]);
    Repos {
        tmp,
        workspace,
        bare,
        base,
        head,
    }
}

pub fn now() -> String {
    LeaseService::rfc3339(Utc::now())
}

/// A memory ledger with one materialized graph and one live writer lease.
pub struct Authority {
    pub ledger: MemoryLedger,
    pub graph: StoredGraph,
    pub token: AuthorityToken,
    pub grant: LeaseGrant,
}

pub fn authority(seed: &str) -> Authority {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: format!("effects {seed}"),
            objective: "effect broker tests".into(),
            packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
        },
        &now(),
    )
    .expect("plan");
    let (_attempt, token, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, &format!("{seed}-a1"), 15).expect("lease");
    Authority {
        ledger,
        graph,
        token,
        grant,
    }
}

/// Create-semantics intent input bound to the live token.
pub fn intent_input(token: &AuthorityToken, repos: &Repos, suffix: &str) -> IntentInput {
    IntentInput {
        provider: "local-bare".into(),
        logical_effect_key: format!("push:{suffix}"),
        target_ref: format!("refs/heads/bullet/candidate/{suffix}"),
        new_oid: repos.head.clone(),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: token.attempt_id.clone(),
        fence: token.attempt_fence,
        policy_version: "policy-v1".into(),
        provider_idempotency_key: None,
    }
}
