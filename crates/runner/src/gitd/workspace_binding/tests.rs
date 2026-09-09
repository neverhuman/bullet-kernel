use super::*;
use bullet_domain::{
    AcceptanceContractId, AttemptId, MissionId, OrganizationId, PlanRevisionId, RepositoryId,
    RunnerId, SelectionGroupId, VariantId, WorkPackageId, WorkspaceId,
};

fn authority() -> AuthorityToken {
    AuthorityToken {
        organization_id: OrganizationId::from_seed("workspace-binding"),
        repository_id: RepositoryId::from_seed("workspace-binding"),
        mission_id: MissionId::from_seed("workspace-binding"),
        acceptance_contract_id: AcceptanceContractId::from_seed("workspace-binding"),
        plan_revision_id: PlanRevisionId::from_seed("workspace-binding"),
        graph_sequence: 1,
        work_package_id: WorkPackageId::from_seed("workspace-binding"),
        selection_group_id: SelectionGroupId::from_seed("workspace-binding"),
        variant_id: VariantId::from_seed("workspace-binding"),
        attempt_id: AttemptId::from_seed("workspace-binding"),
        attempt_fence: 1,
        runner_id: RunnerId::from_seed("workspace-binding"),
        runner_epoch: 1,
        workspace_id: WorkspaceId::from_seed("workspace-binding"),
        workspace_nonce: [7; 32],
        scope_revision: 1,
        context_revision: 1,
        config_snapshot_hash: Digest::of(b"config"),
        policy_snapshot_hash: Digest::of(b"policy"),
        routing_policy_hash: Digest::of(b"routing"),
        credential_profile_id: None,
        credential_generation: None,
    }
}

fn fixture() -> (tempfile::TempDir, AuthorityToken, WorkspaceInfo) {
    let root = tempfile::tempdir().expect("root");
    let authority = authority();
    let runtime = root
        .path()
        .join("runtime")
        .join(authority.attempt_id.as_str());
    let repo = generation_repo(root.path(), &authority, 0);
    fs::create_dir_all(&runtime).expect("runtime");
    fs::create_dir_all(&repo).expect("generation zero");
    let active_generation = ActiveGenerationBinding::test_only(
        &authority,
        0,
        None,
        "generation-zero",
        "sha1:1111111111111111111111111111111111111111",
    );
    let base = active_generation.checkpoint_binding();
    let info = WorkspaceInfo {
        repo_dir: repo,
        runtime_dir: runtime,
        branch: "bullet/test/attempt".into(),
        base_sha: "sha1:1111111111111111111111111111111111111111".into(),
        base_checkpoint_id: base.id,
        base_checkpoint_digest: base.digest,
        active_generation,
    };
    (root, authority, info)
}

fn successor(
    root: &Path,
    authority: &AuthorityToken,
    current: &ActiveGenerationBinding,
    repo_dir: PathBuf,
    git_tree: &str,
) -> ApplyProposalReceipt {
    let active_generation =
        ActiveGenerationBinding::test_only(authority, 1, Some(current), "generation-one", git_tree);
    let checkpoint = active_generation.checkpoint_binding();
    let expected = generation_repo(root, authority, 1);
    fs::create_dir_all(&expected).expect("generation one");
    ApplyProposalReceipt {
        proposal_id: format!("cnt_{}", "1".repeat(64)),
        applied: 1,
        checkpoint,
        repo_dir,
        active_generation,
    }
}

#[test]
fn exact_initial_and_successor_generation_are_admitted() {
    let (root, authority, mut info) = fixture();
    info.validate_initial(root.path(), &info.base_sha.clone(), &authority)
        .expect("initial identity");
    let next = generation_repo(root.path(), &authority, 1);
    let receipt = successor(
        root.path(),
        &authority,
        &info.active_generation,
        next.clone(),
        "sha1:2222222222222222222222222222222222222222",
    );
    info.accept_successor(&receipt, &authority)
        .expect("successor identity");
    assert_eq!(info.repo_dir, next);
    assert_eq!(info.active_generation.generation, 1);
}

#[test]
fn stale_generation_zero_path_is_refused_before_gate() {
    let (root, authority, mut info) = fixture();
    let stale = info.repo_dir.clone();
    let receipt = successor(
        root.path(),
        &authority,
        &info.active_generation,
        stale.clone(),
        "sha1:2222222222222222222222222222222222222222",
    );
    assert!(info.accept_successor(&receipt, &authority).is_err());
    assert_eq!(info.repo_dir, stale);
    assert_eq!(info.active_generation.generation, 0);
}

#[test]
fn outside_directory_is_refused_even_when_it_would_pass_the_gate() {
    let (root, authority, mut info) = fixture();
    let outside = root.path().join("outside");
    fs::create_dir(&outside).expect("outside");
    fs::write(outside.join("PONG.txt"), "PONG\n").expect("outside marker");
    let receipt = successor(
        root.path(),
        &authority,
        &info.active_generation,
        outside.clone(),
        "sha1:2222222222222222222222222222222222222222",
    );
    assert!(info.accept_successor(&receipt, &authority).is_err());
    assert_ne!(info.repo_dir, outside);
    assert!(outside.join("PONG.txt").is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn expected_path_replaced_by_symlink_is_refused_before_gate() {
    use std::os::unix::fs::symlink;

    let (root, authority, mut info) = fixture();
    let expected = generation_repo(root.path(), &authority, 1);
    let outside = root.path().join("outside-symlink-target");
    fs::create_dir(&outside).expect("outside");
    fs::write(outside.join("PONG.txt"), "PONG\n").expect("outside marker");
    let receipt = successor(
        root.path(),
        &authority,
        &info.active_generation,
        expected.clone(),
        "sha1:2222222222222222222222222222222222222222",
    );
    fs::remove_dir_all(&expected).expect("remove expected directory");
    symlink(&outside, &expected).expect("replace with symlink");
    assert!(info.accept_successor(&receipt, &authority).is_err());
    assert_ne!(info.repo_dir, outside);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ordinary_generation_substitution_fails_exact_tree_verification() {
    use crate::gate::GateWorkdir;

    let (root, authority, info) = fixture();
    let root_guard = WorkspaceRootGuard::open(root.path()).expect("retained root");
    let generation_guard = root_guard.bind(&authority, 0).expect("generations");
    let expected = generation_repo(root.path(), &authority, 1);
    fs::create_dir_all(&expected).expect("generation one");
    let expected_tree = init_git_tree(&expected, "CURRENT\n");
    let tagged_tree = format!("sha1:{expected_tree}");
    let receipt = successor(
        root.path(),
        &authority,
        &info.active_generation,
        expected.clone(),
        &tagged_tree,
    );
    info.validate_successor(&receipt, &authority)
        .expect("valid response before substitution");

    let generation_dir = expected.parent().expect("generation directory");
    let retained = root.path().join("retained-generation-one");
    fs::rename(generation_dir, &retained).expect("displace valid generation");
    fs::create_dir_all(&expected).expect("ordinary replacement");
    let stale_tree = init_git_tree(&expected, "STALE\n");
    assert_ne!(stale_tree, expected_tree);

    let opened = generation_guard.open_generation(1).expect("ordinary child");
    let gate_workdir = GateWorkdir::from_file(opened).expect("opened replacement");
    let error = gate_workdir
        .verify_git_tree(&tagged_tree)
        .await
        .expect_err("stale ordinary replacement refused");
    assert_eq!(error.reason_code(), "GATE_FAILED");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn private_expected_tree_ignores_substituted_skip_worktree_index_flags() {
    use crate::gate::GateWorkdir;

    let root = tempfile::tempdir().expect("root");
    let repo = root.path().join("repo");
    fs::create_dir(&repo).expect("repo");
    let expected_tree = init_git_tree(&repo, "EXPECTED\n");
    let status = std::process::Command::new("/usr/bin/git")
        .args(["update-index", "--skip-worktree", "PONG.txt"])
        .current_dir(&repo)
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("set hostile index flag");
    assert!(status.success());
    fs::write(repo.join("PONG.txt"), "STALE\n").expect("stale bytes");

    let gate_workdir =
        GateWorkdir::from_file(fs::File::open(&repo).expect("open repo")).expect("opened repo");
    gate_workdir
        .verify_git_tree(&format!("sha1:{expected_tree}"))
        .await
        .expect_err("private index must hash stale worktree bytes");
}

fn init_git_tree(repo: &Path, contents: &str) -> String {
    let run = |args: &[&str]| {
        let output = std::process::Command::new("/usr/bin/git")
            .args(args)
            .current_dir(repo)
            .env("HOME", "/nonexistent")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("test Git");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };
    run(&["init", "-q"]);
    fs::write(repo.join("PONG.txt"), contents).expect("test worktree");
    run(&["add", "PONG.txt"]);
    run(&["write-tree"])
}
