//! Exact BulletGit preservation-shaped receipt fixture.

use bullet_domain::{CandidateId, Digest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize, Serialize)]
struct Subject {
    schema_version: u32,
    attempt_id: String,
    attempt_fence: u64,
    workspace_nonce_hex: String,
    generation: u64,
    git_tree: String,
    generation_digest: String,
    dirty_untracked: Vec<Value>,
    journal_start: u64,
    journal_end: u64,
    journal_root: String,
}

#[derive(Deserialize, Serialize)]
struct SealedReceipt {
    payload: ReceiptPayload,
    tag: String,
}

#[derive(Deserialize, Serialize)]
struct ReceiptPayload {
    schema_version: u32,
    state_digest: String,
    artifact_digest: String,
    destination: String,
    destination_device: u64,
    destination_inode: u64,
    cleanup_target: String,
}

#[derive(Serialize)]
struct WorkspaceManifest {
    attempt_id: String,
    variant_id: String,
    base_sha: String,
    branch: String,
    created_at: String,
    nonce_hex: String,
    source_repo: String,
    mirror_dir: String,
    object_materialization: String,
    repo_dir: String,
}

#[derive(Deserialize, Serialize)]
struct CleanupTombstone {
    attempt_id: String,
    deleted_at: String,
    nonce_hex: String,
    preservation_artifact_digest: String,
    preservation_destination: String,
    preservation_receipt_digest: String,
    schema_version: u32,
    variant_id: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn fixture(
    artifacts: &Path,
    _run: &Path,
    candidate: &Path,
    candidate_id: &CandidateId,
    attempt_id: &str,
    base: &str,
    head: &str,
    tree: &str,
) -> Value {
    let patch = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(candidate)
        .args(["diff", "--binary", &format!("{base}..{head}")])
        .output()
        .unwrap();
    assert!(patch.status.success());
    let patch_hash = Digest::of(&patch.stdout).to_hex();
    let root = artifacts.join("preserve");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    private_dir(&root.join("cas"));
    private_dir(&root.join("generation/journal"));
    write_compact(&root.join("generation/manifest.json"), &json!({"schema":1}));
    let bundle = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(candidate)
        .args([
            "bundle",
            "create",
            root.join("repository.bundle").to_str().unwrap(),
            "--all",
        ])
        .output()
        .unwrap();
    assert!(
        bundle.status.success(),
        "{}",
        String::from_utf8_lossy(&bundle.stderr)
    );

    let variant_id = format!("var_{}", "8".repeat(64));
    let nonce_hex = "9".repeat(64);
    let execution = artifacts.join("runner-execution");
    let work = execution.join("work");
    let runtime = execution.join("runtime").join(attempt_id);
    let mirrors = execution.join("mirrors");
    private_dir(&work);
    private_dir(&runtime);
    private_dir(&mirrors);
    let mirror = mirrors.join("source.git");
    private_dir(&mirror);
    let cleanup_target = work.join(attempt_id);
    let original_repo = cleanup_target.join("generations/generation-00000000000000000000/repo");
    write_pretty(
        &root.join("workspace.json"),
        &WorkspaceManifest {
            attempt_id: attempt_id.into(),
            variant_id: variant_id.clone(),
            base_sha: format!("sha1:{base}"),
            branch: format!("bullet/{variant_id}/{attempt_id}"),
            created_at: "2026-08-28T08:00:00.000Z".into(),
            nonce_hex: nonce_hex.clone(),
            source_repo: artifacts.join("source").display().to_string(),
            mirror_dir: mirror.display().to_string(),
            object_materialization: "fallback".into(),
            repo_dir: original_repo.display().to_string(),
        },
    );
    let generation_digest =
        super::super::preservation::artifact_digest_for_fixture(&root.join("generation")).unwrap();
    let subject = Subject {
        schema_version: 1,
        attempt_id: attempt_id.into(),
        attempt_fence: 1,
        workspace_nonce_hex: nonce_hex.clone(),
        generation: 1,
        git_tree: format!("sha1:{tree}"),
        generation_digest,
        dirty_untracked: Vec::new(),
        journal_start: 1,
        journal_end: 1,
        journal_root: "b".repeat(64),
    };
    write_compact(&root.join("subject.json"), &subject);
    let state_digest = super::super::preservation::state_digest_for_fixture(&subject).unwrap();
    let artifact_digest = super::super::preservation::artifact_digest_for_fixture(&root).unwrap();
    let metadata = std::fs::symlink_metadata(&root).unwrap();
    let token = hex::encode(
        serde_json::to_vec(&SealedReceipt {
            payload: ReceiptPayload {
                schema_version: 1,
                state_digest,
                artifact_digest: artifact_digest.clone(),
                destination: root.display().to_string(),
                destination_device: metadata.dev(),
                destination_inode: metadata.ino(),
                cleanup_target: cleanup_target.display().to_string(),
            },
            tag: "e".repeat(64),
        })
        .unwrap(),
    );
    let receipt_digest = Digest::of(token.as_bytes()).to_hex();
    write_compact(
        &runtime.join("tombstone.json"),
        &CleanupTombstone {
            attempt_id: attempt_id.into(),
            deleted_at: "2026-08-28T08:01:00.000Z".into(),
            nonce_hex,
            preservation_artifact_digest: artifact_digest.clone(),
            preservation_destination: root.display().to_string(),
            preservation_receipt_digest: receipt_digest.clone(),
            schema_version: 1,
            variant_id,
        },
    );
    json!({
        "candidate_id":candidate_id,"base_commit":format!("sha1:{base}"),
        "head_commit":format!("sha1:{head}"),"tree_hash":format!("sha1:{tree}"),
        "patch_hash":patch_hash,"attempt_id":attempt_id,"fence":1,
        "receipt":{"token":token,"digest":receipt_digest,
            "artifact_digest":artifact_digest,"destination":root}
    })
}

pub(super) fn tombstone_path(run: &Path, attempt_id: &str) -> PathBuf {
    run.join("artifacts/runner-execution/runtime")
        .join(attempt_id)
        .join("tombstone.json")
}

pub(super) fn substitute_token(value: &mut Value, field: &str, replacement: &str) {
    let token = value["product_runner_preservation"]["receipt"]["token"]
        .as_str()
        .unwrap();
    let mut sealed: SealedReceipt = serde_json::from_slice(&hex::decode(token).unwrap()).unwrap();
    match field {
        "tag" => sealed.tag = replacement.into(),
        "state_digest" => sealed.payload.state_digest = replacement.into(),
        "artifact_digest" => {
            sealed.payload.artifact_digest = replacement.into();
            value["product_runner_preservation"]["receipt"]["artifact_digest"] = json!(replacement);
        }
        "cleanup_target" => sealed.payload.cleanup_target = replacement.into(),
        _ => panic!("unsupported token field"),
    }
    let token = hex::encode(serde_json::to_vec(&sealed).unwrap());
    value["product_runner_preservation"]["receipt"]["digest"] =
        json!(Digest::of(token.as_bytes()).to_hex());
    value["product_runner_preservation"]["receipt"]["token"] = json!(token);
}

pub(super) fn substitute_tombstone(run: &Path, attempt_id: &str, field: &str, replacement: &str) {
    let path = tombstone_path(run, attempt_id);
    let mut tombstone: CleanupTombstone =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    match field {
        "attempt_id" => tombstone.attempt_id = replacement.into(),
        "variant_id" => tombstone.variant_id = replacement.into(),
        "nonce_hex" => tombstone.nonce_hex = replacement.into(),
        "artifact_digest" => tombstone.preservation_artifact_digest = replacement.into(),
        "destination" => tombstone.preservation_destination = replacement.into(),
        "receipt_digest" => tombstone.preservation_receipt_digest = replacement.into(),
        _ => panic!("unsupported tombstone field"),
    }
    rewrite_compact(&path, &tombstone);
}

pub(super) fn substitute_state(root: &Path) {
    let path = root.join("subject.json");
    let mut subject: Subject = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    subject.journal_root = "0".repeat(64);
    rewrite_compact(&path, &subject);
}

fn write_compact(path: &Path, value: &impl Serialize) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    file.sync_all().unwrap();
}

fn write_pretty(path: &Path, value: &impl Serialize) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}

fn rewrite_compact(path: &Path, value: &impl Serialize) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    file.sync_all().unwrap();
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
