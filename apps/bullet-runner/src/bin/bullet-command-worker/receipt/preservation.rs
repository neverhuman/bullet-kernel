//! Product Runner preservation and exact retained-patch admission.

#[path = "preservation/artifact.rs"]
mod artifact;

use super::{artifacts, bounded_output::BoundedOutput, invalid, ComponentReceipt, RetainedPaths};
use crate::error::{WorkerContext, WorkerError};
use artifact::{artifact_digest, preservation_state_digest, read_pretty, require_artifact_shape};
use bullet_domain::Digest;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PATCH_DEADLINE: Duration = Duration::from_secs(5);
const PATCH_LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreservationSubject {
    schema_version: u32,
    attempt_id: String,
    attempt_fence: u64,
    workspace_nonce_hex: String,
    generation: u64,
    git_tree: String,
    generation_digest: String,
    dirty_untracked: Vec<WorkingEntry>,
    journal_start: u64,
    journal_end: u64,
    journal_root: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkingEntry {
    path: String,
    status: String,
    kind: String,
    content_digest: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedReceiptView {
    payload: ReceiptPayloadView,
    tag: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPayloadView {
    schema_version: u32,
    state_digest: String,
    artifact_digest: String,
    destination: String,
    destination_device: u64,
    destination_inode: u64,
    cleanup_target: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

pub(super) fn validate(
    receipt: &ComponentReceipt,
    paths: &RetainedPaths,
) -> Result<(), WorkerError> {
    // Component boundary only: the worker has no admitted public preservation
    // verification key, and same-UID custody can coherently rewrite these
    // bytes. The checks below prove complete internal linkage, not independent
    // or release-grade attestation.
    let preservation = &receipt.product_runner_preservation;
    let destination = paths
        .candidate
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| invalid("retained Candidate has no preservation destination"))?;
    if artifacts::canonical_dir(destination)? != destination
        || preservation.candidate_id != receipt.candidate_id
        || preservation.base_commit != format!("sha1:{}", receipt.base_oid)
        || preservation.head_commit != format!("sha1:{}", receipt.head_oid)
        || preservation.tree_hash != format!("sha1:{}", receipt.tree_oid)
        || !artifacts::lower_hex(&preservation.patch_hash, 64)
        || preservation.attempt_id.as_str() != receipt.attempt_first
        || preservation.fence != receipt.fence_first
        || preservation.receipt.destination != destination
        || preservation.receipt.token.is_empty()
    {
        return Err(invalid(
            "product Runner preservation differs from the retained Candidate",
        ));
    }
    let payload = decode_sealed_receipt(preservation, destination)?;

    let subject: PreservationSubject = artifacts::read_state(&destination.join("subject.json"))?;
    let entries_valid = subject.dirty_untracked.iter().all(|entry| {
        !entry.path.is_empty()
            && !entry.status.is_empty()
            && !entry.kind.is_empty()
            && entry
                .content_digest
                .as_deref()
                .is_none_or(|digest| artifacts::lower_hex(digest, 64))
    });
    if subject.schema_version != 1
        || subject.attempt_id != receipt.attempt_first
        || subject.attempt_fence != receipt.fence_first
        || !artifacts::lower_hex(&subject.workspace_nonce_hex, 64)
        || subject.generation == 0
        || subject.git_tree != preservation.tree_hash
        || !artifacts::lower_hex(&subject.generation_digest, 64)
        || subject.journal_start > subject.journal_end
        || !artifacts::lower_hex(&subject.journal_root, 64)
        || !entries_valid
    {
        return Err(invalid(
            "retained preservation subject differs from producing authority",
        ));
    }
    let state_digest = preservation_state_digest(&subject)?;
    if payload.state_digest != state_digest {
        return Err(invalid(
            "preservation state digest differs from the retained subject",
        ));
    }

    let execution = paths
        .source
        .parent()
        .ok_or_else(|| invalid("retained source has no artifact root"))?
        .join("runner-execution");
    let cleanup_target = execution.join("work").join(&receipt.attempt_first);
    let runtime = execution.join("runtime").join(&receipt.attempt_first);
    let workspace: WorkspaceManifest = read_pretty(&destination.join("workspace.json"))?;
    validate_workspace(
        &workspace,
        &subject,
        paths,
        &execution,
        &cleanup_target,
        receipt,
    )?;
    let cleanup_absent = match std::fs::symlink_metadata(&cleanup_target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Ok(_) | Err(_) => false,
    };
    if payload.cleanup_target != cleanup_target.display().to_string() || !cleanup_absent {
        return Err(invalid(
            "preservation cleanup target differs or survived successful cleanup",
        ));
    }

    require_artifact_shape(destination)?;
    let generation_digest = artifact_digest(&destination.join("generation"))?;
    if generation_digest != subject.generation_digest {
        return Err(invalid(
            "preserved generation differs from the recorded generation digest",
        ));
    }
    let artifact_digest = artifact_digest(destination)?;
    if payload.artifact_digest != artifact_digest
        || preservation.receipt.artifact_digest != artifact_digest
    {
        return Err(invalid(
            "preservation artifact digest differs from retained bytes",
        ));
    }
    validate_tombstone(
        &runtime,
        &workspace,
        &subject,
        preservation,
        destination,
        &artifact_digest,
    )?;

    let patch = patch_digest(&paths.candidate, &receipt.base_oid, &receipt.head_oid)?;
    if patch != preservation.patch_hash {
        return Err(invalid(
            "retained Candidate patch differs from product Runner preservation",
        ));
    }
    Ok(())
}

fn decode_sealed_receipt(
    preservation: &bullet_runner_core::CandidatePreservation,
    destination: &Path,
) -> Result<ReceiptPayloadView, WorkerError> {
    let token = &preservation.receipt.token;
    if token.len() > 64 * 1024
        || token.len() % 2 != 0
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || preservation.receipt.digest != Digest::of(token.as_bytes()).to_hex()
    {
        return Err(invalid(
            "preservation sealed receipt encoding or digest differs",
        ));
    }
    let decoded = hex::decode(token).map_err(invalid)?;
    let sealed: SealedReceiptView = serde_json::from_slice(&decoded).map_err(invalid)?;
    if hex::encode(serde_json::to_vec(&sealed).map_err(invalid)?) != *token {
        return Err(invalid(
            "preservation sealed receipt is not exact compact JSON hex",
        ));
    }
    let metadata = std::fs::symlink_metadata(destination).map_err(invalid)?;
    let payload = sealed.payload;
    if payload.schema_version != 1
        || payload.artifact_digest != preservation.receipt.artifact_digest
        || payload.destination != destination.display().to_string()
        || payload.destination_device != metadata.dev()
        || payload.destination_inode != metadata.ino()
        || !Path::new(&payload.cleanup_target).is_absolute()
        || !artifacts::lower_hex(&payload.state_digest, 64)
        || !artifacts::lower_hex(&payload.artifact_digest, 64)
        || !artifacts::lower_hex(&sealed.tag, 64)
    {
        return Err(invalid(
            "preservation sealed payload differs from retained artifact",
        ));
    }
    // `tag` is a daemon-only keyed-BLAKE3 seal. This worker does not possess
    // that symmetric authority and must not claim cryptographic verification.
    // The exact token's successful daemon admission is instead proven below
    // by the cleanup tombstone's receipt digest.
    Ok(payload)
}

fn validate_workspace(
    workspace: &WorkspaceManifest,
    subject: &PreservationSubject,
    paths: &RetainedPaths,
    execution: &Path,
    cleanup_target: &Path,
    receipt: &ComponentReceipt,
) -> Result<(), WorkerError> {
    let repo = Path::new(&workspace.repo_dir);
    let recorded_cleanup = repo
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| invalid("workspace manifest repository path is incomplete"))?;
    let mirror = Path::new(&workspace.mirror_dir);
    let coherent = workspace.attempt_id == receipt.attempt_first
        && artifacts::full_id(&workspace.variant_id, "var")
        && workspace.base_sha == format!("sha1:{}", receipt.base_oid)
        && workspace.branch == format!("bullet/{}/{}", workspace.variant_id, receipt.attempt_first)
        && !workspace.created_at.is_empty()
        && workspace.nonce_hex == subject.workspace_nonce_hex
        && workspace.source_repo == paths.source.display().to_string()
        && mirror.starts_with(execution.join("mirrors"))
        && artifacts::canonical_dir(mirror).is_ok()
        && matches!(
            workspace.object_materialization.as_str(),
            "reflink" | "fallback"
        )
        && recorded_cleanup == cleanup_target
        && repo.file_name().and_then(|name| name.to_str()) == Some("repo")
        && repo
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("generation-") && name.len() == 31);
    coherent
        .then_some(())
        .ok_or_else(|| invalid("preserved workspace manifest differs from exact cleanup authority"))
}

fn validate_tombstone(
    runtime: &Path,
    workspace: &WorkspaceManifest,
    subject: &PreservationSubject,
    preservation: &bullet_runner_core::CandidatePreservation,
    destination: &Path,
    artifact_digest: &str,
) -> Result<(), WorkerError> {
    require_private_dir(runtime)?;
    let tombstone: CleanupTombstone = artifacts::read_state(&runtime.join("tombstone.json"))?;
    let fixed = tombstone.schema_version == 1
        && tombstone.attempt_id == workspace.attempt_id
        && tombstone.variant_id == workspace.variant_id
        && tombstone.nonce_hex == subject.workspace_nonce_hex
        && tombstone.deleted_at.len() <= 64
        && tombstone.deleted_at.ends_with('Z')
        && tombstone
            .deleted_at
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        && tombstone.preservation_receipt_digest == preservation.receipt.digest
        && tombstone.preservation_receipt_digest
            == Digest::of(preservation.receipt.token.as_bytes()).to_hex()
        && tombstone.preservation_artifact_digest == artifact_digest
        && tombstone.preservation_destination == destination.display().to_string();
    fixed.then_some(()).ok_or_else(|| {
        invalid("daemon cleanup tombstone differs from the exact preservation receipt")
    })
}

fn require_private_dir(path: &Path) -> Result<(), WorkerError> {
    let metadata = std::fs::symlink_metadata(path).map_err(invalid)?;
    if path.canonicalize().ok().as_deref() != Some(path)
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(invalid(
            "preservation directory is not canonical private custody",
        ));
    }
    Ok(())
}

fn patch_digest(
    repository: &std::path::Path,
    base: &str,
    head: &str,
) -> Result<String, WorkerError> {
    let git = artifacts::AdmittedGit::admit()?;
    let output = BoundedOutput::new("bullet-command-worker-patch", PATCH_LIMIT)?;
    let range = format!("{base}..{head}");
    let mut child = Command::new(git.procfd_path())
        .env_clear()
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-C")
        .arg(repository)
        .args(["diff", "--binary", "--no-ext-diff", "--no-textconv", &range])
        .stdin(Stdio::null())
        .stdout(output.child_stdout()?)
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .worker(
            "COMMAND_RECEIPT_INVALID",
            "start retained Candidate patch read",
        )?;
    let group = child.id();
    let deadline = Instant::now() + PATCH_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                terminate(&mut child, group);
                return Err(invalid("retained Candidate patch read timed out"));
            }
            Err(error) => {
                terminate(&mut child, group);
                return Err(invalid(format!(
                    "inspect retained Candidate patch read: {error}"
                )));
            }
        }
    };
    kill_group(group);
    let bytes = output.finish("retained Candidate patch exceeded policy bound")?;
    if !status.success() {
        return Err(invalid("retained Candidate patch read failed"));
    }
    git.verify()?;
    Ok(Digest::of(&bytes).to_hex())
}

fn terminate(child: &mut Child, group: u32) {
    kill_group(group);
    let _ = child.kill();
    let _ = child.wait();
}

fn kill_group(group: u32) {
    if let Ok(raw) = i32::try_from(group) {
        if let Some(group) = rustix::process::Pid::from_raw(raw) {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
    }
}

#[cfg(test)]
pub(super) fn artifact_digest_for_fixture(path: &Path) -> Result<String, WorkerError> {
    artifact::artifact_digest(path)
}

#[cfg(test)]
pub(super) fn state_digest_for_fixture(value: &impl Serialize) -> Result<String, WorkerError> {
    artifact::state_digest_for_fixture(value)
}
