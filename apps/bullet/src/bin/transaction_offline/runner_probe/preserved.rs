//! Independent post-exit read-back of the product Runner's retained subject.

use super::super::sim_provider::{admit_product_runner_transcript, SimProviderExecution};
use super::super::support::{fail, strip_oid};
use super::outcome::ProductRunnerOutcome;
use bullet_domain::Digest;
use bullet_runner_core::AcquireGrant;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_GIT_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

pub(super) struct PreservedExecution {
    pub(super) candidate_repository: PathBuf,
    pub(super) provider_execution: SimProviderExecution,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkingEntry {
    path: String,
    status: String,
    kind: String,
    content_digest: Option<String>,
}

pub(super) fn inspect(
    outcome: &ProductRunnerOutcome,
    grant: &AcquireGrant,
    workspace: &Path,
    scratch: &Path,
) -> Result<PreservedExecution, String> {
    let original = workspace.join("work").join(grant.attempt.id.as_str());
    if original.exists() {
        return Err(fail(
            "PRODUCT_RUNNER_CLEANUP_INCOMPLETE: original workspace survived success",
        ));
    }
    let destination = &outcome.preservation.receipt.destination;
    let subject_path = destination.join("subject.json");
    let subject: PreservationSubject = serde_json::from_slice(
        &std::fs::read(&subject_path)
            .map_err(|error| fail(format!("read preserved subject: {error}")))?,
    )
    .map_err(|error| fail(format!("decode preserved subject: {error}")))?;
    validate_subject(&subject, outcome, grant)?;

    let candidate_repository = destination.join("generation/repo");
    if !candidate_repository.is_dir() || candidate_repository.is_symlink() {
        return Err(fail(
            "PRODUCT_RUNNER_PRESERVATION_INVALID: repository missing",
        ));
    }
    let head = git_text(&candidate_repository, &["rev-parse", "HEAD"])?;
    let tree = git_text(&candidate_repository, &["rev-parse", "HEAD^{tree}"])?;
    if head != strip_oid(&outcome.candidate.head_commit)
        || tree != strip_oid(&outcome.candidate.tree_hash)
    {
        return Err(fail(
            "PRODUCT_RUNNER_PRESERVATION_INVALID: reopened head or tree drifted",
        ));
    }
    let patch = git_bytes(
        &candidate_repository,
        &[
            "diff",
            "--binary",
            &format!(
                "{}..{}",
                strip_oid(&outcome.candidate.base_commit),
                strip_oid(&outcome.candidate.head_commit)
            ),
        ],
    )?;
    if Digest::of(&patch).to_hex() != outcome.candidate.patch_hash {
        return Err(fail(
            "PRODUCT_RUNNER_PRESERVATION_INVALID: reopened patch digest drifted",
        ));
    }

    let transcript = workspace
        .join("artifacts")
        .join(grant.attempt.id.as_str())
        .join(format!("{}.raw.jsonl", grant.attempt.id));
    let provider_execution = admit_product_runner_transcript(
        &transcript,
        grant.attempt.id.as_str(),
        &scratch.join("provider-artifacts"),
    )?;
    Ok(PreservedExecution {
        candidate_repository,
        provider_execution,
    })
}

fn validate_subject(
    subject: &PreservationSubject,
    outcome: &ProductRunnerOutcome,
    grant: &AcquireGrant,
) -> Result<(), String> {
    let entries_valid = subject.dirty_untracked.iter().all(|entry| {
        !entry.path.is_empty()
            && !entry.status.is_empty()
            && !entry.kind.is_empty()
            && entry
                .content_digest
                .as_deref()
                .is_none_or(|digest| lower_hex(digest, 64))
    });
    let fixed = subject.schema_version == 1
        && subject.attempt_id == grant.attempt.id.as_str()
        && subject.attempt_fence == grant.attempt.fence
        && subject.workspace_nonce_hex == nonce_hex(&grant.authority_token.workspace_nonce)
        && subject.generation > 0
        && subject.git_tree == outcome.candidate.tree_hash
        && lower_hex(&subject.generation_digest, 64)
        && subject.journal_start <= subject.journal_end
        && lower_hex(&subject.journal_root, 64)
        && entries_valid;
    fixed.then_some(()).ok_or_else(|| {
        fail("PRODUCT_RUNNER_PRESERVATION_INVALID: sealed subject differs from Candidate authority")
    })
}

fn git_text(repository: &Path, args: &[&str]) -> Result<String, String> {
    String::from_utf8(git_bytes(repository, args)?)
        .map(|value| value.trim().to_owned())
        .map_err(|_| fail("preserved Git read-back was not UTF-8"))
}

fn git_bytes(repository: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .current_dir(repository)
        .output()
        .map_err(|error| fail(format!("run preserved Git read-back: {error}")))?;
    if !output.status.success()
        || output.stdout.len() > MAX_GIT_OUTPUT_BYTES
        || output.stderr.len() > MAX_GIT_OUTPUT_BYTES
    {
        return Err(fail(format!(
            "preserved Git read-back refused: status={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

fn lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nonce_hex(nonce: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in nonce {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
