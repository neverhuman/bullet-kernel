//! Closed simulator-provider receipt and retained transcript admission.

use super::{artifacts, bounded_output::BoundedOutput, invalid, ComponentReceipt, WorkerError};
use bullet_domain::{Digest, REPOSITORY_GATE_ID};
use bullet_harness_core::{PatchMutation, PatchProposal, Preimage};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MAX_RAW_ARTIFACT_BYTES: u64 = 1_048_576;
const GIT_DEADLINE: Duration = Duration::from_secs(5);
const MAX_GIT_OUTPUT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderExecution {
    adapter: String,
    version: String,
    session_id: String,
    proposal_id: String,
    producing_attempt_id: String,
    base_checkpoint_id: String,
    base_checkpoint_digest: String,
    gate_ids: Vec<String>,
    raw_artifact_relative: String,
    raw_artifact_blake3: String,
    credential_free: bool,
    transaction_gate_eligible: bool,
}

impl ProviderExecution {
    pub(super) fn validate(
        &self,
        run_root: &Path,
        receipt: &ComponentReceipt,
    ) -> Result<(), WorkerError> {
        let expected_session = format!(
            "cnt_{}",
            Digest::of(self.producing_attempt_id.as_bytes()).to_hex()
        );
        let expected_relative =
            format!("artifacts/provider-artifacts/{}.raw.jsonl", self.session_id);
        let fixed = self.adapter == "sim"
            && self.version == bullet_harness_sim::SIM_VERSION
            && self.credential_free
            && !self.transaction_gate_eligible
            && artifacts::full_id(&self.session_id, "cnt")
            && artifacts::full_id(&self.proposal_id, "cnt")
            && self.producing_attempt_id == receipt.attempt_first
            && self.session_id == expected_session
            && artifacts::full_id(&self.base_checkpoint_id, "ckp")
            && artifacts::lower_hex(&self.base_checkpoint_digest, 64)
            && self.gate_ids == [REPOSITORY_GATE_ID]
            && self.raw_artifact_relative == expected_relative
            && artifacts::lower_hex(&self.raw_artifact_blake3, 64);
        if !fixed {
            return Err(invalid(
                "provider execution classification or subject is not admitted",
            ));
        }

        let bytes = self.read_raw_artifact(run_root)?;
        if Digest::of(&bytes).to_hex() != self.raw_artifact_blake3 {
            return Err(invalid("retained provider transcript digest differs"));
        }
        let proposal = decode_terminal_proposal(&bytes)?;
        if proposal.proposal_id != self.proposal_id
            || proposal.producing_attempt_id != self.producing_attempt_id
            || proposal.base_checkpoint_id != self.base_checkpoint_id
            || proposal.base_checkpoint_digest != self.base_checkpoint_digest
            || proposal.gate_ids != self.gate_ids
        {
            return Err(invalid(
                "retained provider transcript differs from receipt subjects",
            ));
        }
        validate_candidate_change(&proposal, receipt, run_root)?;
        Ok(())
    }

    fn read_raw_artifact(&self, run_root: &Path) -> Result<Vec<u8>, WorkerError> {
        let parent = run_root.join("artifacts/provider-artifacts");
        artifacts::require_private_dir(&parent)?;
        let path = run_root.join(&self.raw_artifact_relative);
        let before = std::fs::symlink_metadata(&path).map_err(invalid)?;
        if !before.file_type().is_file()
            || before.uid() != rustix::process::geteuid().as_raw()
            || before.permissions().mode() & 0o777 != 0o600
            || before.len() == 0
            || before.len() > MAX_RAW_ARTIFACT_BYTES
            || path.canonicalize().ok().as_deref() != Some(path.as_path())
        {
            return Err(invalid(
                "retained provider transcript is not a protected bounded regular file",
            ));
        }
        let descriptor = rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(invalid)?;
        let mut file = File::from(descriptor);
        let opened = file.metadata().map_err(invalid)?;
        if artifacts::identity(&before) != artifacts::identity(&opened) {
            return Err(invalid(
                "retained provider transcript changed before descriptor admission",
            ));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_RAW_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(invalid)?;
        let opened_after = file.metadata().map_err(invalid)?;
        let path_after = std::fs::symlink_metadata(&path).map_err(invalid)?;
        if artifacts::identity(&before) != artifacts::identity(&opened_after)
            || artifacts::identity(&before) != artifacts::identity(&path_after)
            || bytes.len() as u64 != before.len()
        {
            return Err(invalid(
                "retained provider transcript identity changed while reading",
            ));
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
struct TreeEntry {
    mode: String,
    oid: String,
}

fn validate_candidate_change(
    proposal: &PatchProposal,
    receipt: &ComponentReceipt,
    run_root: &Path,
) -> Result<(), WorkerError> {
    let relative = Path::new(&receipt.artifact_custody.candidate_repository_relative);
    if relative.is_absolute() {
        return Err(invalid("Candidate repository receipt path is not relative"));
    }
    let repository = run_root.join(relative).canonicalize().map_err(invalid)?;
    let git = artifacts::AdmittedGit::admit()?;
    let changed = changed_paths(&git, &repository, &receipt.base_oid, &receipt.head_oid)?;
    let proposed = proposal
        .operations
        .iter()
        .map(|operation| operation.path.clone())
        .collect::<BTreeSet<_>>();
    if proposed.len() != proposal.operations.len() || proposed != changed {
        return Err(invalid(
            "provider proposal paths differ from the retained Candidate change",
        ));
    }
    for operation in &proposal.operations {
        let base = tree_entry(&git, &repository, &receipt.base_oid, &operation.path)?;
        let head = tree_entry(&git, &repository, &receipt.head_oid, &operation.path)?;
        if base
            .iter()
            .chain(head.iter())
            .any(|entry| entry.mode != "100644" && entry.mode != "100755")
        {
            return Err(invalid("provider proposal targets a non-regular Git entry"));
        }
        match (&operation.preimage, &base) {
            (Preimage::Absent, None) => {}
            (Preimage::Digest { digest }, Some(entry))
                if Digest::of(&git_blob(&git, &repository, &entry.oid)?).to_hex() == *digest => {}
            _ => {
                return Err(invalid(
                    "provider proposal preimage differs from Candidate base",
                ))
            }
        }
        match (&operation.mutation, &base, &head) {
            (PatchMutation::Delete, _, None) => {}
            (PatchMutation::Write { content_utf8 }, before, Some(after))
                if git_blob(&git, &repository, &after.oid)? == content_utf8.as_bytes()
                    && before
                        .as_ref()
                        .map_or(after.mode == "100644", |entry| entry.mode == after.mode) => {}
            _ => {
                return Err(invalid(
                    "provider proposal result differs from Candidate head",
                ))
            }
        }
    }
    git.verify()?;
    Ok(())
}

fn changed_paths(
    git: &artifacts::AdmittedGit,
    repository: &Path,
    base: &str,
    head: &str,
) -> Result<BTreeSet<String>, WorkerError> {
    let bytes = git_output(
        git,
        repository,
        &[
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            base,
            head,
            "--",
        ],
        128 * 4096,
    )?;
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(invalid(
            "retained Candidate changed-path output is truncated",
        ));
    }
    bytes
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8(path.to_vec()).map_err(invalid))
        .collect()
}

fn tree_entry(
    git: &artifacts::AdmittedGit,
    repository: &Path,
    commit: &str,
    path: &str,
) -> Result<Option<TreeEntry>, WorkerError> {
    let bytes = git_output(
        git,
        repository,
        &["ls-tree", "-z", commit, "--", path],
        8192,
    )?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let record = bytes
        .strip_suffix(&[0])
        .filter(|record| !record.contains(&0))
        .ok_or_else(|| invalid("retained Candidate tree entry is malformed"))?;
    let tab = record
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| invalid("retained Candidate tree entry has no path"))?;
    let (metadata, observed_path) = record.split_at(tab);
    let observed_path = &observed_path[1..];
    let metadata = std::str::from_utf8(metadata).map_err(invalid)?;
    let fields = metadata.split(' ').collect::<Vec<_>>();
    if fields.len() != 3
        || fields[1] != "blob"
        || !artifacts::lower_hex(fields[2], 40)
        || observed_path != path.as_bytes()
    {
        return Err(invalid("retained Candidate tree entry differs"));
    }
    Ok(Some(TreeEntry {
        mode: fields[0].to_owned(),
        oid: fields[2].to_owned(),
    }))
}

fn git_blob(
    git: &artifacts::AdmittedGit,
    repository: &Path,
    oid: &str,
) -> Result<Vec<u8>, WorkerError> {
    git_output(
        git,
        repository,
        &["cat-file", "blob", oid],
        MAX_GIT_OUTPUT_BYTES,
    )
}

fn git_output(
    git: &artifacts::AdmittedGit,
    repository: &Path,
    args: &[&str],
    limit: u64,
) -> Result<Vec<u8>, WorkerError> {
    let output = BoundedOutput::new("bullet-command-worker-provider-git", limit)?;
    let mut child = Command::new(git.procfd_path())
        .env_clear()
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-C")
        .arg(repository)
        .args(args)
        .stdin(Stdio::null())
        .stdout(output.child_stdout()?)
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(invalid)?;
    let group = child.id();
    let deadline = Instant::now() + GIT_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                terminate(&mut child, group);
                return Err(invalid("provider Candidate replay timed out"));
            }
            Err(error) => {
                terminate(&mut child, group);
                return Err(invalid(error));
            }
        }
    };
    kill_group(group);
    let bytes = output.finish("provider Candidate replay exceeded its bound")?;
    if !status.success() {
        return Err(invalid("provider Candidate Git replay failed"));
    }
    Ok(bytes)
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

fn decode_terminal_proposal(bytes: &[u8]) -> Result<PatchProposal, WorkerError> {
    if bytes.last() != Some(&b'\n') {
        return Err(invalid("retained provider transcript is truncated"));
    }
    let text = std::str::from_utf8(bytes).map_err(invalid)?;
    let lines = text.lines().collect::<Vec<_>>();
    let mut completed = None;
    for (index, line) in lines.iter().enumerate() {
        let value = bullet_harness_core::strict_json::decode_strict_json(line).map_err(invalid)?;
        let object = value
            .as_object()
            .filter(|object| {
                object.len() == 2 && object.contains_key("kind") && object.contains_key("payload")
            })
            .ok_or_else(|| invalid("retained provider event shape is open or malformed"))?;
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("turn.completed") if index + 1 == lines.len() && completed.is_none() => {
                completed = Some(
                    object
                        .get("payload")
                        .and_then(|payload| payload.get("proposal"))
                        .ok_or_else(|| invalid("retained provider completion has no proposal"))
                        .and_then(|proposal| {
                            PatchProposal::from_value(proposal).map_err(invalid)
                        })?,
                );
            }
            Some("turn.completed" | "turn.failed") => {
                return Err(invalid(
                    "retained provider terminal is not one final completion",
                ));
            }
            Some(_) => {}
            None => return Err(invalid("retained provider event kind is malformed")),
        }
    }
    completed.ok_or_else(|| invalid("retained provider completion is absent"))
}
