//! Retained ordinary-Git, LocalBare, and ledger read-back.

use super::{invalid, ComponentReceipt, RetainedPaths, TARGET};
use crate::error::{WorkerContext, WorkerError};
use bullet_domain::Digest;
use bullet_effects_core::{
    CheckReceipt, IntegrationReceipt, IntegrationSubject, ObservationSubjectV1, ProtectionState,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "ledger.rs"]
mod ledger;

const GIT_DEADLINE: Duration = Duration::from_secs(2);
const GIT_OUTPUT_LIMIT: u64 = 256;
const MAX_GIT_BINARY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;
const RECEIPT_NAME: &str = "COMPONENT_PROOF.receipt.json";

pub(super) fn read_receipt(path: &Path, run_root: &Path) -> Result<Vec<u8>, WorkerError> {
    require_private_dir(run_root)?;
    if path != run_root.join(RECEIPT_NAME) {
        return Err(invalid("receipt path is not the exact run-root subject"));
    }
    let before = std::fs::symlink_metadata(path)
        .worker("COMMAND_RECEIPT_INVALID", "inspect retained receipt")?;
    let canonical = path
        .canonicalize()
        .worker("COMMAND_RECEIPT_INVALID", "canonicalize retained receipt")?;
    if canonical != path
        || !before.file_type().is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.permissions().mode() & 0o177 != 0
        || before.len() == 0
        || before.len() > MAX_RECEIPT_BYTES
    {
        return Err(invalid("receipt is not a bounded protected regular file"));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(invalid)?;
    let mut file = File::from(descriptor);
    let opened = file
        .metadata()
        .worker("COMMAND_RECEIPT_INVALID", "inspect opened receipt")?;
    if identity(&before) != identity(&opened) {
        return Err(invalid("receipt changed before descriptor admission"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .worker("COMMAND_RECEIPT_INVALID", "read retained receipt")?;
    let descriptor_after = file
        .metadata()
        .worker("COMMAND_RECEIPT_INVALID", "reinspect opened receipt")?;
    let after = std::fs::symlink_metadata(path)
        .worker("COMMAND_RECEIPT_INVALID", "reinspect retained receipt")?;
    if identity(&before) != identity(&descriptor_after)
        || identity(&before) != identity(&after)
        || bytes.len() as u64 != before.len()
    {
        return Err(invalid("receipt identity or length changed while reading"));
    }
    Ok(bytes)
}

pub(super) fn validate_artifacts(
    paths: &RetainedPaths,
    receipt: &ComponentReceipt,
    subject: &ObservationSubjectV1,
) -> Result<(), WorkerError> {
    validate_ledger(&paths.ledger, receipt)?;
    let git = AdmittedGit::admit()?;
    if git_value(&git, &paths.source, &["rev-parse", "HEAD"])? != receipt.base_oid
        || git_value(&git, &paths.candidate, &["rev-parse", "HEAD"])? != receipt.head_oid
        || git_value(&git, &paths.candidate, &["rev-parse", "HEAD^{tree}"])? != receipt.tree_oid
    {
        return Err(invalid("retained source or Candidate Git subject drifted"));
    }
    for category in ["protections", "checks", "subjects", "integrations"] {
        canonical_dir(&paths.forge.join("bullet-effects-v1").join(category))?;
    }
    let delivered_ref = format!("refs/heads/bullet/candidate/{}", paths.candidate_id);
    if git_value(&git, &paths.forge, &["rev-parse", &delivered_ref])? != receipt.head_oid
        || git_value(&git, &paths.forge, &["rev-parse", TARGET])? != receipt.head_oid
    {
        return Err(invalid("retained LocalBare delivery or target drifted"));
    }
    let state = paths.forge.join("bullet-effects-v1");
    let protection: ProtectionState = read_state(&state.join("protections").join(format!(
        "{}.json",
        state_key("bullet-local-protection-v1", &[TARGET])
    )))?;
    let check: CheckReceipt = read_state(&state.join("checks").join(format!(
        "{}.json",
        state_key(
            "bullet-local-check-v1",
            &[&receipt.head_oid, &receipt.local_forge.check_name],
        )
    )))?;
    if !protection.protected
        || protection.required_proof_root.as_deref()
            != Some(receipt.local_forge.proof_root.as_str())
        || check.sha != receipt.head_oid
        || check.name != receipt.local_forge.check_name
        || check.proof_root != receipt.local_forge.proof_root
    {
        return Err(invalid("retained LocalBare protection or check drifted"));
    }
    let expected_subject = IntegrationSubject {
        id: subject.integration_subject_id.clone(),
        base: subject.previous_oid.clone(),
        head: subject.integrated_oid.clone(),
        target: subject.target.clone(),
    };
    let retained_subject: IntegrationSubject = read_state(
        &state
            .join("subjects")
            .join(format!("{}.json", subject.integration_subject_id)),
    )?;
    let integration: IntegrationReceipt = read_state(
        &state
            .join("integrations")
            .join(format!("{}.json", subject.integration_subject_id)),
    )?;
    if retained_subject != expected_subject
        || integration.target != subject.target
        || integration.check != check
        || integration.subject_id != subject.integration_subject_id
        || integration.integrated_oid != receipt.head_oid
        || integration.previous_oid != receipt.base_oid
    {
        return Err(invalid("retained LocalBare integration receipt drifted"));
    }
    git.verify()?;
    Ok(())
}

fn validate_ledger(path: &Path, receipt: &ComponentReceipt) -> Result<(), WorkerError> {
    let (file, metadata) = open_protected(path, 100, None, "ledger")?;
    verify_open_identity(path, &file, &metadata, "ledger")?;
    let result = ledger::validate(path, &file, receipt);
    let final_identity = verify_open_identity(path, &file, &metadata, "ledger");
    result.and(final_identity)
}

#[cfg(test)]
pub(crate) use ledger::{clear_test_hook, install_test_hook};

pub(super) fn require_private_dir(path: &Path) -> Result<(), WorkerError> {
    let meta = std::fs::symlink_metadata(path).worker(
        "COMMAND_RECEIPT_INVALID",
        "inspect private receipt directory",
    )?;
    if path.canonicalize().ok().as_deref() != Some(path)
        || !meta.file_type().is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err(invalid(
            "receipt directory is not canonical caller-owned mode 0700",
        ));
    }
    Ok(())
}

pub(super) fn canonical_dir(path: &Path) -> Result<PathBuf, WorkerError> {
    let canonical = path
        .canonicalize()
        .worker("COMMAND_RECEIPT_INVALID", "canonicalize retained directory")?;
    let metadata = std::fs::symlink_metadata(path)
        .worker("COMMAND_RECEIPT_INVALID", "inspect retained directory")?;
    if canonical != path || !metadata.file_type().is_dir() {
        return Err(invalid(
            "retained directory is absent, noncanonical, or not a directory",
        ));
    }
    Ok(canonical)
}

fn git_value(git: &AdmittedGit, repo: &Path, args: &[&str]) -> Result<String, WorkerError> {
    let mut child = Command::new(git.procfd_path())
        .env_clear()
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .worker("COMMAND_RECEIPT_INVALID", "start exact retained Git read")?;
    let group = child.id();
    let deadline = Instant::now() + GIT_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                terminate(&mut child, group);
                return Err(invalid("retained Git subject read timed out"));
            }
            Err(error) => {
                terminate(&mut child, group);
                return Err(invalid(format!("inspect retained Git read: {error}")));
            }
        }
    };
    kill_group(group);
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| invalid("retained Git stdout is absent"))?
        .take(GIT_OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .worker("COMMAND_RECEIPT_INVALID", "read retained Git output")?;
    if bytes.len() as u64 > GIT_OUTPUT_LIMIT {
        return Err(invalid("retained Git subject output exceeded its bound"));
    }
    let value = String::from_utf8(bytes)
        .worker("COMMAND_RECEIPT_INVALID", "decode retained Git subject")?;
    let value = value.trim_end_matches('\n');
    if !status.success() || value.lines().count() != 1 || !oid(value) {
        return Err(invalid(
            "retained Git subject read-back failed or was malformed",
        ));
    }
    Ok(value.into())
}

pub(super) struct AdmittedGit {
    sealed: File,
    sha256: String,
}

impl AdmittedGit {
    pub(super) fn admit() -> Result<Self, WorkerError> {
        let path = Path::new("/usr/bin/git");
        let before = std::fs::symlink_metadata(path)
            .worker("COMMAND_RECEIPT_INVALID", "inspect retained Git executable")?;
        if path.canonicalize().ok().as_deref() != Some(path)
            || !before.file_type().is_file()
            || before.uid() != 0
            || before.permissions().mode() & 0o022 != 0
            || before.len() == 0
            || before.len() > MAX_GIT_BINARY_BYTES
        {
            return Err(invalid(
                "Git executable is not a protected canonical subject",
            ));
        }
        let mut source =
            File::open(path).worker("COMMAND_RECEIPT_INVALID", "open retained Git executable")?;
        let fd = rustix::fs::memfd_create(
            "bullet-command-worker-git",
            rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(invalid)?;
        let mut sealed = File::from(fd);
        let sha256 = copy_sha256(&mut source, &mut sealed)?;
        let after = source.metadata().worker(
            "COMMAND_RECEIPT_INVALID",
            "reinspect retained Git executable",
        )?;
        if identity(&before) != identity(&after) {
            return Err(invalid("Git executable changed while sealing"));
        }
        rustix::fs::fchmod(&sealed, rustix::fs::Mode::from_raw_mode(0o500)).map_err(invalid)?;
        rustix::fs::fcntl_add_seals(
            &sealed,
            rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::SEAL,
        )
        .map_err(invalid)?;
        sealed.seek(SeekFrom::Start(0)).map_err(invalid)?;
        Ok(Self { sealed, sha256 })
    }

    pub(super) fn procfd_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.sealed.as_raw_fd()))
    }

    pub(super) fn verify(&self) -> Result<(), WorkerError> {
        let mut file = self.sealed.try_clone().map_err(invalid)?;
        file.seek(SeekFrom::Start(0)).map_err(invalid)?;
        let observed = copy_sha256(&mut file, &mut std::io::sink())?;
        if observed == self.sha256 {
            Ok(())
        } else {
            Err(invalid("sealed Git executable digest changed"))
        }
    }
}

fn copy_sha256<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
) -> Result<String, WorkerError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = source.read(&mut buffer).map_err(invalid)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("Git size overflow"))?;
        if total > MAX_GIT_BINARY_BYTES {
            return Err(invalid("Git executable exceeded its bound"));
        }
        hasher.update(&buffer[..count]);
        destination.write_all(&buffer[..count]).map_err(invalid)?;
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn read_state<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T, WorkerError> {
    let (mut file, metadata) = open_protected(path, 1, Some(64 * 1024), "LocalBare state")?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .worker("COMMAND_RECEIPT_INVALID", "read LocalBare state")?;
    verify_open_identity(path, &file, &metadata, "LocalBare state")?;
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid("LocalBare state length changed while reading"));
    }
    let value: T = serde_json::from_slice(&bytes).map_err(invalid)?;
    if serde_json::to_vec(&value).map_err(invalid)? != bytes {
        return Err(invalid("LocalBare state is not exact canonical JSON"));
    }
    Ok(value)
}

fn open_protected(
    path: &Path,
    minimum: u64,
    maximum: Option<u64>,
    subject: &str,
) -> Result<(File, std::fs::Metadata), WorkerError> {
    let before = std::fs::symlink_metadata(path).worker(
        "COMMAND_RECEIPT_INVALID",
        "inspect protected retained subject",
    )?;
    if !before.file_type().is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.permissions().mode() & 0o777 != 0o600
        || before.len() < minimum
        || maximum.is_some_and(|limit| before.len() > limit)
        || path.canonicalize().ok().as_deref() != Some(path)
    {
        return Err(invalid(format!(
            "retained {subject} is not an exact protected regular file"
        )));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(invalid)?;
    let file = File::from(descriptor);
    let opened = file.metadata().map_err(invalid)?;
    if identity(&before) != identity(&opened) {
        return Err(invalid(format!(
            "retained {subject} changed before descriptor admission"
        )));
    }
    Ok((file, before))
}

fn verify_open_identity(
    path: &Path,
    file: &File,
    before: &std::fs::Metadata,
    subject: &str,
) -> Result<(), WorkerError> {
    let opened_after = file.metadata().map_err(invalid)?;
    let path_after = std::fs::symlink_metadata(path).map_err(invalid)?;
    if identity(before) != identity(&opened_after) || identity(before) != identity(&path_after) {
        return Err(invalid(format!(
            "retained {subject} identity changed while reading"
        )));
    }
    Ok(())
}

fn state_key(domain: &str, parts: &[&str]) -> String {
    let mut bytes = domain.as_bytes().to_vec();
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    Digest::of(&bytes).to_hex()
}

fn terminate(child: &mut Child, group: u32) {
    kill_group(group);
    let _ = child.kill();
    let _ = child.wait();
}

fn kill_group(raw: u32) {
    if let Ok(raw) = i32::try_from(raw) {
        if let Some(group) = rustix::process::Pid::from_raw(raw) {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
    }
}

pub(super) fn identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

pub(super) fn full_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(|body| lower_hex(body, 64))
}

pub(super) fn oid(value: &str) -> bool {
    lower_hex(value, 40)
}

pub(super) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn blake3_label(bytes: &[u8]) -> String {
    format!("blake3:{}", Digest::of(bytes).to_hex())
}

pub(super) fn now_unix_ms() -> Result<u64, WorkerError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(invalid)?;
    u64::try_from(elapsed.as_millis()).map_err(invalid)
}
