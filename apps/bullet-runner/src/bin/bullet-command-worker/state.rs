//! Crash-retained command claim and component receipt custody.

use super::error::{WorkerContext, WorkerError};
use bullet_application::{CommandDispatchClaim, CommandDispatchDisposition};
use bullet_domain::Digest;
use bullet_harness_core::launch_grant::canonical_json;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const STATE_SCHEMA: &str = "bullet.command-worker-state.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum Stage {
    Claimed,
    ReceiptRetained,
    SettledUnknown,
}

impl Stage {
    fn file_name(self) -> &'static str {
        match self {
            Self::Claimed => "state-claimed.json",
            Self::ReceiptRetained => "state-receipt-retained.json",
            Self::SettledUnknown => "state-settled-unknown.json",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerState {
    schema_version: String,
    pub(super) stage: Stage,
    pub(super) claim: CommandDispatchClaim,
    claim_blake3: String,
    pub(super) binary_manifest_sha256: String,
    pub(super) receipt_sha256: Option<String>,
    pub(super) receipt_digest: Option<Digest>,
    receipt_admitted_at_unix_ms: Option<u64>,
}

impl WorkerState {
    fn new(claim: CommandDispatchClaim, manifest: &str) -> Result<Self, WorkerError> {
        let canonical =
            canonical_json(&claim).worker("COMMAND_STATE_INVALID", "canonicalize claim")?;
        let state = Self {
            schema_version: STATE_SCHEMA.into(),
            stage: Stage::Claimed,
            claim,
            claim_blake3: format!("blake3:{}", Digest::of(&canonical).to_hex()),
            binary_manifest_sha256: manifest.into(),
            receipt_sha256: None,
            receipt_digest: None,
            receipt_admitted_at_unix_ms: None,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), WorkerError> {
        self.claim
            .validate()
            .worker("COMMAND_STATE_INVALID", "validate retained claim")?;
        let canonical = canonical_json(&self.claim)
            .worker("COMMAND_STATE_INVALID", "canonicalize retained claim")?;
        if self.schema_version != STATE_SCHEMA
            || self.claim.disposition != CommandDispatchDisposition::Claimed
            || self.claim.request.kind != "run_demo"
            || self.claim.request.payload != "{}"
            || self.claim_blake3 != format!("blake3:{}", Digest::of(&canonical).to_hex())
            || !lower_hex(&self.binary_manifest_sha256)
            || self
                .receipt_sha256
                .as_deref()
                .is_some_and(|value| !lower_hex(value))
            || !self.receipt_subjects_match_stage()
        {
            return Err(WorkerError::input(
                "COMMAND_STATE_INVALID",
                "retained state subjects or stage contradict",
            ));
        }
        Ok(())
    }

    pub(super) fn retain_receipt(
        mut self,
        sha256: String,
        digest: Digest,
        admitted_at_unix_ms: u64,
    ) -> Result<Self, WorkerError> {
        if self.stage != Stage::Claimed
            || !lower_hex(&sha256)
            || admitted_at_unix_ms == 0
            || admitted_at_unix_ms > 9_007_199_254_740_991
        {
            return Err(WorkerError::input(
                "COMMAND_STATE_INVALID",
                "receipt transition is invalid",
            ));
        }
        self.stage = Stage::ReceiptRetained;
        self.receipt_sha256 = Some(sha256);
        self.receipt_digest = Some(digest);
        self.receipt_admitted_at_unix_ms = Some(admitted_at_unix_ms);
        self.validate()?;
        Ok(self)
    }

    fn receipt_subjects_match_stage(&self) -> bool {
        let subjects = (
            self.receipt_sha256.is_some(),
            self.receipt_digest.is_some(),
            self.receipt_admitted_at_unix_ms.is_some(),
        );
        match self.stage {
            Stage::Claimed => subjects == (false, false, false),
            Stage::ReceiptRetained | Stage::SettledUnknown => {
                subjects == (true, true, true)
                    && self
                        .receipt_admitted_at_unix_ms
                        .is_some_and(|value| value > 0 && value <= 9_007_199_254_740_991)
            }
        }
    }

    pub(super) fn settled(mut self) -> Result<Self, WorkerError> {
        if self.stage != Stage::ReceiptRetained {
            return Err(WorkerError::input(
                "COMMAND_STATE_INVALID",
                "only a retained receipt can settle",
            ));
        }
        self.stage = Stage::SettledUnknown;
        self.validate()?;
        Ok(self)
    }
}

#[derive(Debug)]
pub(super) struct StateStore {
    root: PathBuf,
}

impl StateStore {
    pub(super) fn admit(root: &Path) -> Result<Self, WorkerError> {
        if !root.is_absolute() {
            return Err(WorkerError::input(
                "COMMAND_STATE_DIR_INVALID",
                "state directory is not absolute",
            ));
        }
        let meta = std::fs::symlink_metadata(root)
            .worker("COMMAND_STATE_DIR_INVALID", "inspect state directory")?;
        let canonical = root
            .canonicalize()
            .worker("COMMAND_STATE_DIR_INVALID", "canonicalize state directory")?;
        if canonical != root
            || !meta.file_type().is_dir()
            || meta.permissions().mode() & 0o777 != 0o700
            || meta.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(WorkerError::input(
                "COMMAND_STATE_DIR_INVALID",
                "state directory is not canonical caller-owned mode 0700",
            ));
        }
        Ok(Self { root: root.into() })
    }

    pub(super) fn load(&self) -> Result<Option<WorkerState>, WorkerError> {
        let path = self.root.join("current.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_private(&path, "COMMAND_STATE_INVALID")?;
        let state: WorkerState = serde_json::from_slice(&bytes)
            .worker("COMMAND_STATE_INVALID", "decode closed worker state")?;
        state.validate()?;
        if canonical_json(&state).ok().as_deref() != Some(bytes.as_slice()) {
            return Err(WorkerError::input(
                "COMMAND_STATE_INVALID",
                "worker state is not canonical JSON",
            ));
        }
        Ok(Some(state))
    }

    pub(super) fn begin(
        &self,
        claim: CommandDispatchClaim,
        manifest: &str,
    ) -> Result<WorkerState, WorkerError> {
        if let Some(existing) = self.load()? {
            if existing.stage != Stage::SettledUnknown {
                if existing.claim == claim && existing.binary_manifest_sha256 == manifest {
                    return Ok(existing);
                }
                return Err(WorkerError::input(
                    "COMMAND_STATE_CONFLICT",
                    "another retained claim or manifest owns this worker",
                ));
            }
            if existing.claim.claim_id == claim.claim_id {
                return Err(WorkerError::input(
                    "COMMAND_STATE_CONFLICT",
                    "a settled claim cannot execute again",
                ));
            }
        }
        let state = WorkerState::new(claim, manifest)?;
        let claim_root = self.claim_root(&state);
        create_or_admit_private_dir(&claim_root, "claim custody")?;
        let run_root = claim_root.join("run");
        create_or_admit_private_dir(&run_root, "private run root")?;
        write_immutable(
            &claim_root.join("claim.json"),
            &canonical_json(&state.claim).worker("COMMAND_STATE_WRITE_FAILED", "encode claim")?,
        )?;
        self.persist(&state)?;
        Ok(state)
    }

    pub(super) fn persist(&self, state: &WorkerState) -> Result<(), WorkerError> {
        state.validate()?;
        let bytes =
            canonical_json(state).worker("COMMAND_STATE_WRITE_FAILED", "encode worker state")?;
        let claim_root = self.claim_root(state);
        write_immutable(&claim_root.join(state.stage.file_name()), &bytes)?;
        let tmp = self
            .root
            .join(format!("current.{}.tmp", std::process::id()));
        write_replaceable(&tmp, &bytes)?;
        std::fs::rename(&tmp, self.root.join("current.json"))
            .worker("COMMAND_STATE_WRITE_FAILED", "publish current worker state")?;
        sync_dir(&claim_root)?;
        sync_dir(&self.root)
    }

    pub(super) fn run_root(&self, state: &WorkerState) -> PathBuf {
        self.claim_root(state).join("run")
    }

    pub(super) fn receipt_path(&self, state: &WorkerState) -> PathBuf {
        self.run_root(state).join("COMPONENT_PROOF.receipt.json")
    }

    fn claim_root(&self, state: &WorkerState) -> PathBuf {
        self.root.join(&state.claim.claim_id)
    }
}

fn read_private(path: &Path, code: &'static str) -> Result<Vec<u8>, WorkerError> {
    let before = std::fs::symlink_metadata(path).worker(code, "inspect retained file")?;
    if !before.file_type().is_file()
        || before.permissions().mode() & 0o177 != 0
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.len() > 4 * 1024 * 1024
    {
        return Err(WorkerError::input(
            code,
            "retained file is not a bounded protected regular file",
        ));
    }
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .worker(code, "open exact retained file")?;
    let mut file = File::from(fd);
    let opened = file
        .metadata()
        .worker(code, "inspect opened retained file")?;
    if file_identity(&before) != file_identity(&opened) {
        return Err(WorkerError::input(
            code,
            "retained file changed while opening",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .worker(code, "read retained file")?;
    let after = file.metadata().worker(code, "reinspect retained file")?;
    if file_identity(&opened) != file_identity(&after) || bytes.len() as u64 != opened.len() {
        return Err(WorkerError::input(
            code,
            "retained file changed while reading",
        ));
    }
    Ok(bytes)
}

fn file_identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), WorkerError> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => sync_write(&mut file, bytes),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_private(path, "COMMAND_STATE_CONFLICT")? == bytes {
                Ok(())
            } else {
                Err(WorkerError::input(
                    "COMMAND_STATE_CONFLICT",
                    "immutable retained state differs",
                ))
            }
        }
        Err(error) => Err(WorkerError::input(
            "COMMAND_STATE_WRITE_FAILED",
            error.to_string(),
        )),
    }
}

fn write_replaceable(path: &Path, bytes: &[u8]) -> Result<(), WorkerError> {
    let opened = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    match opened {
        Ok(mut file) => sync_write(&mut file, bytes),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_private(path, "COMMAND_STATE_CONFLICT")? == bytes {
                Ok(())
            } else {
                Err(WorkerError::input(
                    "COMMAND_STATE_CONFLICT",
                    "stale state publication differs",
                ))
            }
        }
        Err(error) => Err(WorkerError::input(
            "COMMAND_STATE_WRITE_FAILED",
            format!("create state publication: {error}"),
        )),
    }
}

fn create_or_admit_private_dir(path: &Path, label: &str) -> Result<(), WorkerError> {
    match std::fs::create_dir(path) {
        Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).worker(
            "COMMAND_STATE_WRITE_FAILED",
            "protect private state directory",
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(WorkerError::input(
                "COMMAND_STATE_WRITE_FAILED",
                format!("create {label}: {error}"),
            ))
        }
    }
    let meta = std::fs::symlink_metadata(path).worker(
        "COMMAND_STATE_CONFLICT",
        "inspect existing private state directory",
    )?;
    let canonical = path.canonicalize().worker(
        "COMMAND_STATE_CONFLICT",
        "canonicalize private state directory",
    )?;
    if canonical != path
        || !meta.file_type().is_dir()
        || meta.permissions().mode() & 0o777 != 0o700
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(WorkerError::input(
            "COMMAND_STATE_CONFLICT",
            format!("existing {label} is not canonical caller-owned mode 0700"),
        ));
    }
    Ok(())
}

fn sync_write(file: &mut File, bytes: &[u8]) -> Result<(), WorkerError> {
    file.write_all(bytes)
        .worker("COMMAND_STATE_WRITE_FAILED", "write retained state")?;
    file.sync_all()
        .worker("COMMAND_STATE_WRITE_FAILED", "sync retained state")
}

fn sync_dir(path: &Path) -> Result<(), WorkerError> {
    File::open(path)
        .worker("COMMAND_STATE_WRITE_FAILED", "open state directory")?
        .sync_all()
        .worker("COMMAND_STATE_WRITE_FAILED", "sync state directory")
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod tests;
