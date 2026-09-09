use bullet_application::{EffectRecoveryAuthority, LeaseGrant, StoredGraph};
use bullet_domain::{AuthorityToken, CandidateId, EffectId};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

pub(crate) const MANIFEST_ENV: &str = "BULLET_RESTART_PROCESS_MANIFEST";
pub(crate) const MANIFEST_DIGEST_ENV: &str = "BULLET_RESTART_PROCESS_MANIFEST_BLAKE3";
const MANIFEST_SCHEMA: &str = "bullet.test.restart-process-manifest.v1";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WorkerAction {
    Reconcile,
    StaleReadbackProbe,
    SpawnDescendant,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CrashAfter {
    None,
    Claim,
    RetryReserved,
    Push,
    Adopted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerManifest {
    pub(crate) schema: String,
    pub(crate) root: PathBuf,
    pub(crate) database: PathBuf,
    pub(crate) workspace: PathBuf,
    pub(crate) bare: PathBuf,
    pub(crate) forge_log: PathBuf,
    pub(crate) result: PathBuf,
    pub(crate) subjects: Vec<PathSubject>,
    pub(crate) intent_id: EffectId,
    pub(crate) authority: EffectRecoveryAuthority,
    pub(crate) token: AuthorityToken,
    pub(crate) graph: StoredGraph,
    pub(crate) grant: LeaseGrant,
    pub(crate) expected_ref: String,
    pub(crate) expected_old_oid: String,
    pub(crate) expected_new_oid: String,
    pub(crate) action: WorkerAction,
    pub(crate) crash_after: CrashAfter,
}

pub(crate) struct WorkerManifestInput {
    pub(crate) root: PathBuf,
    pub(crate) database: PathBuf,
    pub(crate) workspace: PathBuf,
    pub(crate) bare: PathBuf,
    pub(crate) forge_log: PathBuf,
    pub(crate) result: PathBuf,
    pub(crate) intent_id: EffectId,
    pub(crate) authority: EffectRecoveryAuthority,
    pub(crate) token: AuthorityToken,
    pub(crate) graph: StoredGraph,
    pub(crate) grant: LeaseGrant,
    pub(crate) expected_ref: String,
    pub(crate) expected_old_oid: String,
    pub(crate) expected_new_oid: String,
    pub(crate) action: WorkerAction,
    pub(crate) crash_after: CrashAfter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PathSubject {
    path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    kind: String,
}

impl WorkerManifest {
    pub(crate) fn new(input: WorkerManifestInput) -> Result<Self, String> {
        let subjects = [
            &input.root,
            &input.database,
            &input.workspace,
            &input.bare,
            &input.forge_log,
        ]
        .into_iter()
        .map(|path| PathSubject::capture(path))
        .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            schema: MANIFEST_SCHEMA.into(),
            root: input.root,
            database: input.database,
            workspace: input.workspace,
            bare: input.bare,
            forge_log: input.forge_log,
            result: input.result,
            subjects,
            intent_id: input.intent_id,
            authority: input.authority,
            token: input.token,
            graph: input.graph,
            grant: input.grant,
            expected_ref: input.expected_ref,
            expected_old_oid: input.expected_old_oid,
            expected_new_oid: input.expected_new_oid,
            action: input.action,
            crash_after: input.crash_after,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != MANIFEST_SCHEMA {
            return Err("manifest schema mismatch".into());
        }
        validate_private_root(&self.root)?;
        for path in [&self.database, &self.workspace, &self.bare, &self.forge_log] {
            validate_existing_beneath(path, &self.root)?;
        }
        let expected_paths = [
            &self.root,
            &self.database,
            &self.workspace,
            &self.bare,
            &self.forge_log,
        ];
        if self.subjects.len() != expected_paths.len() {
            return Err("path subject cardinality mismatch".into());
        }
        for (subject, expected) in self.subjects.iter().zip(expected_paths) {
            if subject.path != *expected {
                return Err("path subject order mismatch".into());
            }
            subject.validate_current()?;
        }
        validate_absent_beneath(&self.result, &self.root)?;
        self.authority
            .validate()
            .map_err(|error| format!("authority: {error}"))?;
        self.authority
            .validate_token(&self.token)
            .map_err(|error| format!("token projection: {error}"))?;
        if self.grant.attempt.id != self.authority.attempt_id
            || self.grant.attempt.fence != self.authority.attempt_fence
            || self.grant.attempt.variant_id != self.authority.variant_id
            || self.grant.attempt.runner_id != self.authority.runner_id
            || self.grant.attempt.runner_epoch != self.authority.runner_epoch
            || self.grant.attempt.workspace_id != self.authority.workspace_id
            || self.grant.attempt.workspace_nonce != self.authority.workspace_nonce
            || self.grant.lease.attempt_id != self.grant.attempt.id
            || self.grant.lease.variant_id != self.grant.attempt.variant_id
            || self.grant.lease.fence != self.grant.attempt.fence
            || self.grant.lease.runner_id != self.grant.attempt.runner_id
            || self.grant.lease.runner_epoch != self.grant.attempt.runner_epoch
            || self.grant.lease.workspace_nonce != self.grant.attempt.workspace_nonce
            || self.graph.mission.id != self.token.mission_id
            || self.graph.plan.id != self.token.plan_revision_id
            || !self.graph.packages.iter().any(|package| {
                package.id == self.token.work_package_id
                    && package.mission_id == self.token.mission_id
                    && package.plan_revision_id == self.token.plan_revision_id
            })
            || !self.graph.variants.iter().any(|variant| {
                variant.id == self.token.variant_id
                    && variant.work_package_id == self.token.work_package_id
                    && variant.selection_group_id == self.token.selection_group_id
            })
        {
            return Err("graph/grant authority mismatch".into());
        }
        let candidate = self
            .expected_ref
            .strip_prefix("refs/heads/bullet/candidate/")
            .ok_or("candidate ref prefix mismatch")?;
        candidate
            .parse::<CandidateId>()
            .map_err(|error| format!("candidate ref id: {error}"))?;
        if !valid_oid(&self.expected_old_oid) || !valid_oid(&self.expected_new_oid) {
            return Err("expected forge subject malformed".into());
        }
        Ok(())
    }
}

impl PathSubject {
    fn capture(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        let kind = if metadata.file_type().is_file() {
            "FILE"
        } else if metadata.file_type().is_dir() {
            "DIRECTORY"
        } else {
            return Err("path subject is not a file or directory".into());
        };
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
            kind: kind.into(),
        })
    }

    fn validate_current(&self) -> Result<(), String> {
        let current = Self::capture(&self.path)?;
        if current != *self || self.owner != rustix::process::getuid().as_raw() {
            return Err("path subject identity changed".into());
        }
        match self.kind.as_str() {
            "FILE" if self.mode == 0o600 => Ok(()),
            "DIRECTORY" if self.mode == 0o700 => Ok(()),
            _ => Err("path subject is not private".into()),
        }
    }
}

pub(crate) fn write(
    root: &Path,
    sequence: u64,
    manifest: &WorkerManifest,
) -> Result<(PathBuf, String), String> {
    validate_private_root(root)?;
    let path = root.join(format!("worker-{sequence}.json"));
    let bytes = serde_json::to_vec(manifest).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("manifest exceeds byte limit".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| format!("create manifest: {error}"))?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    sync_parent(root)?;
    Ok((path, blake3::hash(&bytes).to_hex().to_string()))
}

pub(crate) fn load_from_environment() -> Result<Option<WorkerManifest>, String> {
    let Some(path) = std::env::var_os(MANIFEST_ENV).map(PathBuf::from) else {
        if std::env::var_os(MANIFEST_DIGEST_ENV).is_some() {
            return Err("manifest digest exists without manifest".into());
        }
        return Ok(None);
    };
    let expected =
        std::env::var(MANIFEST_DIGEST_ENV).map_err(|_| "manifest digest is absent".to_string())?;
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("manifest digest is malformed".into());
    }
    let before = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    require_private_file(&before)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| format!("open manifest: {error}"))?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    same_file(&before, &opened)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("manifest exceeds byte limit".into());
    }
    let after = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    same_file(&opened, &after)?;
    if blake3::hash(&bytes).to_hex().as_str() != expected {
        return Err("manifest digest mismatch".into());
    }
    let manifest: WorkerManifest =
        serde_json::from_slice(&bytes).map_err(|error| format!("decode manifest: {error}"))?;
    if serde_json::to_vec(&manifest).map_err(|error| error.to_string())? != bytes {
        return Err("manifest is not exact closed writer output".into());
    }
    manifest.validate()?;
    if path.parent() != Some(manifest.root.as_path()) {
        return Err("manifest is outside its declared root".into());
    }
    Ok(Some(manifest))
}

fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn write_result(path: &Path, value: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("create result: {error}"))?;
    file.write_all(value.as_bytes())
        .map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    sync_parent(path.parent().ok_or("result parent absent")?)
}

fn validate_private_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || has_parent_component(root) {
        return Err("private root is not normalized absolute".into());
    }
    let metadata = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
        || root.canonicalize().map_err(|error| error.to_string())? != root
    {
        return Err("private root custody mismatch".into());
    }
    Ok(())
}

fn validate_existing_beneath(path: &Path, root: &Path) -> Result<(), String> {
    validate_path_shape(path, root)?;
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    if !canonical.starts_with(root) {
        return Err("manifest path escaped private root".into());
    }
    Ok(())
}

fn validate_absent_beneath(path: &Path, root: &Path) -> Result<(), String> {
    validate_path_shape(path, root)?;
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        return Err("result path already exists".into());
    }
    let parent = path.parent().ok_or("result parent absent")?;
    if parent == root {
        Ok(())
    } else {
        validate_existing_beneath(parent, root)
    }
}

fn validate_path_shape(path: &Path, root: &Path) -> Result<(), String> {
    if !path.is_absolute() || has_parent_component(path) || !path.starts_with(root) || path == root
    {
        return Err("manifest path is outside private root".into());
    }
    Ok(())
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
}

fn require_private_file(metadata: &std::fs::Metadata) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err("manifest file custody mismatch".into());
    }
    Ok(())
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> Result<(), String> {
    if left.dev() != right.dev()
        || left.ino() != right.ino()
        || left.uid() != right.uid()
        || left.mode() != right.mode()
        || left.nlink() != right.nlink()
        || left.len() != right.len()
    {
        return Err("manifest identity changed during read".into());
    }
    require_private_file(right)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync parent: {error}"))
}
