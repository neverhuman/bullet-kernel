//! Private scratch selection with an explicitly retained proof mode.

use super::support::fail;
use std::fs;
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
use std::fs::{File, Metadata};
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
use std::path::Component;
use std::path::{Path, PathBuf};

const ARTIFACT_ROOT_ENV: &str = "TRANSACTION_OFFLINE_ARTIFACT_ROOT";
const RECEIPT_ENV: &str = "TRANSACTION_OFFLINE_RECEIPT";
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
const EFFECT_RECEIPT_ENV: &str = "TRANSACTION_OFFLINE_EFFECT_RECEIPT";
const ARTIFACT_DIR_NAME: &str = "artifacts";
const DATA_DIR_NAME: &str = "data";
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
const SYNTHETIC_RECEIPT_NAME: &str = "DF_DOG1_SELECTION.receipt.json";
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
const SYNTHETIC_EFFECT_RECEIPT_NAME: &str = "DF_DOG1_EFFECT_CHAIN.receipt.json";
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
const MAX_RETAINED_PATH_BYTES: usize = 4096;
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
const MAX_RETAINED_PATH_COMPONENTS: usize = 64;

/// Exact retained paths admitted for one synthetic-selection component run.
#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
pub(super) struct SyntheticSelectionCustody {
    artifacts: PathBuf,
    data: PathBuf,
    receipt: PathBuf,
    effect_receipt: PathBuf,
}

#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
impl SyntheticSelectionCustody {
    pub(super) fn artifacts(&self) -> &Path {
        &self.artifacts
    }

    pub(super) fn data(&self) -> &Path {
        &self.data
    }

    pub(super) fn receipt(&self) -> &Path {
        &self.receipt
    }

    pub(super) fn effect_receipt(&self) -> &Path {
        &self.effect_receipt
    }
}

/// Owns either disposable scratch or the explicitly retained proof artifacts.
pub(super) struct ArtifactCustody {
    path: PathBuf,
    temporary: Option<tempfile::TempDir>,
    proof_root: Option<PathBuf>,
}

impl ArtifactCustody {
    /// Create an admitted private artifact root or an ephemeral developer root.
    pub(super) fn create() -> Result<Self, String> {
        let Some(raw) = std::env::var_os(ARTIFACT_ROOT_ENV) else {
            let temporary = tempfile::Builder::new()
                .prefix("bullet-txn.")
                .tempdir()
                .map_err(|error| fail(format!("create private scratch: {error}")))?;
            let path = fs::canonicalize(temporary.path())
                .map_err(|error| fail(format!("canonicalize private scratch: {error}")))?;
            return Ok(Self {
                path,
                temporary: Some(temporary),
                proof_root: None,
            });
        };

        let path = PathBuf::from(raw);
        require_new_absolute_path(&path)?;
        if path.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_DIR_NAME) {
            return Err(fail(
                "retained artifact root must use the exact basename `artifacts`",
            ));
        }
        let receipt = PathBuf::from(
            std::env::var_os(RECEIPT_ENV)
                .ok_or_else(|| fail("retained artifact custody requires an exact receipt path"))?,
        );
        if !receipt.is_absolute() || receipt.file_name().is_none() {
            return Err(fail("retained receipt path must be absolute"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| fail("retained artifact root has no parent"))?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|error| fail(format!("canonicalize retained proof root: {error}")))?;
        if parent != canonical_parent || receipt.parent() != Some(parent) {
            return Err(fail(
                "artifact and receipt must share one canonical private proof root",
            ));
        }
        fs::create_dir(&path)
            .map_err(|error| fail(format!("create retained artifact root: {error}")))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|error| fail(format!("chmod retained artifact root: {error}")))?;
        let canonical = fs::canonicalize(&path)
            .map_err(|error| fail(format!("canonicalize retained artifact root: {error}")))?;
        if canonical != path {
            return Err(fail(
                "retained artifact root changed identity after creation",
            ));
        }
        Ok(Self {
            path,
            temporary: None,
            proof_root: Some(canonical_parent),
        })
    }

    /// Admit new retained subjects required before a synthetic selection starts.
    ///
    /// This does not use recursive directory creation: each exact child must be
    /// absent and is created under one already-private, canonical proof root.
    #[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
    #[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
    pub(super) fn synthetic_selection_retained() -> Result<SyntheticSelectionCustody, String> {
        let artifacts = PathBuf::from(
            std::env::var_os(ARTIFACT_ROOT_ENV)
                .ok_or_else(|| fail("synthetic selection requires retained artifact custody"))?,
        );
        let receipt = PathBuf::from(
            std::env::var_os(RECEIPT_ENV)
                .ok_or_else(|| fail("synthetic selection requires retained receipt custody"))?,
        );
        let effect_receipt =
            PathBuf::from(std::env::var_os(EFFECT_RECEIPT_ENV).ok_or_else(|| {
                fail("synthetic selection requires retained effect receipt custody")
            })?);
        admit_synthetic_selection_paths(&artifacts, &receipt, &effect_receipt)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) const fn is_retained(&self) -> bool {
        self.temporary.is_none()
    }

    /// Retained runs bind the ledger to the same proof-root namespace.
    pub(super) fn admit_data_dir(&self, data: &Path) -> Result<(), String> {
        let Some(root) = &self.proof_root else {
            return Ok(());
        };
        if data != root.join(DATA_DIR_NAME) {
            return Err(fail(
                "retained ledger must be the canonical proof-root data directory",
            ));
        }
        Ok(())
    }

    /// Delete only ephemeral scratch. Explicitly retained bytes survive exit.
    pub(super) fn finish(mut self) -> Result<(), String> {
        if let Some(temporary) = self.temporary.take() {
            temporary
                .close()
                .map_err(|error| fail(format!("remove private scratch: {error}")))?;
        }
        Ok(())
    }
}

#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
fn admit_synthetic_selection_paths(
    artifacts: &Path,
    receipt: &Path,
    effect_receipt: &Path,
) -> Result<SyntheticSelectionCustody, String> {
    require_absent_absolute(artifacts, "synthetic artifact root")?;
    if artifacts.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_DIR_NAME) {
        return Err(fail(
            "synthetic artifact root must use exact `artifacts` basename",
        ));
    }
    if !receipt.is_absolute()
        || receipt.file_name().and_then(|name| name.to_str()) != Some(SYNTHETIC_RECEIPT_NAME)
    {
        return Err(fail(
            "synthetic receipt must use exact absolute DF_DOG1_SELECTION.receipt.json path",
        ));
    }
    require_absent_absolute(receipt, "synthetic receipt")?;
    if !effect_receipt.is_absolute()
        || effect_receipt.file_name().and_then(|name| name.to_str())
            != Some(SYNTHETIC_EFFECT_RECEIPT_NAME)
    {
        return Err(fail(
            "synthetic effect receipt must use exact absolute DF_DOG1_EFFECT_CHAIN.receipt.json path",
        ));
    }
    require_absent_absolute(effect_receipt, "synthetic effect receipt")?;
    let proof_root = artifacts
        .parent()
        .ok_or_else(|| fail("synthetic artifact root has no proof parent"))?;
    if receipt.parent() != Some(proof_root) || effect_receipt.parent() != Some(proof_root) {
        return Err(fail(
            "synthetic artifacts and both receipts must share one proof root",
        ));
    }
    require_private_canonical_directory(proof_root, "synthetic proof root")?;
    let data = proof_root.join(DATA_DIR_NAME);
    require_absent_absolute(&data, "synthetic data root")?;
    create_private_child(artifacts, "synthetic artifact root")?;
    create_private_child(&data, "synthetic data root")?;
    File::open(proof_root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| fail(format!("sync synthetic proof root: {error}")))?;
    Ok(SyntheticSelectionCustody {
        artifacts: artifacts.to_path_buf(),
        data,
        receipt: receipt.to_path_buf(),
        effect_receipt: effect_receipt.to_path_buf(),
    })
}

#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
fn require_absent_absolute(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > MAX_RETAINED_PATH_BYTES {
        return Err(fail(format!("{label} must be bounded and absolute")));
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(fail(format!("{label} must begin at the filesystem root")));
    }
    let mut count = 0_usize;
    for component in components {
        if !matches!(component, Component::Normal(_)) {
            return Err(fail(format!("{label} must not contain dot components")));
        }
        count += 1;
    }
    if count == 0 || count > MAX_RETAINED_PATH_COMPONENTS {
        return Err(fail(format!("{label} path component count is invalid")));
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(fail(format!(
            "{label} must not already exist or be a symlink"
        ))),
        Err(error) => Err(fail(format!("inspect {label}: {error}"))),
    }
}

#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
fn require_private_canonical_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| fail(format!("inspect {label}: {error}")))?;
    let identity = require_private_directory_metadata(&metadata, label)?;
    let canonical =
        fs::canonicalize(path).map_err(|error| fail(format!("canonicalize {label}: {error}")))?;
    if canonical != path {
        return Err(fail(format!(
            "{label} must be canonical without symlink traversal"
        )));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| fail(format!("open private {label}: {error}")))?;
    let opened = require_private_directory_metadata(
        &descriptor
            .metadata()
            .map_err(|error| fail(format!("inspect opened {label}: {error}")))?,
        label,
    )?;
    let after = require_private_directory_metadata(
        &fs::symlink_metadata(path).map_err(|error| fail(format!("reinspect {label}: {error}")))?,
        label,
    )?;
    if opened != identity || after != identity {
        return Err(fail(format!(
            "{label} identity changed during no-follow admission"
        )));
    }
    Ok(())
}

#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    links: u64,
    owner: u32,
    mode: u32,
}

#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
fn require_private_directory_metadata(
    metadata: &Metadata,
    label: &str,
) -> Result<DirectoryIdentity, String> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(fail(format!(
            "{label} must be caller-owned directory at exact mode 0700"
        )));
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        owner: metadata.uid(),
        mode: metadata.mode(),
    })
}

#[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
#[allow(dead_code)] // The parent synthetic route is intentionally integrated by a disjoint claim.
fn create_private_child(path: &Path, label: &str) -> Result<(), String> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|error| fail(format!("create {label}: {error}")))?;
    require_private_canonical_directory(path, label)
}

fn require_new_absolute_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(fail("retained artifact root must be absolute"));
    }
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        return Err(fail("retained artifact root must not already exist"));
    }
    Ok(())
}

#[cfg(all(test, feature = "synthetic-dogfood", debug_assertions))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("proof root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        root
    }

    #[test]
    fn synthetic_custody_creates_exact_private_children() {
        let root = private_root();
        let artifacts = root.path().join(ARTIFACT_DIR_NAME);
        let receipt = root.path().join(SYNTHETIC_RECEIPT_NAME);
        let effect_receipt = root.path().join(SYNTHETIC_EFFECT_RECEIPT_NAME);
        let custody =
            admit_synthetic_selection_paths(&artifacts, &receipt, &effect_receipt).expect("admit");
        assert_eq!(custody.artifacts(), artifacts);
        assert_eq!(custody.data(), root.path().join(DATA_DIR_NAME));
        assert_eq!(custody.receipt(), receipt);
        assert_eq!(custody.effect_receipt(), effect_receipt);
        for path in [custody.artifacts(), custody.data()] {
            let metadata = fs::symlink_metadata(path).expect("metadata");
            assert!(metadata.is_dir());
            assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
        assert!(fs::symlink_metadata(custody.receipt()).is_err());
        assert!(fs::symlink_metadata(custody.effect_receipt()).is_err());
    }

    #[test]
    fn synthetic_custody_refuses_nonprivate_or_existing_subjects() {
        let root = private_root();
        let artifacts = root.path().join(ARTIFACT_DIR_NAME);
        let receipt = root.path().join(SYNTHETIC_RECEIPT_NAME);
        let effect_receipt = root.path().join(SYNTHETIC_EFFECT_RECEIPT_NAME);
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("weaken root");
        assert!(admit_synthetic_selection_paths(&artifacts, &receipt, &effect_receipt).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("restore root");
        assert!(admit_synthetic_selection_paths(
            &artifacts,
            &root.path().join("wrong.json"),
            &effect_receipt,
        )
        .is_err());
        symlink("missing", &receipt).expect("receipt symlink");
        assert!(admit_synthetic_selection_paths(&artifacts, &receipt, &effect_receipt).is_err());
    }

    #[test]
    fn synthetic_custody_requires_exact_absent_effect_receipt() {
        let root = private_root();
        let artifacts = root.path().join(ARTIFACT_DIR_NAME);
        let receipt = root.path().join(SYNTHETIC_RECEIPT_NAME);
        let effect_receipt = root.path().join(SYNTHETIC_EFFECT_RECEIPT_NAME);

        assert!(admit_synthetic_selection_paths(
            &artifacts,
            &receipt,
            &root.path().join("wrong-effect.json"),
        )
        .is_err());
        let oversized = PathBuf::from("/")
            .join("x".repeat(MAX_RETAINED_PATH_BYTES))
            .join(SYNTHETIC_EFFECT_RECEIPT_NAME);
        assert!(admit_synthetic_selection_paths(&artifacts, &receipt, &oversized).is_err());
        let other_root = private_root();
        let outside = other_root.path().join(SYNTHETIC_EFFECT_RECEIPT_NAME);
        assert!(admit_synthetic_selection_paths(&artifacts, &receipt, &outside).is_err());
        fs::write(&effect_receipt, b"retain-existing").expect("existing effect receipt");
        fs::set_permissions(&effect_receipt, fs::Permissions::from_mode(0o600))
            .expect("private existing effect receipt");
        assert!(admit_synthetic_selection_paths(&artifacts, &receipt, &effect_receipt).is_err());
        assert_eq!(
            fs::read(&effect_receipt).expect("existing receipt retained"),
            b"retain-existing"
        );

        fs::remove_file(&effect_receipt).expect("remove test subject");
        let target = root.path().join("effect-target");
        fs::write(&target, b"retain-target").expect("effect target");
        symlink(&target, &effect_receipt).expect("effect receipt symlink");
        assert!(admit_synthetic_selection_paths(&artifacts, &receipt, &effect_receipt).is_err());
        assert_eq!(
            fs::read(&target).expect("target retained"),
            b"retain-target"
        );
    }
}
