use crate::assertions::assert_log;
use crate::fixture::Fixture;
use crate::model::{self, CrashAfter, WorkerAction};
use crate::{process, snapshot};
use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(crate) fn run() -> Result<(), String> {
    private_manifest_channel_refuses_hostiles()?;
    worker_descendants_are_always_reaped()
}

fn private_manifest_channel_refuses_hostiles() -> Result<(), String> {
    let mut fixture = Fixture::new("process-hostile")?;
    let manifest = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::None)?;
    let (valid_path, valid_digest) = model::write(&fixture.root, 1, &manifest)?;
    let before = hostile_snapshot(&fixture)?;

    assert_refused(
        &fixture,
        &valid_path,
        &"0".repeat(64),
        "manifest digest mismatch",
    )?;
    std::fs::set_permissions(&valid_path, Permissions::from_mode(0o644))
        .map_err(|error| error.to_string())?;
    let public = process::run_worker(&fixture.root, &valid_path, &valid_digest);
    std::fs::set_permissions(&valid_path, Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    assert_failed(public?, "manifest file custody mismatch")?;

    let link = fixture.root.join("manifest-link.json");
    std::os::unix::fs::symlink(&valid_path, &link).map_err(|error| error.to_string())?;
    assert_refused(
        &fixture,
        &link,
        &valid_digest,
        "manifest file custody mismatch",
    )?;
    let partial = fixture.root.join("manifest-partial.json");
    write_private(&partial, b"{\"schema\":")?;
    assert_refused(
        &fixture,
        &partial,
        &digest_file(&partial)?,
        "decode manifest",
    )?;
    let oversized = fixture.root.join("manifest-oversized.json");
    write_private(&oversized, &vec![b'x'; 64 * 1024 + 1])?;
    assert_refused(
        &fixture,
        &oversized,
        &digest_file(&oversized)?,
        "manifest file custody mismatch",
    )?;

    let unknown = fixture.root.join("manifest-unknown.json");
    let mut value = serde_json::to_value(&manifest).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or("manifest stopped being an object")?
        .insert("untrusted".into(), serde_json::Value::Bool(true));
    write_private(
        &unknown,
        &serde_json::to_vec(&value).map_err(|error| error.to_string())?,
    )?;
    assert_refused(&fixture, &unknown, &digest_file(&unknown)?, "unknown field")?;

    std::fs::set_permissions(&fixture.root, Permissions::from_mode(0o755))
        .map_err(|error| error.to_string())?;
    let root_mode = process::run_worker(&fixture.root, &valid_path, &valid_digest);
    std::fs::set_permissions(&fixture.root, Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    assert_failed(root_mode?, "private root custody mismatch")?;

    std::fs::set_permissions(&fixture.forge_log, Permissions::from_mode(0o644))
        .map_err(|error| error.to_string())?;
    let subject_mode = process::run_worker(&fixture.root, &valid_path, &valid_digest);
    std::fs::set_permissions(&fixture.forge_log, Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    assert_failed(subject_mode?, "path subject identity changed")?;

    let retained_log = fixture.root.join("forge-original.log");
    std::fs::rename(&fixture.forge_log, &retained_log).map_err(|error| error.to_string())?;
    write_private(&fixture.forge_log, b"")?;
    let subject_inode = process::run_worker(&fixture.root, &valid_path, &valid_digest);
    std::fs::remove_file(&fixture.forge_log).map_err(|error| error.to_string())?;
    std::fs::rename(&retained_log, &fixture.forge_log).map_err(|error| error.to_string())?;
    assert_failed(subject_inode?, "path subject identity changed")?;
    assert_eq!(hostile_snapshot(&fixture)?, before);
    Ok(())
}

fn worker_descendants_are_always_reaped() -> Result<(), String> {
    let mut fixture = Fixture::new("process-descendant")?;
    let manifest = fixture.current_manifest(WorkerAction::SpawnDescendant, CrashAfter::None)?;
    let (path, digest) = model::write(&fixture.root, 1, &manifest)?;
    let result = process::run_worker(&fixture.root, &path, &digest)?;
    process::assert_success(&result)?;
    let raw = std::fs::read_to_string(&manifest.result).map_err(|error| error.to_string())?;
    let pid = raw
        .trim()
        .parse::<u32>()
        .map_err(|error| error.to_string())?;
    let proc_path = std::path::PathBuf::from(format!("/proc/{pid}"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while proc_path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if proc_path.exists() {
        return Err(format!(
            "worker descendant {pid} survived process-group cleanup"
        ));
    }
    assert_eq!(fixture.remote_ref()?, None);
    assert_log(&fixture, &[])
}

fn assert_refused(
    fixture: &Fixture,
    path: &Path,
    digest: &str,
    expected: &str,
) -> Result<(), String> {
    assert_failed(process::run_worker(&fixture.root, path, digest)?, expected)
}

fn assert_failed(result: process::ChildResult, expected: &str) -> Result<(), String> {
    if result.status.code() != Some(101) {
        return Err(format!(
            "hostile refusal status drifted: {:?}",
            result.status.code()
        ));
    }
    let diagnostic = result
        .diagnostic
        .ok_or_else(|| "hostile refusal omitted diagnostic".to_string())?;
    if !diagnostic.contains(expected) {
        return Err(format!(
            "hostile refusal mismatch: expected {expected:?}, got {diagnostic:?}"
        ));
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn digest_file(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        .map_err(|error| error.to_string())
}

fn hostile_snapshot(fixture: &Fixture) -> Result<(String, Vec<u8>, Option<String>), String> {
    Ok((
        snapshot::durable(&fixture.database)?,
        std::fs::read(&fixture.forge_log).map_err(|error| error.to_string())?,
        fixture.remote_ref()?,
    ))
}
