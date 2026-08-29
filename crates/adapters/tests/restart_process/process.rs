use crate::model::{MANIFEST_DIGEST_ENV, MANIFEST_ENV};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const CHILD_TIMEOUT: Duration = Duration::from_secs(20);
const ERROR_ENV: &str = "BULLET_RESTART_PROCESS_ERROR";
const MAX_ERROR_BYTES: u64 = 4 * 1024;
static ERROR_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) struct ChildResult {
    pub(crate) status: ExitStatus,
    pub(crate) diagnostic: Option<String>,
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn wait(mut self) -> Result<ChildResult, String> {
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            let child = self.0.as_mut().ok_or("child already consumed")?;
            let process_group = rustix::process::Pid::from_child(&*child);
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                let _ = rustix::process::kill_process_group(
                    process_group,
                    rustix::process::Signal::KILL,
                );
                self.0.take();
                return Ok(ChildResult {
                    status,
                    diagnostic: None,
                });
            }
            if Instant::now() >= deadline {
                return Err("restart worker exceeded deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let pid = rustix::process::Pid::from_child(child);
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(crate) fn run_worker(
    root: &Path,
    manifest_path: &Path,
    manifest_digest: &str,
) -> Result<ChildResult, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let sequence = ERROR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let error_path = root.join(format!("worker-error-{sequence}.txt"));
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg("recovery_worker_process")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env(MANIFEST_ENV, manifest_path)
        .env(MANIFEST_DIGEST_ENV, manifest_digest)
        .env(ERROR_ENV, &error_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let child = command
        .spawn()
        .map_err(|error| format!("spawn worker: {error}"))?;
    let mut result = ChildGuard(Some(child)).wait()?;
    result.diagnostic = read_worker_error(&error_path)?;
    Ok(result)
}

pub(crate) fn assert_success(result: &ChildResult) -> Result<(), String> {
    if result.status.success() {
        return Ok(());
    }
    Err(format!(
        "worker failed status={:?} diagnostic={:?}",
        result.status.code(),
        result.diagnostic
    ))
}

pub(crate) fn write_worker_error(error: &str) {
    let Some(path) = std::env::var_os(ERROR_ENV).map(PathBuf::from) else {
        return;
    };
    let bytes = error.as_bytes();
    let bounded = &bytes[..bytes.len().min(MAX_ERROR_BYTES as usize)];
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .and_then(|mut file| {
            file.write_all(bounded)?;
            file.sync_all()
        });
    let _ = result;
}

fn read_worker_error(path: &Path) -> Result<Option<String>, String> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    require_private_diagnostic(&before)?;
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => return Err(error.to_string()),
    };
    let opened = file.metadata().map_err(|error| error.to_string())?;
    same_diagnostic(&before, &opened)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ERROR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    same_diagnostic(&opened, &after)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn require_private_diagnostic(metadata: &std::fs::Metadata) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_ERROR_BYTES
    {
        return Err("worker diagnostic custody mismatch".into());
    }
    Ok(())
}

fn same_diagnostic(left: &std::fs::Metadata, right: &std::fs::Metadata) -> Result<(), String> {
    if left.dev() != right.dev()
        || left.ino() != right.ino()
        || left.uid() != right.uid()
        || left.mode() != right.mode()
        || left.nlink() != right.nlink()
        || left.len() != right.len()
    {
        return Err("worker diagnostic identity changed".into());
    }
    require_private_diagnostic(right)
}
