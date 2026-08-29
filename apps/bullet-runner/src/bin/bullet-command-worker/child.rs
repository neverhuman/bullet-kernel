//! Bounded, environment-cleared component child supervision.

use super::claim_fd::SealedClaim;
use super::error::{WorkerContext, WorkerError};
use super::manifest::AdmittedManifest;
use std::io::Read;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: u64 = 256 * 1024;
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) struct ChildOutput {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

pub(super) fn run_transaction(
    manifest: &AdmittedManifest,
    claim: &SealedClaim,
    run_root: &Path,
    receipt: &Path,
    deadline: Duration,
) -> Result<ChildOutput, WorkerError> {
    validate_child_roots(run_root, receipt)?;
    enable_subreaper()?;
    let mut command = Command::new(manifest.transaction_offline.procfd_path());
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("BULLET_COMMAND_CLAIM_FD", claim.fd().to_string())
        .env("BULLET_COMMAND_BINARY_MANIFEST_DIGEST", manifest.sha256())
        .env("BULLET_FARMD_BIN", manifest.farmd.procfd_path())
        .env("BULLET_RUNNER_BIN", manifest.runner.procfd_path())
        .env("BULLET_GITD_BIN", manifest.gitd.original())
        .env("BULLET_GITD_SHA256", manifest.gitd.sha256())
        .env(
            "BULLET_VERIFIER_FIXTURE_FD",
            manifest.verifier.inherited_fd().to_string(),
        )
        .env("BULLET_VERIFIER_FIXTURE_SHA256", manifest.verifier.sha256())
        .env("BULLET_DATA_DIR", run_root.join("data"))
        .env(
            "TRANSACTION_OFFLINE_ARTIFACT_ROOT",
            run_root.join("artifacts"),
        )
        .env("TRANSACTION_OFFLINE_RECEIPT", receipt)
        .current_dir(run_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let child = command.spawn().worker(
        "COMMAND_CHILD_SPAWN_FAILED",
        "spawn exact transaction child",
    )?;
    ProcessGuard::new(child).wait_with_output(deadline)
}

fn validate_child_roots(run_root: &Path, receipt: &Path) -> Result<(), WorkerError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let canonical = run_root
        .canonicalize()
        .worker("COMMAND_CHILD_ROOT_INVALID", "canonicalize run root")?;
    let meta = std::fs::symlink_metadata(run_root)
        .worker("COMMAND_CHILD_ROOT_INVALID", "inspect run root")?;
    if canonical != run_root
        || !meta.file_type().is_dir()
        || meta.permissions().mode() & 0o777 != 0o700
        || receipt.parent() != Some(run_root)
    {
        return Err(WorkerError::input(
            "COMMAND_CHILD_ROOT_INVALID",
            "child roots are not new beneath one private canonical run root",
        ));
    }
    require_absent(&run_root.join("data"))?;
    require_absent(&run_root.join("artifacts"))?;
    if !receipt.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(receipt)
            .worker("COMMAND_CHILD_ROOT_INVALID", "reserve private receipt file")?
            .sync_all()
            .worker("COMMAND_CHILD_ROOT_INVALID", "sync private receipt file")?;
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), WorkerError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(WorkerError::input(
            "COMMAND_CHILD_ROOT_INVALID",
            "child data and artifact roots must not exist",
        )),
        Err(error) => Err(WorkerError::input(
            "COMMAND_CHILD_ROOT_INVALID",
            format!("inspect child root: {error}"),
        )),
    }
}

struct ProcessGuard {
    child: Option<Child>,
    group: u32,
}

impl ProcessGuard {
    fn new(child: Child) -> Self {
        let group = child.id();
        Self {
            child: Some(child),
            group,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child owned")
    }

    fn kill_group(&self) -> std::io::Result<()> {
        let group = pid(self.group)?;
        match rustix::process::kill_process_group(group, rustix::process::Signal::KILL) {
            Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
            result => result.map_err(std::io::Error::from),
        }
    }

    fn reap_group(&self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let group = pid(self.group)?;
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match rustix::process::waitpgid(group, rustix::process::WaitOptions::NOHANG) {
                    Ok(Some(_)) => {}
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "process-group reap timed out",
                        ));
                    }
                    Err(error) if error == rustix::io::Errno::CHILD => return Ok(()),
                    Err(error) => return Err(std::io::Error::from(error)),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        Ok(())
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        let mut errors = Vec::new();
        if let Err(error) = self.kill_group() {
            errors.push(format!("kill process group: {error}"));
        }
        if let Some(mut child) = self.child.take() {
            if let Err(error) = child.wait() {
                errors.push(format!("reap child: {error}"));
            }
        }
        if let Err(error) = self.reap_group() {
            errors.push(format!("reap process group: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(errors.join("; ")))
        }
    }

    fn wait_with_output(mut self, timeout: Duration) -> Result<ChildOutput, WorkerError> {
        let stdout = self
            .child_mut()
            .stdout
            .take()
            .ok_or_else(|| WorkerError::input("COMMAND_CHILD_PIPE_FAILED", "stdout missing"))?;
        let stderr = self
            .child_mut()
            .stderr
            .take()
            .ok_or_else(|| WorkerError::input("COMMAND_CHILD_PIPE_FAILED", "stderr missing"))?;
        let (out_tx, out_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = out_tx.send(result);
        });
        let (err_tx, err_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stderr
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = err_tx.send(result);
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            match self.child_mut().try_wait() {
                Ok(Some(status)) => {
                    self.child.take();
                    self.kill_group().worker(
                        "COMMAND_CHILD_CLEANUP_FAILED",
                        "kill descendant process group",
                    )?;
                    self.reap_group().worker(
                        "COMMAND_CHILD_CLEANUP_FAILED",
                        "reap descendant process group",
                    )?;
                    break status;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    self.terminate()
                        .worker("COMMAND_CHILD_TIMEOUT", "terminate timed-out child")?;
                    return Err(WorkerError::input(
                        "COMMAND_CHILD_TIMEOUT",
                        "transaction child exceeded its monotonic deadline",
                    ));
                }
                Err(error) => {
                    let _ = self.terminate();
                    return Err(WorkerError::input(
                        "COMMAND_CHILD_WAIT_FAILED",
                        error.to_string(),
                    ));
                }
            }
        };
        let drain = Instant::now() + PIPE_DRAIN_TIMEOUT;
        let stdout = out_rx
            .recv_timeout(drain.saturating_duration_since(Instant::now()))
            .worker("COMMAND_CHILD_PIPE_FAILED", "drain child stdout")?
            .worker("COMMAND_CHILD_PIPE_FAILED", "read child stdout")?;
        let stderr = err_rx
            .recv_timeout(drain.saturating_duration_since(Instant::now()))
            .worker("COMMAND_CHILD_PIPE_FAILED", "drain child stderr")?
            .worker("COMMAND_CHILD_PIPE_FAILED", "read child stderr")?;
        if stdout.len() > OUTPUT_LIMIT as usize || stderr.len() > OUTPUT_LIMIT as usize {
            return Err(WorkerError::input(
                "COMMAND_CHILD_OUTPUT_LIMIT",
                "transaction child output exceeded 256 KiB",
            ));
        }
        Ok(ChildOutput {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.terminate();
        }
    }
}

fn pid(raw: u32) -> std::io::Result<rustix::process::Pid> {
    rustix::process::Pid::from_raw(
        i32::try_from(raw).map_err(|_| std::io::Error::other("pid overflow"))?,
    )
    .ok_or_else(|| std::io::Error::other("pid is zero"))
}

fn enable_subreaper() -> Result<(), WorkerError> {
    #[cfg(target_os = "linux")]
    rustix::process::set_child_subreaper(Some(
        pid(std::process::id()).worker("COMMAND_CHILD_CONTAINMENT_FAILED", "read worker pid")?,
    ))
    .worker("COMMAND_CHILD_CONTAINMENT_FAILED", "enable child subreaper")?;
    Ok(())
}

#[cfg(test)]
#[path = "child/tests.rs"]
mod tests;
