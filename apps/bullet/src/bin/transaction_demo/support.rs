use bullet_domain::{Digest, RunnerId, REPOSITORY_GATE_ID};
use bullet_runner_core::lease::{HeartbeatCall, LeaseClient};
use bullet_runner_core::{ExpectedLeaseServer, SignedLeaseRpcClient};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use super::verifier_binary::verifier_fixture_binary;

pub(super) const FIXTURE_KEY: [u8; 32] = [0x5a; 32];
#[derive(Serialize)]
pub(super) struct FixturePermitClaims {
    pub(super) schema_version: String,
    pub(super) attempt_id: String,
    pub(super) attempt_fence: u64,
    pub(super) workspace_nonce_hex: String,
    pub(super) destination: String,
}
#[derive(Serialize)]
pub(super) struct FixturePermit {
    claims: FixturePermitClaims,
    mac_hex: String,
}
pub(super) fn fail(message: impl Into<String>) -> String {
    message.into()
}
pub(super) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn framed_digest(fields: &[&[u8]]) -> String {
    let mut buf = Vec::new();
    for field in fields {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    Digest::of(&buf).to_hex()
}
pub(super) fn mint_fixture_permit(claims: FixturePermitClaims) -> FixturePermit {
    let body = serde_json::to_vec(&claims).expect("claims");
    let mac_hex = framed_digest(&[b"bullet-gitd.fixture-permit.mac.v1", &FIXTURE_KEY, &body]);
    FixturePermit { claims, mac_hex }
}
pub(super) fn private_dir(path: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(path).map_err(|err| fail(format!("create {}: {err}", path.display())))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| fail(format!("chmod {}: {err}", path.display())))?;
    fs::canonicalize(path).map_err(|err| fail(format!("canonicalize {}: {err}", path.display())))
}
const FARMD_BIN_ENV: &str = "BULLET_FARMD_BIN";

fn kernel_bin(name: &str) -> PathBuf {
    let override_name = match name {
        "bullet-farmd" => Some(FARMD_BIN_ENV),
        _ => None,
    };
    if let Some(path) = override_name.and_then(std::env::var_os) {
        return PathBuf::from(path);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug")
        .join(name)
}
pub(super) fn wait_for(path: &Path, tries: u32) -> Result<(), String> {
    for _ in 0..tries {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(fail(format!("timed out waiting for {}", path.display())))
}
pub(super) struct FarmdGuard(Option<Child>);

impl FarmdGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
    pub(super) fn stop(mut self) -> Result<(), String> {
        stop_child(self.0.take().expect("farmd child is owned"))
    }
}
impl Drop for FarmdGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.take() {
            let _ = stop_child(child);
        }
    }
}
pub(super) struct LeaseHeartbeatGuard {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}
impl LeaseHeartbeatGuard {
    pub(super) fn start(client: &Arc<SignedLeaseRpcClient>, call: HeartbeatCall) -> Self {
        let client = Arc::clone(client);
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = &mut stopped => return Ok(()),
                    _ = interval.tick() => {
                        client
                            .heartbeat(&call)
                            .await
                            .map_err(|error| fail(error.to_string()))?;
                    }
                }
            }
        });
        Self {
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub(super) async fn stop(mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task
            .take()
            .expect("heartbeat task is owned")
            .await
            .map_err(|error| fail(format!("join lease heartbeat: {error}")))?
    }
}
impl Drop for LeaseHeartbeatGuard {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
fn stop_child(mut child: Child) -> Result<(), String> {
    let mut errors = Vec::new();
    match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => errors.push(format!("inspect child: {error}")),
    }
    if let Err(error) = child.kill() {
        errors.push(format!("kill child: {error}"));
    }
    if let Err(error) = child.wait() {
        errors.push(format!("wait for child: {error}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(fail(errors.join("; ")))
    }
}
pub(super) fn sh(dir: &Path, script: &str) -> Result<(), String> {
    let out = Command::new("sh")
        .arg("-ec")
        .arg(script)
        .current_dir(dir)
        .output()
        .map_err(|err| fail(format!("spawn git: {err}")))?;
    if !out.status.success() {
        return Err(fail(format!(
            "git: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}
pub(super) fn init_source(root: &Path) -> Result<(PathBuf, String), String> {
    let src = root.join("source");
    fs::create_dir_all(src.join("src")).map_err(|err| fail(err.to_string()))?;
    fs::write(src.join("src").join("lib.rs"), "pub fn seed() {}\n")
        .map_err(|err| fail(err.to_string()))?;
    sh(
        &src,
        "git init -q -b main . && git config user.name bullet && git config user.email bullet@test && git add . && git commit -qm seed",
    )?;
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&src)
        .output()
        .map_err(|err| fail(err.to_string()))?;
    let hex = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((src, format!("sha1:{hex}")))
}

pub(super) fn spawn_farmd(
    data: &Path,
    socket: &Path,
    runner: &RunnerId,
    runner_epoch: u64,
) -> Result<FarmdGuard, String> {
    let bin = kernel_bin("bullet-farmd");
    if !bin.is_file() {
        return Err(fail(format!(
            "bullet-farmd missing at {} (build -p bullet-farmd)",
            bin.display()
        )));
    }
    let child = Command::new(bin)
        .arg("--data-dir")
        .arg(data)
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--lease-transport-socket")
        .arg(socket)
        .arg("--fixture-lease-peer-registration")
        .arg(format!("{}:{runner_epoch}", runner.as_str()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| fail(format!("spawn farmd: {err}")))?;
    Ok(FarmdGuard::new(child))
}

pub(super) fn admitted_lease_client(
    socket: PathBuf,
    runner: &RunnerId,
    runner_epoch: u64,
) -> Result<Arc<SignedLeaseRpcClient>, String> {
    let process = fs::metadata("/proc/self")
        .map_err(|err| fail(format!("inspect transaction demo identity: {err}")))?;
    let expected_server = ExpectedLeaseServer::new(process.uid(), process.gid());
    Ok(Arc::new(SignedLeaseRpcClient::new_admitted(
        socket,
        runner.clone(),
        runner_epoch,
        expected_server,
    )))
}

pub(super) fn run_verifier(
    workspace: &Path,
    base: &str,
    head: &str,
    tree: &str,
    attempt: &str,
    overlap: bool,
) -> Result<(i32, Value), String> {
    enable_child_subreaper().map_err(|err| fail(format!("enable verifier subreaper: {err}")))?;
    let admitted = verifier_fixture_binary()?;
    let spawn_path = admitted.spawn_path()?;
    let request = json!({
        "workspace_repo_path": workspace.display().to_string(),
        "base_sha": base,
        "head_sha": head,
        "tree_sha": tree,
        "gate_id": REPOSITORY_GATE_ID,
        "author_attempt_id": attempt,
    });
    let mut cmd = Command::new(spawn_path);
    cmd.arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if overlap {
        cmd.env("BULLET_VERIFIER_AUTHOR_OVERLAP", "1");
    }
    let child = cmd
        .spawn()
        .map_err(|err| fail(format!("spawn verifier: {err}")))?;
    let mut child = ProcessGuard::new(child);
    child
        .write_request(request.to_string().as_bytes())
        .map_err(|err| fail(err.to_string()))?;
    let out = child
        .wait_with_output()
        .map_err(|err| fail(err.to_string()))?;
    let text = if out.stdout.is_empty() {
        String::from_utf8_lossy(&out.stderr).into_owned()
    } else {
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let value = serde_json::from_str(text.trim()).unwrap_or(json!({ "raw": text.trim() }));
    Ok((out.status.code().unwrap_or(1), value))
}

struct ProcessGuard {
    child: Option<Child>,
    process_group: u32,
}

impl ProcessGuard {
    fn new(child: Child) -> Self {
        let process_group = child.id();
        Self {
            child: Some(child),
            process_group,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("verifier child is owned")
    }

    fn write_request(&mut self, payload: &[u8]) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind, Write as _};

        let mut stdin = self
            .child_mut()
            .stdin
            .take()
            .ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "verifier stdin pipe missing"))?;
        stdin.write_all(payload)
    }

    fn kill_process_group_members(&self) -> std::io::Result<()> {
        let process_group = process_id(self.process_group)?;
        match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
            Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
            result => result.map_err(std::io::Error::from),
        }
    }

    fn reap_process_group_members(&self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let process_group = process_id(self.process_group)?;
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                match rustix::process::waitpgid(process_group, rustix::process::WaitOptions::NOHANG)
                {
                    Ok(Some(_)) => {}
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "verifier process-group reap timed out",
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
        if let Err(error) = self.kill_process_group_members() {
            errors.push(format!("signal verifier process group: {error}"));
        }
        if let Some(child) = self.child.take() {
            if let Err(error) = stop_child(child) {
                errors.push(error);
            }
        }
        if let Err(error) = self.reap_process_group_members() {
            errors.push(format!("reap verifier process group: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(errors.join("; ")))
        }
    }

    fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
        use std::io::{Error, ErrorKind, Read as _};
        use std::sync::mpsc;

        const OUTPUT_LIMIT: u64 = 64 * 1024;
        const TIMEOUT: Duration = Duration::from_secs(30);
        const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

        let stdout = self
            .child_mut()
            .stdout
            .take()
            .ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "verifier stdout pipe missing"))?;
        let stderr = self
            .child_mut()
            .stderr
            .take()
            .ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "verifier stderr pipe missing"))?;
        let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = stdout_tx.send(result);
        });
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stderr
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = stderr_tx.send(result);
        });
        let deadline = std::time::Instant::now() + TIMEOUT;
        let status = loop {
            match self.child_mut().try_wait() {
                Ok(Some(status)) => {
                    let group_result = self.kill_process_group_members();
                    self.child.take();
                    let reap_result = self.reap_process_group_members();
                    break group_result.and(reap_result).map(|()| status);
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    break match self.terminate() {
                        Ok(()) => Err(Error::new(
                            ErrorKind::TimedOut,
                            "verifier process timed out",
                        )),
                        Err(error) => Err(error),
                    };
                }
                Err(error) => {
                    break match self.terminate() {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(Error::other(format!(
                            "verifier wait failed: {error}; containment cleanup failed: {cleanup}"
                        ))),
                    };
                }
            }
        };
        let drain_deadline = std::time::Instant::now() + PIPE_DRAIN_TIMEOUT;
        let stdout = stdout_rx
            .recv_timeout(drain_deadline.saturating_duration_since(std::time::Instant::now()))
            .map_err(|_| Error::new(ErrorKind::TimedOut, "verifier stdout drain timed out"))??;
        let stderr = stderr_rx
            .recv_timeout(drain_deadline.saturating_duration_since(std::time::Instant::now()))
            .map_err(|_| Error::new(ErrorKind::TimedOut, "verifier stderr drain timed out"))??;
        if stdout.len() > OUTPUT_LIMIT as usize || stderr.len() > OUTPUT_LIMIT as usize {
            return Err(Error::other("verifier output exceeded 64 KiB"));
        }
        Ok(std::process::Output {
            status: status?,
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

fn process_id(raw: u32) -> std::io::Result<rustix::process::Pid> {
    let raw = i32::try_from(raw)
        .map_err(|_| std::io::Error::other("process id exceeds the platform range"))?;
    rustix::process::Pid::from_raw(raw)
        .ok_or_else(|| std::io::Error::other("process id must be non-zero"))
}

fn enable_child_subreaper() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let own = process_id(std::process::id())?;
        rustix::process::set_child_subreaper(Some(own)).map_err(std::io::Error::from)
    }
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

pub(super) fn strip_oid(oid: &str) -> &str {
    oid.rsplit(':').next().unwrap_or(oid)
}

pub(super) fn content_id(label: &str) -> String {
    format!("cnt_{}", Digest::of(label.as_bytes()).to_hex())
}
