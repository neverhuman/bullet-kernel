use bullet_domain::{Digest, RunnerId, REPOSITORY_GATE_ID};
use bullet_runner_core::lease::{HeartbeatCall, LeaseClient};
use bullet_runner_core::{ExpectedLeaseServer, SignedLeaseRpcClient};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

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

fn kernel_bin(name: &str) -> PathBuf {
    let env = format!("BULLET_{}_BIN", name.to_ascii_uppercase().replace('-', "_"));
    if let Some(path) = std::env::var_os(&env) {
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
    let kill_error = if child
        .try_wait()
        .map_err(|err| fail(format!("inspect farmd: {err}")))?
        .is_none()
    {
        child.kill().err()
    } else {
        None
    };
    match child.wait() {
        Ok(_) => Ok(()),
        Err(wait_error) => match kill_error {
            Some(kill_error) => Err(fail(format!(
                "kill farmd: {kill_error}; wait for farmd: {wait_error}"
            ))),
            None => Err(fail(format!("wait for farmd: {wait_error}"))),
        },
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
    let bin = kernel_bin("bullet-verifier");
    if !bin.is_file() {
        return Err(fail(format!(
            "bullet-verifier missing at {}",
            bin.display()
        )));
    }
    let request = json!({
        "workspace_repo_path": workspace.display().to_string(),
        "base_sha": base,
        "head_sha": head,
        "tree_sha": tree,
        "gate_id": REPOSITORY_GATE_ID,
        "author_attempt_id": attempt,
    });
    let mut cmd = Command::new(bin);
    cmd.arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if overlap {
        cmd.env("BULLET_VERIFIER_AUTHOR_OVERLAP", "1");
    }
    let mut child = cmd
        .spawn()
        .map_err(|err| fail(format!("spawn verifier: {err}")))?;
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| fail("verifier stdin"))?
        .write_all(request.to_string().as_bytes())
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

pub(super) fn strip_oid(oid: &str) -> &str {
    oid.rsplit(':').next().unwrap_or(oid)
}

pub(super) fn content_id(label: &str) -> String {
    format!("cnt_{}", Digest::of(label.as_bytes()).to_hex())
}
