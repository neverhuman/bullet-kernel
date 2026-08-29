use bullet_domain::{Digest, RunnerId, REPOSITORY_GATE_ID};
use bullet_runner_core::lease::{HeartbeatCall, LeaseClient};
use bullet_runner_core::{ExpectedLeaseServer, SignedLeaseRpcClient};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

#[cfg(debug_assertions)]
use super::process_observation::observe_and_guard_verifier;
use super::verifier_binary::verifier_fixture_binary;
use super::verifier_process::enable_child_subreaper;
#[cfg(not(debug_assertions))]
use super::verifier_process::ProcessGuard;
use super::{chaos, chaos::Boundary};
use bullet_harness_core::candidate_preparation::{
    CandidatePreparationSigningKey, CandidatePreparationVerificationKey,
};
use bullet_harness_core::lease_transport::LeaseTransportSigningKey;

const CANDIDATE_KEY_ISSUER: &str = "kernel-local";
const CANDIDATE_KEY_ID: &str = "candidate-preparation-1";
const LEASE_RUNTIME_ROOT: &str = "/tmp";
const UNIX_SOCKET_PATH_BUDGET: usize = 100;

#[allow(dead_code)]
pub(super) const FIXTURE_KEY: [u8; 32] = [0x5a; 32];
#[allow(dead_code)]
#[derive(Serialize)]
pub(super) struct FixturePermitClaims {
    pub(super) schema_version: String,
    pub(super) attempt_id: String,
    pub(super) attempt_fence: u64,
    pub(super) workspace_nonce_hex: String,
    pub(super) destination: String,
}
#[allow(dead_code)]
#[derive(Serialize)]
pub(super) struct FixturePermit {
    claims: FixturePermitClaims,
    mac_hex: String,
}
pub(super) fn fail(message: impl Into<String>) -> String {
    message.into()
}
#[allow(dead_code)]
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
#[allow(dead_code)]
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
const PUBLIC_COMMAND_SOURCE_ENV: &str = "BULLET_COMMAND_CLAIM_FD";

pub(super) fn kernel_bin(name: &str) -> PathBuf {
    let override_name = match name {
        "bullet-farmd" => Some(FARMD_BIN_ENV),
        _ => None,
    };
    if let Some(path) = override_name.and_then(std::env::var_os) {
        return PathBuf::from(path);
    }
    if std::env::var_os(PUBLIC_COMMAND_SOURCE_ENV).is_some() {
        return PathBuf::from("/public-command-worker-subject-unprovisioned");
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug")
        .join(name)
}
pub(super) fn wait_for(path: &Path, tries: u32) -> Result<(), String> {
    for _ in 0..tries {
        if UnixStream::connect(path).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(fail(format!("timed out waiting for {}", path.display())))
}
pub(super) struct FarmdGuard(Option<Child>);

impl FarmdGuard {
    pub(super) fn new(child: Child) -> Self {
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
                        let mut retries = 0;
                        loop {
                            match client.heartbeat(&call).await {
                                Ok(()) => break,
                                Err(error)
                                    if matches!(error.reason_code(), "IO_FAILED" | "PROTOCOL_ERROR")
                                        && retries < 3 =>
                                {
                                    retries += 1;
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                                Err(error) => return Err(fail(error.to_string())),
                            }
                        }
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
pub(super) fn stop_child(mut child: Child) -> Result<(), String> {
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

pub(super) struct DurableFarmd {
    guard: FarmdGuard,
    _lease_runtime: tempfile::TempDir,
    pub(super) lease_socket: PathBuf,
    pub(super) kernel_socket: PathBuf,
    pub(super) recovery: PathBuf,
    pub(super) candidate_verification_key: PathBuf,
    pub(super) candidate_verification_key_material: CandidatePreparationVerificationKey,
    pub(super) farmd_uid: u32,
    pub(super) socket_gid: u32,
}

impl DurableFarmd {
    pub(super) fn stop(self) -> Result<(), String> {
        self.guard.stop()
    }
}

#[derive(Serialize)]
struct CandidateVerificationKeyRecord<'a> {
    schema_version: &'static str,
    issuer: &'static str,
    key_id: &'static str,
    public_key_hex: &'a str,
}

pub(super) fn spawn_durable_farmd(
    data: &Path,
    runner: &RunnerId,
    runner_epoch: u64,
) -> Result<DurableFarmd, String> {
    let bin = kernel_bin("bullet-farmd");
    if !bin.is_file() {
        return Err(fail(format!(
            "bullet-farmd missing at {} (build -p bullet-farmd)",
            bin.display()
        )));
    }
    let process =
        fs::metadata("/proc/self").map_err(|err| fail(format!("inspect farmd identity: {err}")))?;
    let farmd_uid = process.uid();
    let socket_gid = process.gid();
    let (lease_runtime, socket, kernel_socket) = create_lease_runtime()?;
    let custody = private_dir(&data.join("custody"))?;
    let key_path = custody.join("signing.key");
    let registry_path = custody.join("peer-registry.json");
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1")
        .map_err(|err| fail(err.to_string()))?;
    let candidate_key = CandidatePreparationSigningKey::from_bytes(
        CANDIDATE_KEY_ISSUER,
        CANDIDATE_KEY_ID,
        key.secret_bytes(),
    )
    .map_err(|err| fail(format!("derive Candidate verification key: {err}")))?;
    let candidate_verification_key = custody.join("candidate-verification-key.json");
    let candidate_verification_key_material = candidate_key
        .verification_key()
        .map_err(|err| fail(format!("derive Candidate public-key material: {err}")))?;
    let candidate_record = CandidateVerificationKeyRecord {
        schema_version: "v1alpha1",
        issuer: CANDIDATE_KEY_ISSUER,
        key_id: CANDIDATE_KEY_ID,
        public_key_hex: candidate_key.public_key_hex(),
    };
    write_private_file(
        &candidate_verification_key,
        &serde_json::to_vec(&candidate_record)
            .map_err(|err| fail(format!("encode Candidate verification key: {err}")))?,
    )?;
    write_private_file(&key_path, key.secret_bytes())?;
    let registry = serde_json::json!({
        "farmd_uid": farmd_uid,
        "socket_gid": socket_gid,
        "runners": [{
            "runner_id": runner.to_string(),
            "runner_epoch": runner_epoch,
            "service_uid": farmd_uid
        }]
    });
    write_private_file(
        &registry_path,
        &serde_json::to_vec(&registry).map_err(|err| fail(err.to_string()))?,
    )?;
    let recovery = data.join("lease-recovery.json");
    let child = Command::new(bin)
        .arg("--data-dir")
        .arg(data)
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--lease-transport-socket")
        .arg(&socket)
        .arg("--lease-peer-registry")
        .arg(&registry_path)
        .arg("--lease-transport-key")
        .arg(&key_path)
        .arg("--kernel-authority-socket")
        .arg(&kernel_socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| fail(format!("spawn farmd: {err}")))?;
    Ok(DurableFarmd {
        guard: FarmdGuard::new(child),
        _lease_runtime: lease_runtime,
        lease_socket: socket,
        kernel_socket,
        recovery,
        candidate_verification_key,
        candidate_verification_key_material,
        farmd_uid,
        socket_gid,
    })
}

pub(super) fn create_lease_runtime() -> Result<(tempfile::TempDir, PathBuf, PathBuf), String> {
    let runtime = tempfile::Builder::new()
        .prefix("bullet-l.")
        .tempdir_in(LEASE_RUNTIME_ROOT)
        .map_err(|error| fail(format!("create bounded lease runtime: {error}")))?;
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o710))
        .map_err(|error| fail(format!("chmod bounded lease runtime: {error}")))?;
    let lease_socket = runtime.path().join("lease.sock");
    let kernel_socket = runtime.path().join("kernel.sock");
    for socket in [&lease_socket, &kernel_socket] {
        if socket.as_os_str().as_bytes().len() > UNIX_SOCKET_PATH_BUDGET {
            return Err(fail(format!(
                "bounded lease socket path exceeds {UNIX_SOCKET_PATH_BUDGET} bytes"
            )));
        }
    }
    Ok((runtime, lease_socket, kernel_socket))
}

pub(super) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| fail(format!("write {}: {err}", path.display())))?;
    file.write_all(bytes)
        .map_err(|err| fail(format!("write {}: {err}", path.display())))?;
    file.sync_all()
        .map_err(|err| fail(format!("sync {}: {err}", path.display())))?;
    Ok(())
}

pub(super) fn admitted_lease_client(
    socket: PathBuf,
    recovery: PathBuf,
    runner: &RunnerId,
    runner_epoch: u64,
) -> Result<Arc<SignedLeaseRpcClient>, String> {
    let process = fs::metadata("/proc/self")
        .map_err(|err| fail(format!("inspect transaction demo identity: {err}")))?;
    let expected_server = ExpectedLeaseServer::new(process.uid(), process.gid());
    Ok(Arc::new(
        SignedLeaseRpcClient::new_admitted(socket, runner.clone(), runner_epoch, expected_server)
            .with_recovery_file(recovery)
            .map_err(|error| fail(error.to_string()))?,
    ))
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
    let fault = chaos::fault_for(Boundary::VerifierHandoff)?;
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
    #[cfg(debug_assertions)]
    let mut child = observe_and_guard_verifier(child, fault.is_some())?;
    #[cfg(not(debug_assertions))]
    let mut child = ProcessGuard::new(child);
    if let Some(cell) = fault {
        child.signal_process_group(cell.signal()).map_err(|error| {
            fail(format!(
                "CHAOS_FAULT_SIGNAL_FAILED: cell={} error={error}",
                cell.label()
            ))
        })?;
        let outcome = child.wait_with_output_for(cell.deadline());
        return Err(chaos::validate_process_fault(cell, &outcome)?);
    }
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

pub(super) fn strip_oid(oid: &str) -> &str {
    oid.rsplit(':').next().unwrap_or(oid)
}

pub(super) fn content_id(label: &str) -> String {
    format!("cnt_{}", Digest::of(label.as_bytes()).to_hex())
}

#[cfg(test)]
mod lease_runtime_tests {
    use super::*;

    #[test]
    fn runtime_is_private_bounded_and_removed_with_its_guard() {
        let (runtime, lease_socket, kernel_socket) = create_lease_runtime().expect("runtime");
        let root = runtime.path().to_path_buf();
        assert_eq!(root.parent(), Some(Path::new(LEASE_RUNTIME_ROOT)));
        assert_eq!(
            fs::metadata(&root).expect("metadata").permissions().mode() & 0o777,
            0o710
        );
        for socket in [lease_socket, kernel_socket] {
            assert_eq!(socket.parent(), Some(root.as_path()));
            assert!(socket.as_os_str().as_bytes().len() <= UNIX_SOCKET_PATH_BUDGET);
        }
        drop(runtime);
        assert!(!root.exists());
    }
}
