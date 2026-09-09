//! Private two-Runner farmd fixture for debug-only synthetic dogfood mechanics.

mod binary;

use super::support::{
    create_lease_runtime, fail, kernel_bin, private_dir, write_private_file, FarmdGuard,
};
use bullet_domain::RunnerId;
use bullet_harness_core::candidate_preparation::{
    CandidatePreparationSigningKey, CandidatePreparationVerificationKey,
};
use bullet_harness_core::lease_transport::LeaseTransportSigningKey;
use bullet_runner_core::{ExpectedLeaseServer, SignedLeaseRpcClient};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

const CANDIDATE_KEY_ISSUER: &str = "kernel-local";
const CANDIDATE_KEY_ID: &str = "candidate-preparation-1";
const FARMD_DIGEST_ENV: &str = "BULLET_FARMD_SHA256";

#[derive(Clone, Debug)]
pub(super) struct RunnerRegistration {
    pub(super) runner_id: RunnerId,
    pub(super) runner_epoch: u64,
}

pub(super) struct SyntheticFarmd {
    guard: FarmdGuard,
    _lease_runtime: tempfile::TempDir,
    pub(super) lease_socket: PathBuf,
    pub(super) kernel_socket: PathBuf,
    pub(super) candidate_verification_key: PathBuf,
    pub(super) farmd_uid: u32,
    pub(super) socket_gid: u32,
    recovery_files: Vec<PathBuf>,
}

impl SyntheticFarmd {
    pub(super) fn client(
        &self,
        index: usize,
        registration: &RunnerRegistration,
    ) -> Result<Arc<SignedLeaseRpcClient>, String> {
        let recovery = self
            .recovery_files
            .get(index)
            .ok_or_else(|| fail("synthetic Runner recovery index is absent"))?;
        let expected = ExpectedLeaseServer::new(self.farmd_uid, self.socket_gid);
        let client = SignedLeaseRpcClient::new_admitted(
            self.lease_socket.clone(),
            registration.runner_id.clone(),
            registration.runner_epoch,
            expected,
        )
        .with_recovery_file(recovery)
        .map_err(|error| fail(format!("open synthetic Runner recovery: {error}")))?;
        Ok(Arc::new(client))
    }

    pub(super) fn recovery_file(&self, index: usize) -> Option<&Path> {
        self.recovery_files.get(index).map(PathBuf::as_path)
    }

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

pub(super) fn spawn_synthetic_farmd(
    data: &Path,
    registrations: &[RunnerRegistration],
) -> Result<SyntheticFarmd, String> {
    spawn_synthetic_farmd_inner(
        data,
        registrations,
        2,
        "synthetic-custody",
        "synthetic-runner",
    )
}

pub(super) fn spawn_synthetic_effect_farmd(
    data: &Path,
    registration: &RunnerRegistration,
) -> Result<SyntheticFarmd, String> {
    spawn_synthetic_farmd_inner(
        data,
        std::slice::from_ref(registration),
        1,
        "synthetic-effect-custody",
        "synthetic-effect-runner",
    )
}

fn spawn_synthetic_farmd_inner(
    data: &Path,
    registrations: &[RunnerRegistration],
    expected_count: usize,
    custody_name: &str,
    recovery_prefix: &str,
) -> Result<SyntheticFarmd, String> {
    let distinct = registrations.iter().enumerate().all(|(index, runner)| {
        registrations[..index]
            .iter()
            .all(|prior| prior.runner_id != runner.runner_id)
    });
    if registrations.len() != expected_count
        || !distinct
        || registrations.iter().any(|runner| runner.runner_epoch == 0)
    {
        return Err(fail(
            "synthetic farmd requires the exact distinct nonzero Runner principal count",
        ));
    }
    let bin = kernel_bin("bullet-farmd");
    let expected_digest = std::env::var(FARMD_DIGEST_ENV)
        .map_err(|_| fail("synthetic bullet-farmd digest is unprovisioned"))?;
    let admitted = binary::AdmittedFarmdBinary::open(&bin, &expected_digest)?;
    let process = fs::metadata("/proc/self")
        .map_err(|error| fail(format!("inspect farmd identity: {error}")))?;
    let farmd_uid = process.uid();
    let socket_gid = process.gid();
    let (lease_runtime, lease_socket, kernel_socket) = create_lease_runtime()?;
    let custody = private_dir(&data.join(custody_name))?;
    let key_path = custody.join("signing.key");
    let registry_path = custody.join("peer-registry.json");
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1")
        .map_err(|error| fail(error.to_string()))?;
    let candidate_key = CandidatePreparationSigningKey::from_bytes(
        CANDIDATE_KEY_ISSUER,
        CANDIDATE_KEY_ID,
        key.secret_bytes(),
    )
    .map_err(|error| fail(format!("derive Candidate verification key: {error}")))?;
    let candidate_verification_key = custody.join("candidate-verification-key.json");
    let candidate_verification_key_material: CandidatePreparationVerificationKey = candidate_key
        .verification_key()
        .map_err(|error| fail(format!("derive Candidate public key: {error}")))?;
    let candidate_record = CandidateVerificationKeyRecord {
        schema_version: "v1alpha1",
        issuer: CANDIDATE_KEY_ISSUER,
        key_id: CANDIDATE_KEY_ID,
        public_key_hex: candidate_key.public_key_hex(),
    };
    write_private_file(
        &candidate_verification_key,
        &serde_json::to_vec(&candidate_record)
            .map_err(|error| fail(format!("encode Candidate verification key: {error}")))?,
    )?;
    write_private_file(&key_path, key.secret_bytes())?;
    let runners = registrations
        .iter()
        .map(|registration| {
            serde_json::json!({
                "runner_id": registration.runner_id.to_string(),
                "runner_epoch": registration.runner_epoch,
                "service_uid": farmd_uid,
            })
        })
        .collect::<Vec<_>>();
    let registry = serde_json::json!({
        "farmd_uid": farmd_uid,
        "socket_gid": socket_gid,
        "runners": runners,
    });
    write_private_file(
        &registry_path,
        &serde_json::to_vec(&registry).map_err(|error| fail(error.to_string()))?,
    )?;
    let recovery_files = (0..registrations.len())
        .map(|index| data.join(format!("{recovery_prefix}-{index}-recovery.json")))
        .collect::<Vec<_>>();
    let child = Command::new(admitted.spawn_path()?)
        .arg("--data-dir")
        .arg(data)
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--lease-transport-socket")
        .arg(&lease_socket)
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
        .map_err(|error| fail(format!("spawn synthetic farmd: {error}")))?;
    drop(candidate_verification_key_material);
    Ok(SyntheticFarmd {
        guard: FarmdGuard::new(child),
        _lease_runtime: lease_runtime,
        lease_socket,
        kernel_socket,
        candidate_verification_key,
        farmd_uid,
        socket_gid,
        recovery_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_requires_two_distinct_principals_before_process_start() {
        let runner = RunnerRegistration {
            runner_id: RunnerId::from_seed("same"),
            runner_epoch: 1,
        };
        let error = spawn_synthetic_farmd(Path::new("/unused"), &[runner.clone(), runner])
            .err()
            .expect("refusal");
        assert!(error.contains("exact distinct nonzero"));
    }
}
