//! Native `run_coding` argv and labeled observation — never a simulator.

use super::{need_env, ChildOutput, WorkerError};
use bullet_application::{RunCodingPayload, RUN_CODING_KIND};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(crate) const CODING_OBSERVATION_SCHEMA: &str = "bullet.coding-harness-observation.v1";
pub(crate) const CODING_EVIDENCE_CLASS: &str = "CODING_HARNESS_OBSERVATION";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodingObservation {
    pub(crate) schema_version: String,
    pub(crate) evidence_class: String,
    pub(crate) transaction_gate_eligible: bool,
    pub(crate) independent_evidence_eligible: bool,
    pub(crate) command_id: String,
    pub(crate) kind: String,
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) allocated_run: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout_sha256: String,
    pub(crate) stderr_sha256: String,
    pub(crate) cost: String,
}

pub(super) fn coding_runner_args(payload: &RunCodingPayload) -> Result<Vec<String>, WorkerError> {
    let provider = match payload.provider.as_str() {
        "antigravity" => "agy".to_string(),
        "sim" => {
            return Err(WorkerError::input(
                "COMMAND_CODING_SIM_REFUSED",
                "run_coding never selects the simulator",
            ))
        }
        other => other.to_string(),
    };
    let mut args = vec![
        "--provider".into(),
        provider.clone(),
        "--model".into(),
        payload.model.clone(),
        "--runner-id".into(),
        payload.allocated_run.clone(),
        "--work-package-id".into(),
        need_env("BULLET_HARNESS_WORK_PACKAGE_ID")?,
        "--candidate-request-digest".into(),
        need_env("BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST")?,
        "--candidate-verification-key".into(),
        need_env("BULLET_HARNESS_CANDIDATE_VERIFICATION_KEY")?,
        "--workspace-root".into(),
        need_env("BULLET_HARNESS_WORKSPACE_ROOT")?,
        "--source-repo".into(),
        need_env("BULLET_HARNESS_SOURCE_REPO")?,
        "--base-sha".into(),
        need_env("BULLET_HARNESS_BASE_SHA")?,
        "--preservation-destination".into(),
        need_env("BULLET_HARNESS_PRESERVATION")?,
        "--objective".into(),
        need_env("BULLET_HARNESS_OBJECTIVE")?,
        "--gate-id".into(),
        need_env("BULLET_HARNESS_GATE_ID")?,
        "--scope".into(),
        need_env("BULLET_HARNESS_SCOPE")?,
        "--idempotency-key".into(),
        need_env("BULLET_HARNESS_IDEMPOTENCY_KEY")?,
        "--lease-socket".into(),
        need_env("BULLET_HARNESS_LEASE_SOCKET")?,
        "--farmd-uid".into(),
        need_env("BULLET_HARNESS_FARMD_UID")?,
        "--socket-gid".into(),
        need_env("BULLET_HARNESS_SOCKET_GID")?,
        "--lease-recovery".into(),
        need_env("BULLET_HARNESS_LEASE_RECOVERY")?,
    ];
    if let Ok(farmd) = std::env::var("BULLET_HARNESS_FARMD") {
        args.extend(["--farmd".into(), farmd]);
    }
    if payload.provider.as_str() == "claude" {
        args.extend(claude_dogfood_args()?);
    } else {
        args.extend([
            "--signed-in-executable".into(),
            need_env("BULLET_HARNESS_EXECUTABLE")?,
        ]);
    }
    let _ = provider;
    Ok(args)
}

fn claude_dogfood_args() -> Result<Vec<String>, WorkerError> {
    Ok(vec![
        "--dogfood-data-dir".into(),
        need_env("BULLET_HARNESS_DOGFOOD_DATA_DIR")?,
        "--dogfood-policy".into(),
        need_env("BULLET_HARNESS_DOGFOOD_POLICY")?,
        "--dogfood-binding".into(),
        need_env("BULLET_HARNESS_DOGFOOD_BINDING")?,
        "--dogfood-enrollment".into(),
        need_env("BULLET_HARNESS_DOGFOOD_ENROLLMENT")?,
        "--dogfood-issuer".into(),
        need_env("BULLET_HARNESS_DOGFOOD_ISSUER")?,
        "--dogfood-key-id".into(),
        need_env("BULLET_HARNESS_DOGFOOD_KEY_ID")?,
        "--dogfood-executable".into(),
        need_env("BULLET_HARNESS_EXECUTABLE")?,
        "--dogfood-receipt".into(),
        need_env("BULLET_HARNESS_DOGFOOD_RECEIPT")?,
        "--dogfood-max-budget-usd".into(),
        need_env("BULLET_HARNESS_DOGFOOD_MAX_BUDGET_USD")?,
    ])
}

pub(super) fn write_coding_observation(
    receipt: &Path,
    command_id: &str,
    payload: &RunCodingPayload,
    output: &ChildOutput,
) -> Result<(), WorkerError> {
    let observation = CodingObservation {
        schema_version: CODING_OBSERVATION_SCHEMA.into(),
        evidence_class: CODING_EVIDENCE_CLASS.into(),
        transaction_gate_eligible: false,
        independent_evidence_eligible: false,
        command_id: command_id.into(),
        kind: RUN_CODING_KIND.into(),
        provider: payload.provider.as_str().into(),
        model: payload.model.clone(),
        allocated_run: payload.allocated_run.clone(),
        exit_code: output.status.code(),
        stdout_sha256: hex::encode(Sha256::digest(&output.stdout)),
        stderr_sha256: hex::encode(Sha256::digest(&output.stderr)),
        cost: "UNPRICED".into(),
    };
    let bytes = serde_json::to_vec(&observation).map_err(|error| {
        WorkerError::input("COMMAND_CODING_OBSERVATION_INVALID", error.to_string())
    })?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(receipt)
        .map_err(|error| {
            WorkerError::input(
                "COMMAND_CODING_OBSERVATION_INVALID",
                format!("write coding observation: {error}"),
            )
        })?;
    file.write_all(&bytes).map_err(|error| {
        WorkerError::input(
            "COMMAND_CODING_OBSERVATION_INVALID",
            format!("write coding observation: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        WorkerError::input(
            "COMMAND_CODING_OBSERVATION_INVALID",
            format!("sync coding observation: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::RunnerId;
    use serde_json::json;

    fn payload(provider: &str) -> RunCodingPayload {
        RunCodingPayload::parse(
            &json!({
                "account_id": "acct-local",
                "provider": provider,
                "model": "test-model",
                "expected_revision": 1,
                "launch_nonce": "ab".repeat(32),
                "quota_reservation": format!("rsv_{}", "cd".repeat(32)),
                "quota_units": 1,
                "allocated_run": RunnerId::from_seed("coding-args").to_string(),
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn missing_harness_env_is_typed_and_does_not_name_sim() {
        let _guard = lock_env();
        clear_required_env();
        let error = coding_runner_args(&payload("cursor")).unwrap_err();
        assert_eq!(error.code(), "COMMAND_CODING_HARNESS_UNBOUND");
        assert!(!error.to_string().contains("sim"));
    }

    #[test]
    fn antigravity_is_agy_on_the_runner_flag() {
        let _guard = lock_env();
        set_required_env();
        std::env::set_var("BULLET_HARNESS_EXECUTABLE", "/usr/bin/true");
        let args = coding_runner_args(&payload("antigravity")).unwrap();
        assert!(args.windows(2).any(|pair| pair == ["--provider", "agy"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--signed-in-executable", "/usr/bin/true"]));
        assert!(!args.contains(&"--dogfood-executable".into()));
        clear_required_env();
    }

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn clear_required_env() {
        for name in [
            "BULLET_HARNESS_WORK_PACKAGE_ID",
            "BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST",
            "BULLET_HARNESS_CANDIDATE_VERIFICATION_KEY",
            "BULLET_HARNESS_WORKSPACE_ROOT",
            "BULLET_HARNESS_SOURCE_REPO",
            "BULLET_HARNESS_BASE_SHA",
            "BULLET_HARNESS_PRESERVATION",
            "BULLET_HARNESS_OBJECTIVE",
            "BULLET_HARNESS_GATE_ID",
            "BULLET_HARNESS_SCOPE",
            "BULLET_HARNESS_IDEMPOTENCY_KEY",
            "BULLET_HARNESS_LEASE_SOCKET",
            "BULLET_HARNESS_FARMD_UID",
            "BULLET_HARNESS_SOCKET_GID",
            "BULLET_HARNESS_LEASE_RECOVERY",
            "BULLET_HARNESS_EXECUTABLE",
            "BULLET_HARNESS_FARMD",
        ] {
            std::env::remove_var(name);
        }
    }

    fn set_required_env() {
        for (name, value) in [
            ("BULLET_HARNESS_WORK_PACKAGE_ID", "wpk_test"),
            ("BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST", &"a".repeat(64)),
            ("BULLET_HARNESS_CANDIDATE_VERIFICATION_KEY", "/tmp/key.json"),
            ("BULLET_HARNESS_WORKSPACE_ROOT", "/tmp/ws"),
            ("BULLET_HARNESS_SOURCE_REPO", "/tmp/src"),
            ("BULLET_HARNESS_BASE_SHA", &"b".repeat(40)),
            ("BULLET_HARNESS_PRESERVATION", "/tmp/preserve"),
            ("BULLET_HARNESS_OBJECTIVE", "edit one owned path"),
            ("BULLET_HARNESS_GATE_ID", "gat_test"),
            ("BULLET_HARNESS_SCOPE", "src"),
            ("BULLET_HARNESS_IDEMPOTENCY_KEY", "coding-test"),
            ("BULLET_HARNESS_LEASE_SOCKET", "/tmp/lease.sock"),
            ("BULLET_HARNESS_FARMD_UID", "1000"),
            ("BULLET_HARNESS_SOCKET_GID", "1000"),
            ("BULLET_HARNESS_LEASE_RECOVERY", "/tmp/recovery.json"),
        ] {
            std::env::set_var(name, value);
        }
    }
}
