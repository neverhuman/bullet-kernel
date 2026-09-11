//! Native `run_coding` argv and labeled observation — never a simulator.

use super::{need_env, ChildOutput, WorkerContext, WorkerError};
use bullet_application::coding_tasks::{task_payload, RunCodingTaskPayload};
use bullet_application::{CommandDispatchClaim, RunCodingPayload, RUN_CODING_KIND};
use bullet_domain::WorkPackageId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(super) const WORK_PACKAGE_SEED: &str = "bullet.coding-work-package.v1";

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

#[derive(Debug)]
pub(super) struct CodingLaunch {
    pub(super) provider: String,
    pub(super) model: String,
    pub(super) allocated_run: String,
    work_package_id: String,
    candidate_request_digest: String,
    idempotency_key: String,
    objective: String,
    gate_ids: Vec<String>,
    scopes: Vec<String>,
    base_sha: String,
}

impl CodingLaunch {
    pub(super) fn from_claim(claim: &CommandDispatchClaim) -> Result<Self, WorkerError> {
        if let Some(payload) = task_payload(&claim.request).map_err(|error| {
            WorkerError::input("COMMAND_CODING_PAYLOAD_INVALID", error.to_string())
        })? {
            return Self::from_task(claim, &payload);
        }
        let payload = RunCodingPayload::parse(&claim.request.payload).map_err(|error| {
            WorkerError::input("COMMAND_CODING_PAYLOAD_INVALID", error.to_string())
        })?;
        Self::from_legacy(&payload)
    }

    fn from_task(
        claim: &CommandDispatchClaim,
        payload: &RunCodingTaskPayload,
    ) -> Result<Self, WorkerError> {
        if payload.task.gate_ids.is_empty() || payload.task.scope_paths.is_empty() {
            return Err(WorkerError::input(
                "COMMAND_CODING_PAYLOAD_INVALID",
                "task intent requires at least one gate and one scope path",
            ));
        }
        let seed = format!("{WORK_PACKAGE_SEED}\0{}", claim.command_id);
        Ok(Self {
            provider: payload.selection.provider.as_str().into(),
            model: payload.selection.model.clone(),
            allocated_run: claim.runner_id.to_string(),
            work_package_id: WorkPackageId::from_seed(&seed).to_string(),
            candidate_request_digest: claim.request.digest().to_hex(),
            idempotency_key: bullet_application::coding_tasks::coding_lease_key(&claim.request)
                .worker("COMMAND_CODING_PAYLOAD_INVALID", "derive lease identity")?,
            objective: payload.task.objective.clone(),
            gate_ids: payload.task.gate_ids.clone(),
            scopes: payload.task.scope_paths.clone(),
            base_sha: payload.task.base_commit.clone(),
        })
    }

    fn from_legacy(payload: &RunCodingPayload) -> Result<Self, WorkerError> {
        Ok(Self {
            provider: payload.provider.as_str().into(),
            model: payload.model.clone(),
            allocated_run: payload.allocated_run.clone(),
            work_package_id: produced_env("BULLET_HARNESS_WORK_PACKAGE_ID")?,
            candidate_request_digest: produced_env("BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST")?,
            idempotency_key: produced_env("BULLET_HARNESS_IDEMPOTENCY_KEY")?,
            objective: produced_env("BULLET_HARNESS_OBJECTIVE")?,
            gate_ids: vec![produced_env("BULLET_HARNESS_GATE_ID")?],
            scopes: vec![produced_env("BULLET_HARNESS_SCOPE")?],
            base_sha: produced_env("BULLET_HARNESS_BASE_SHA")?,
        })
    }
}

pub(super) fn coding_runner_args(launch: &CodingLaunch) -> Result<Vec<String>, WorkerError> {
    let provider = match launch.provider.as_str() {
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
        provider,
        "--model".into(),
        launch.model.clone(),
        "--runner-id".into(),
        launch.allocated_run.clone(),
        "--work-package-id".into(),
        launch.work_package_id.clone(),
        "--candidate-request-digest".into(),
        launch.candidate_request_digest.clone(),
        "--candidate-verification-key".into(),
        need_env("BULLET_HARNESS_CANDIDATE_VERIFICATION_KEY")?,
        "--workspace-root".into(),
        need_env("BULLET_HARNESS_WORKSPACE_ROOT")?,
        "--source-repo".into(),
        need_env("BULLET_HARNESS_SOURCE_REPO")?,
        "--base-sha".into(),
        launch.base_sha.clone(),
        "--preservation-destination".into(),
        need_env("BULLET_HARNESS_PRESERVATION")?,
        "--objective".into(),
        launch.objective.clone(),
        "--idempotency-key".into(),
        launch.idempotency_key.clone(),
        "--lease-socket".into(),
        need_env("BULLET_HARNESS_LEASE_SOCKET")?,
        "--farmd-uid".into(),
        need_env("BULLET_HARNESS_FARMD_UID")?,
        "--socket-gid".into(),
        need_env("BULLET_HARNESS_SOCKET_GID")?,
        "--lease-recovery".into(),
        need_env("BULLET_HARNESS_LEASE_RECOVERY")?,
    ];
    for gate in &launch.gate_ids {
        args.extend(["--gate-id".into(), gate.clone()]);
    }
    for scope in &launch.scopes {
        args.extend(["--scope".into(), scope.clone()]);
    }
    if let Ok(farmd) = std::env::var("BULLET_HARNESS_FARMD") {
        args.extend(["--farmd".into(), farmd]);
    }
    if launch.provider == "claude" {
        args.extend(claude_dogfood_args()?);
        args.extend(dogfood_credential_args()?);
    } else {
        args.extend([
            "--signed-in-executable".into(),
            need_env("BULLET_HARNESS_EXECUTABLE")?,
        ]);
    }
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

fn produced_env(name: &str) -> Result<String, WorkerError> {
    let value = need_env(name)?;
    if value.starts_with("PLACEHOLDER_DRY_RUN_ONLY:") {
        return Err(WorkerError::input(
            "COMMAND_CODING_HARNESS_UNBOUND",
            format!("{name} is a dry-run placeholder, not a ledger producer"),
        ));
    }
    Ok(value)
}

fn dogfood_credential_args() -> Result<Vec<String>, WorkerError> {
    let Ok(raw) = std::env::var("BULLET_HARNESS_DOGFOOD_CREDENTIALS") else {
        return Ok(Vec::new());
    };
    let grants = raw.strip_prefix("NOT_CONSUMED_BY_WORKER:").unwrap_or(&raw);
    let mut args = Vec::new();
    for (index, grant) in grants
        .split(';')
        .filter(|part| !part.is_empty())
        .enumerate()
    {
        let parts: Vec<&str> = grant.splitn(3, ',').collect();
        if parts.len() != 3
            || parts[0].is_empty()
            || parts[1].is_empty()
            || parts[2].len() != 64
            || !parts[2]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WorkerError::input(
                "COMMAND_CODING_CREDENTIAL_INVALID",
                format!(
                    "dogfood credential grant {} is not source,target,blake3",
                    index + 1
                ),
            ));
        }
        args.extend(["--dogfood-credential".into(), grant.to_string()]);
    }
    Ok(args)
}

pub(super) fn write_coding_observation(
    receipt: &Path,
    command_id: &str,
    launch: &CodingLaunch,
    output: &ChildOutput,
) -> Result<(), WorkerError> {
    let observation = CodingObservation {
        schema_version: CODING_OBSERVATION_SCHEMA.into(),
        evidence_class: CODING_EVIDENCE_CLASS.into(),
        transaction_gate_eligible: false,
        independent_evidence_eligible: false,
        command_id: command_id.into(),
        kind: RUN_CODING_KIND.into(),
        provider: launch.provider.clone(),
        model: launch.model.clone(),
        allocated_run: launch.allocated_run.clone(),
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
        let error = CodingLaunch::from_legacy(&payload("cursor")).unwrap_err();
        assert_eq!(error.code(), "COMMAND_CODING_HARNESS_UNBOUND");
        assert!(!error.to_string().contains("sim"));
    }

    #[test]
    fn antigravity_is_agy_on_the_runner_flag() {
        let _guard = lock_env();
        set_required_env();
        std::env::set_var("BULLET_HARNESS_EXECUTABLE", "/usr/bin/true");
        let args = coding_runner_args(&CodingLaunch::from_legacy(&payload("antigravity")).unwrap())
            .unwrap();
        assert!(args.windows(2).any(|pair| pair == ["--provider", "agy"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--signed-in-executable", "/usr/bin/true"]));
        assert!(!args.contains(&"--dogfood-executable".into()));
        clear_required_env();
    }

    #[test]
    fn v2_task_uses_ledger_producers_and_forwards_credentials_without_naming_them() {
        let _guard = lock_env();
        clear_required_env();
        set_workspace_env();
        std::env::set_var("BULLET_HARNESS_EXECUTABLE", "/usr/bin/true");
        let digest = "ab".repeat(32);
        std::env::set_var(
            "BULLET_HARNESS_DOGFOOD_CREDENTIALS",
            format!("/tmp/claude.cred,.claude/cred,{digest}"),
        );
        set_claude_dogfood_env();
        let request = bullet_application::CommandRequest::new(
            "v2-harness",
            "run_coding",
            &json!({
                "schema_version":"bullet.run-coding.v2",
                "task": {"title":"Bound task","objective":"ledger producers",
                    "repository_id":format!("rep_{}","ab".repeat(32)), "base_commit":"ab".repeat(20),
                    "scope_paths":["src/lib.rs"], "acceptance_criteria":["one"],
                    "gate_ids":[format!("gat_{}","cd".repeat(32))], "dependencies":[],
                    "budget":{"max_invocations":1,"max_cost_microusd":1000}, "deadline_unix_ms":4_102_444_800_000u64},
                "selection":{"account_id":"fixture-account","provider":"claude","model":"fixture-model","effort":null}
            }),
        )
        .unwrap();
        let claim = CommandDispatchClaim {
            schema_version: "bullet.command-dispatch-claim.v1".into(),
            claim_id: format!("dcl_{}", bullet_domain::Digest::of(b"v2-harness").to_hex()),
            command_id: request.id(),
            outbox_sequence: 1,
            request_digest: request.digest(),
            request: request.clone(),
            runner_id: RunnerId::from_seed("v2-worker"),
            runner_epoch: 1,
            authority_epoch: 1,
            freeze_generation: 0,
            restore_epoch: 0,
            disposition: bullet_application::CommandDispatchDisposition::Claimed,
            completion_digest: None,
            claimed_at: "2026-09-11T00:00:00.000Z".into(),
            updated_at: "2026-09-11T00:00:00.000Z".into(),
        };
        let launch = CodingLaunch::from_claim(&claim).unwrap();
        let args = coding_runner_args(&launch).unwrap();
        let package = WorkPackageId::from_seed(&format!("{WORK_PACKAGE_SEED}\0{}", request.id()));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--work-package-id", package.as_str()]));
        assert!(args.windows(2).any(|pair| {
            pair[0] == "--candidate-request-digest" && pair[1] == request.digest().to_hex()
        }));
        let key = bullet_application::coding_tasks::coding_lease_key(&request).unwrap();
        assert_ne!(key, request.idempotency_key);
        let lease_arg = ["--idempotency-key", key.as_str()];
        assert!(args.windows(2).any(|pair| pair == lease_arg));
        assert!(args.iter().any(|arg| arg == "--dogfood-credential"));
        let bad = dogfood_credential_args_error();
        assert_eq!(bad.code(), "COMMAND_CODING_CREDENTIAL_INVALID");
        assert!(!bad.to_string().contains(&digest));
        clear_required_env();
        std::env::remove_var("BULLET_HARNESS_DOGFOOD_CREDENTIALS");
        clear_claude_dogfood_env();
    }

    fn dogfood_credential_args_error() -> WorkerError {
        std::env::set_var("BULLET_HARNESS_DOGFOOD_CREDENTIALS", "not-a-grant");
        dogfood_credential_args().unwrap_err()
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

    fn set_workspace_env() {
        for (name, value) in [
            ("BULLET_HARNESS_CANDIDATE_VERIFICATION_KEY", "/tmp/key.json"),
            ("BULLET_HARNESS_WORKSPACE_ROOT", "/tmp/ws"),
            ("BULLET_HARNESS_SOURCE_REPO", "/tmp/src"),
            ("BULLET_HARNESS_PRESERVATION", "/tmp/preserve"),
            ("BULLET_HARNESS_LEASE_SOCKET", "/tmp/lease.sock"),
            ("BULLET_HARNESS_FARMD_UID", "1000"),
            ("BULLET_HARNESS_SOCKET_GID", "1000"),
            ("BULLET_HARNESS_LEASE_RECOVERY", "/tmp/recovery.json"),
        ] {
            std::env::set_var(name, value);
        }
    }

    fn set_claude_dogfood_env() {
        for (name, value) in [
            ("BULLET_HARNESS_DOGFOOD_DATA_DIR", "/tmp/dogfood"),
            ("BULLET_HARNESS_DOGFOOD_POLICY", "/tmp/policy.json"),
            ("BULLET_HARNESS_DOGFOOD_BINDING", "/tmp/binding.json"),
            ("BULLET_HARNESS_DOGFOOD_ENROLLMENT", "/tmp/enroll.json"),
            ("BULLET_HARNESS_DOGFOOD_ISSUER", "dogfood-local"),
            ("BULLET_HARNESS_DOGFOOD_KEY_ID", "dogfood-runner-1"),
            ("BULLET_HARNESS_DOGFOOD_RECEIPT", "/tmp/receipt.json"),
            ("BULLET_HARNESS_DOGFOOD_MAX_BUDGET_USD", "0.75"),
        ] {
            std::env::set_var(name, value);
        }
    }

    fn clear_claude_dogfood_env() {
        for name in [
            "BULLET_HARNESS_DOGFOOD_DATA_DIR",
            "BULLET_HARNESS_DOGFOOD_POLICY",
            "BULLET_HARNESS_DOGFOOD_BINDING",
            "BULLET_HARNESS_DOGFOOD_ENROLLMENT",
            "BULLET_HARNESS_DOGFOOD_ISSUER",
            "BULLET_HARNESS_DOGFOOD_KEY_ID",
            "BULLET_HARNESS_DOGFOOD_RECEIPT",
            "BULLET_HARNESS_DOGFOOD_MAX_BUDGET_USD",
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
