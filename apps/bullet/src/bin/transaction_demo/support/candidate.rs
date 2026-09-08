//! Test-only custody and real Candidate-grant consumers for the component demo.
//! The Gitd MAC fixture and self-signed receipt remain ineligible for admission.

use super::{fail, kernel_bin, FarmdGuard};
use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    execution_toolchain_digest, CandidatePreparationSource, ExecutionEnvelopeV1, ExecutionToolV1,
};
use bullet_application::{AuthorityScopeStore, Ledger, AUTHORITY_SCOPE_ENVELOPE_CLASS};
use bullet_domain::{schema_bundle::ScopeGrantV1, Digest, RunnerId};
use bullet_harness_core::candidate_preparation::{
    authenticate_candidate_preparation_grant, candidate_preparation_scope_paths_digest,
    validate_candidate_preparation_binding, CandidatePreparationSigningKey,
    CandidatePreparationVerificationKey,
};
use bullet_harness_core::lease_transport::LeaseTransportSigningKey;
use bullet_runner_core::gitd::CheckpointBinding;
use bullet_runner_core::{
    AcquireGrant, CandidatePreparationRpcClient, CandidateProvenanceRequest, ChangeRequest,
    PrepareCandidateRequest, SignedLeaseRpcClient, WorkspaceInfo,
};
use serde_json::json;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

const SCOPE: [&str; 1] = ["src"];

pub(in crate::transaction_demo) struct FixtureFarmd {
    guard: FarmdGuard,
    verification_key: CandidatePreparationVerificationKey,
}

impl FixtureFarmd {
    pub(in crate::transaction_demo) fn stop(self) -> Result<(), String> {
        self.guard.stop()
    }
}

pub(in crate::transaction_demo) fn admit_fixture_scope(
    ledger: &mut SqliteLedger,
    now: &str,
) -> Result<(), String> {
    let current = ledger
        .current_authority()
        .map_err(|error| fail(error.to_string()))?;
    let scope = ScopeGrantV1 {
        schema_version: "v1alpha1".into(),
        scope_grant_id: typed_id("sgr", "transaction-demo-component-scope"),
        scope_revision: 1,
        normalized_paths: SCOPE.map(str::to_owned).to_vec(),
        protected_resources: Vec::new(),
        envelope_class: AUTHORITY_SCOPE_ENVELOPE_CLASS.into(),
    };
    ledger
        .admit_scope_grant(
            &scope,
            current.authority_epoch(),
            "transaction-demo-scope",
            now,
        )
        .map_err(|error| fail(format!("admit component scope: {error}")))?;
    Ok(())
}

pub(in crate::transaction_demo) fn spawn_farmd(
    data: &Path,
    socket: &Path,
    runner: &RunnerId,
    runner_epoch: u64,
) -> Result<FixtureFarmd, String> {
    let bin = kernel_bin("bullet-farmd");
    if !bin.is_file() {
        return Err(fail(format!(
            "bullet-farmd missing at {} (build -p bullet-farmd)",
            bin.display()
        )));
    }
    let custody = data.join("candidate-fixture-custody");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&custody)
        .map_err(|error| fail(format!("create new Candidate fixture custody: {error}")))?;
    let key_path = custody.join("signing.key");
    let registry_path = custody.join("peer-registry.json");
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1")
        .map_err(|error| fail(error.to_string()))?;
    let candidate_key = CandidatePreparationSigningKey::from_bytes(
        "kernel-local",
        "candidate-preparation-1",
        key.secret_bytes(),
    )
    .map_err(|error| fail(format!("derive fixture Candidate key: {error}")))?;
    let verification_key = candidate_key
        .verification_key()
        .map_err(|error| fail(format!("derive fixture Candidate public key: {error}")))?;
    write_private_file(&key_path, key.secret_bytes())?;
    let process = fs::metadata("/proc/self")
        .map_err(|error| fail(format!("inspect fixture service identity: {error}")))?;
    let registry = json!({
        "farmd_uid": process.uid(), "socket_gid": process.gid(),
        "runners": [{"runner_id": runner.to_string(), "runner_epoch": runner_epoch,
            "service_uid": process.uid()}],
    });
    write_private_file(
        &registry_path,
        &serde_json::to_vec(&registry)
            .map_err(|error| fail(format!("encode fixture peer registry: {error}")))?,
    )?;
    fs::File::open(data)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| fail(format!("sync fixture custody parent: {error}")))?;
    let child = Command::new(bin)
        .arg("--data-dir")
        .arg(data)
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--lease-transport-socket")
        .arg(socket)
        .arg("--lease-peer-registry")
        .arg(&registry_path)
        .arg("--lease-transport-key")
        .arg(&key_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| fail(format!("spawn farmd: {error}")))?;
    Ok(FixtureFarmd {
        guard: FarmdGuard::new(child),
        verification_key,
    })
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| fail(format!("create fixture file {}: {error}", path.display())))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| fail(format!("sync fixture file {}: {error}", path.display())))?;
    fs::File::open(
        path.parent()
            .ok_or_else(|| fail("fixture file has no parent"))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| fail(format!("sync fixture file parent: {error}")))
}

pub(in crate::transaction_demo) async fn prepare_candidate_request(
    farmd: &FixtureFarmd,
    client: &SignedLeaseRpcClient,
    grant: &AcquireGrant,
    workspace: &WorkspaceInfo,
    checkpoint: &CheckpointBinding,
) -> Result<PrepareCandidateRequest, String> {
    let source = candidate_source(client, grant).await?;
    let request_digest = source
        .request_digest()
        .map_err(|error| fail(format!("Candidate source digest: {error}")))?;
    let registered = client
        .register_candidate_preparation_source(&source)
        .await
        .map_err(|error| fail(format!("register Candidate source: {error}")))?;
    if registered != request_digest {
        return Err(fail("registered Candidate source digest differs"));
    }
    let response = client
        .candidate_prepare(&grant.attempt.id, &request_digest)
        .await
        .map_err(|error| fail(format!("prepare Candidate grant: {error}")))?;
    client
        .candidate_readback(&response)
        .await
        .map_err(|error| fail(format!("read back Candidate grant: {error}")))?;
    let claims =
        authenticate_candidate_preparation_grant(response.signed_grant(), &farmd.verification_key)
            .map_err(|error| fail(format!("authenticate Candidate grant: {error}")))?;
    validate_candidate_preparation_binding(&claims, &source.execution_envelope)
        .map_err(|error| fail(format!("bind Candidate execution: {error}")))?;
    let token = &grant.authority_token;
    let mut expected = claims.clone();
    expected.request_digest = request_digest;
    expected.candidate_preparation_grant_id = response.candidate_preparation_grant_id().to_owned();
    expected.authority_token_digest = token
        .digest()
        .map_err(|error| fail(error.to_string()))?
        .to_hex();
    expected.repository_id = token.repository_id.to_string();
    expected.mission_id = token.mission_id.to_string();
    expected.plan_revision_id = token.plan_revision_id.to_string();
    expected.work_package_id = token.work_package_id.to_string();
    expected.variant_id = token.variant_id.to_string();
    expected.attempt_id = token.attempt_id.to_string();
    expected.attempt_fence = token.attempt_fence;
    expected.runner_id = token.runner_id.to_string();
    expected.runner_epoch = token.runner_epoch;
    expected.workspace_id = token.workspace_id.to_string();
    expected.scope_revision = token.scope_revision;
    expected.context_revision = token.context_revision;
    expected.scope_grant_digest =
        candidate_preparation_scope_paths_digest(&SCOPE.map(str::to_owned))
            .map_err(|error| fail(format!("Candidate scope digest: {error}")))?;
    expected.change_id = source.change_id;
    expected.parent_candidate_ids = source.parent_candidate_ids;
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| fail("Candidate fixture clock precedes epoch"))?;
    if claims != expected || now < claims.not_before_unix_ms || now >= claims.expires_at_unix_ms {
        return Err(fail(
            "Candidate grant differs from current fixture subject or time",
        ));
    }
    let acceptance_root = token
        .acceptance_contract_id
        .as_str()
        .strip_prefix("acc_")
        .ok_or_else(|| fail("acceptance contract prefix"))?
        .to_owned();
    Ok(PrepareCandidateRequest {
        change: ChangeRequest {
            id: claims.change_id,
            mission: claims.mission_id,
            acceptance_root,
        },
        provenance: CandidateProvenanceRequest {
            schema_version: 1,
            repository_id: claims.repository_id,
            producing_attempt_id: claims.attempt_id,
            attempt_fence: claims.attempt_fence,
            work_package_id: claims.work_package_id,
            variant_id: claims.variant_id,
            plan_revision_id: claims.plan_revision_id,
            graph_revision_id: claims.graph_revision_id,
            base_checkpoint_id: checkpoint.id.clone(),
            base_commit: workspace.base_sha.clone(),
            parent_candidate_ids: claims.parent_candidate_ids,
            granted_scope: SCOPE.map(str::to_owned).to_vec(),
            context_capsule_id: claims.context_capsule_id,
            configuration_snapshot_id: format!("cnt_{}", token.config_snapshot_hash.to_hex()),
            policy_snapshot_id: format!("cnt_{}", token.policy_snapshot_hash.to_hex()),
            routing_snapshot_id: format!("cnt_{}", token.routing_policy_hash.to_hex()),
            environment_digest: claims.environment_digest,
            toolchain_digest: claims.toolchain_digest,
        },
        candidate_preparation_grant: response.signed_grant().clone(),
    })
}

async fn candidate_source(
    client: &SignedLeaseRpcClient,
    grant: &AcquireGrant,
) -> Result<CandidatePreparationSource, String> {
    let attempt = &grant.attempt;
    let authority = client
        .candidate_preparation_authority(&attempt.id)
        .await
        .map_err(|error| fail(format!("read Candidate source authority: {error}")))?;
    let git_path = fs::canonicalize("/usr/bin/git")
        .map_err(|error| fail(format!("canonicalize fixture Git: {error}")))?;
    let bytes = fs::read(&git_path).map_err(|error| fail(format!("read fixture Git: {error}")))?;
    let version = Command::new(&git_path)
        .arg("--version")
        .output()
        .map_err(|error| fail(format!("probe fixture Git: {error}")))?;
    if !version.status.success() {
        return Err(fail("fixture Git version probe failed"));
    }
    let version = String::from_utf8(version.stdout)
        .map_err(|_| fail("fixture Git version not UTF-8"))?
        .trim()
        .to_owned();
    let executable_digest = Digest::of(&bytes).to_hex();
    let descriptor_digest =
        Digest::of(format!("{}\0{version}\0{executable_digest}", git_path.display()).as_bytes())
            .to_hex();
    let tools = vec![ExecutionToolV1 {
        schema_version: "v1alpha1".into(),
        tool_id: typed_id("etl", "demo-fixture-git"),
        role: "git".into(),
        executable_path: git_path.display().to_string(),
        executable_digest,
        descriptor_digest,
        version,
    }];
    Ok(CandidatePreparationSource {
        schema_version: "v1alpha1".into(),
        attempt_id: attempt.id.clone(),
        root_change: true,
        change_id: typed_id("chg", attempt.id.as_str()),
        parent_candidate_ids: Vec::new(),
        execution_envelope: ExecutionEnvelopeV1 {
            schema_version: "v1alpha1".into(),
            execution_envelope_id: typed_id("exe", "transaction-demo-fixture"),
            issuer: "bullet-kernel".into(),
            key_id: "execution-component-1".into(),
            signing_purpose: "execution-envelope-signing".into(),
            claims_domain: "execution.envelope.v1alpha1".into(),
            runner_id: attempt.runner_id.to_string(),
            runner_epoch: attempt.runner_epoch,
            provider: "simulator".into(),
            model: "deterministic".into(),
            adapter: "simulator-v1".into(),
            provider_profile_id: typed_id("prf", "transaction-demo-fixture"),
            platform: "linux-x86_64".into(),
            containment_profile_id: typed_id("ctp", "same-host-component-fixture"),
            environment_digest: Digest::of(b"transaction-demo-fixture-environment").to_hex(),
            toolchain_digest: execution_toolchain_digest(&tools)
                .map_err(|error| fail(error.to_string()))?,
            sandbox_image_digest: Digest::of(b"component-fixture-no-image").to_hex(),
            tools,
            authority_epoch: authority.authority_epoch(),
            freeze_generation: authority.freeze_generation(),
            issued_at_unix_ms: authority.now_unix_ms(),
            expires_at_unix_ms: authority.lease_expires_at_unix_ms(),
        },
        ttl_ms: 15_000,
    })
}

fn typed_id(prefix: &str, label: &str) -> String {
    format!("{prefix}_{}", Digest::of(label.as_bytes()).to_hex())
}
