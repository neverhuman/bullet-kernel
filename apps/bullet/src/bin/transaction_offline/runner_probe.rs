mod outcome;
mod preserved;

use super::chaos::{self, Boundary};
#[cfg(debug_assertions)]
use super::process_observation::observe_and_guard_runner;
use super::support::{fail, private_dir, DurableFarmd};
#[cfg(not(debug_assertions))]
use super::verifier_process::ProcessGuard;
use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    execution_toolchain_digest, CandidatePreparationSource, ExecutionEnvelopeV1, ExecutionToolV1,
};
use bullet_application::Ledger;
use bullet_domain::{AttemptState, Digest, RunnerId, WorkPackageId, REPOSITORY_GATE_ID};
use bullet_runner_core::lease::{AcquireGrant, AcquireRequest, LeaseClient, ReleaseCall};
use bullet_runner_core::{CandidatePreservation, CandidateReceipt, SignedLeaseRpcClient};
use outcome::ProductRunnerOutcome;
use preserved::inspect;
use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

const PRODUCT_RUNNER_IDEMPOTENCY: &str = "txn-demo-product-runner";

pub(super) struct RunnerExecution {
    pub(super) gate_passed: bool,
    pub(super) outcome: &'static str,
    pub(super) candidate: CandidateReceipt,
    pub(super) preservation: CandidatePreservation,
    pub(super) candidate_repository: PathBuf,
    pub(super) provider_execution: super::sim_provider::SimProviderExecution,
    pub(super) author_grant: AcquireGrant,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_product_runner(
    farmd: &DurableFarmd,
    client: &Arc<SignedLeaseRpcClient>,
    socket: &Path,
    runner: &RunnerId,
    work_package: &WorkPackageId,
    database: &Path,
    source: &Path,
    base: &str,
    scratch: &Path,
    granted_scope: &[String],
) -> Result<RunnerExecution, String> {
    let grant = client
        .acquire(&AcquireRequest {
            work_package_id: work_package.clone(),
            runner_id: runner.clone(),
            runner_epoch: 1,
            idempotency_key: PRODUCT_RUNNER_IDEMPOTENCY.into(),
            ttl_seconds: 15,
        })
        .await
        .map_err(|error| fail(format!("pre-acquire product Runner: {error}")))?;
    let work = async {
        chaos::refuse_if_selected(Boundary::GrantPersistence)?;
        let request_digest = register_candidate_source(client, &grant.attempt).await?;
        let configured = std::env::var_os("BULLET_RUNNER_BIN").map(PathBuf::from);
        let bin = if std::env::var_os("BULLET_COMMAND_CLAIM_FD").is_some() {
            configured.ok_or_else(|| fail("public command worker did not admit bullet-runner"))?
        } else if let Some(path) = configured {
            path
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/bullet-runner")
        };
        if !bin.is_file() {
            return Err(fail("bullet-runner missing (build -p bullet-runner)"));
        }
        let workspace = private_dir(&scratch.join("runner-execution"))?;
        let preserve_to = scratch.join("preserve");
        let mut command = Command::new(bin);
        command
            .arg("--lease-socket")
            .arg(socket)
            .arg("--farmd-uid")
            .arg(farmd.farmd_uid.to_string())
            .arg("--socket-gid")
            .arg(farmd.socket_gid.to_string())
            .arg("--lease-recovery")
            .arg(&farmd.recovery)
            .arg("--candidate-request-digest")
            .arg(&request_digest)
            .arg("--candidate-verification-key")
            .arg(&farmd.candidate_verification_key)
            .arg("--runner-id")
            .arg(runner.as_str())
            .arg("--work-package-id")
            .arg(work_package.as_str())
            .arg("--idempotency-key")
            .arg(PRODUCT_RUNNER_IDEMPOTENCY)
            .arg("--workspace-root")
            .arg(&workspace)
            .arg("--source-repo")
            .arg(source)
            .arg("--base-sha")
            .arg(base)
            .arg("--preservation-destination")
            .arg(&preserve_to)
            .arg("--objective")
            .arg(
                std::env::var("BULLET_TXN_OBJECTIVE")
                    .unwrap_or_else(|_| "offline-component-bridge".to_owned()),
            )
            .arg("--gate-id")
            .arg(REPOSITORY_GATE_ID);
        for path in granted_scope {
            command.arg("--scope").arg(path);
        }
        apply_provider_selection(&mut command)?;
        chaos::refuse_if_selected(Boundary::RunnerStartup)?;
        let fault = chaos::fault_for(Boundary::RunnerStartup)?;
        command
            .arg("--data-dir")
            .arg(&workspace)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0);
        let child = command
            .spawn()
            .map_err(|error| fail(format!("spawn product runner: {error}")))?;
        #[cfg(debug_assertions)]
        let child = observe_and_guard_runner(child, fault.is_some())?;
        #[cfg(not(debug_assertions))]
        let child = ProcessGuard::new(child);
        let output = if let Some(cell) = fault {
            if let Err(error) = child.signal_process_group(cell.signal()) {
                drop(child);
                return Err(fail(format!(
                    "CHAOS_FAULT_SIGNAL_FAILED: cell={} error={error}",
                    cell.label()
                )));
            }
            let outcome = child.wait_with_output_for(cell.deadline());
            return match chaos::validate_process_fault(cell, &outcome) {
                Ok(reason) | Err(reason) => Err(reason),
            };
        } else {
            child
                .wait_with_output_for(runner_supervision_ceiling())
                .map_err(|error| fail(format!("supervise product runner: {error}")))?
        };
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            return Err(fail(format!(
                "product runner did not preserve its Candidate (status {:?}): {stderr}",
                output.status.code()
            )));
        }
        let response =
            ProductRunnerOutcome::decode_and_admit(&output.stdout, &grant, base, &preserve_to)?;
        let retained = inspect(&response, &grant, &workspace, scratch)?;
        Ok(RunnerExecution {
            gate_passed: response.gate_passed,
            outcome: "CANDIDATE_PRESERVED",
            candidate: response.candidate,
            preservation: response.preservation,
            candidate_repository: retained.candidate_repository,
            provider_execution: retained.provider_execution,
            author_grant: grant.clone(),
        })
    }
    .await;
    let work = work.and_then(|execution| {
        verify_product_runner_terminal(database, &grant, AttemptState::Succeeded)?;
        Ok(execution)
    });
    match work {
        Ok(execution) => Ok(execution),
        Err(error) => match cancel_failed_runner(client, database, &grant).await {
            Ok(()) => Err(error),
            Err(cleanup) => Err(fail(format!(
                "{error}; product Runner cleanup failed: {cleanup}"
            ))),
        },
    }
}

async fn cancel_failed_runner(
    client: &Arc<SignedLeaseRpcClient>,
    database: &Path,
    grant: &AcquireGrant,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Cancelled,
            requeue: true,
        })
        .await
    {
        errors.push(format!("cancel failed product Runner lease: {error}"));
    }
    if let Err(error) = verify_product_runner_terminal(database, grant, AttemptState::Cancelled) {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(fail(errors.join("; ")))
    }
}

fn verify_product_runner_terminal(
    database: &Path,
    grant: &AcquireGrant,
    expected: AttemptState,
) -> Result<(), String> {
    let ledger = SqliteLedger::open(database)
        .map_err(|error| fail(format!("reopen product Runner ledger: {error}")))?;
    if ledger
        .get_lease(&grant.lease.variant_id)
        .map_err(|error| fail(format!("read product Runner active lease: {error}")))?
        .is_some()
    {
        return Err(fail("product Runner lease remained active"));
    }
    let attempt = ledger
        .get_attempt(&grant.attempt.id)
        .map_err(|error| fail(format!("read product Runner Attempt: {error}")))?
        .ok_or_else(|| fail("product Runner Attempt disappeared"))?;
    if attempt.state != expected {
        return Err(fail(format!(
            "product Runner Attempt ended as {:?}, expected {expected:?}",
            attempt.state,
        )));
    }
    Ok(())
}

pub(super) async fn register_candidate_source(
    client: &SignedLeaseRpcClient,
    attempt: &bullet_domain::Attempt,
) -> Result<String, String> {
    let authority = client
        .candidate_preparation_authority(&attempt.id)
        .await
        .map_err(|error| fail(format!("read Candidate source authority: {error}")))?;
    let git_path = fs::canonicalize("/usr/bin/git")
        .map_err(|error| fail(format!("canonicalize admitted Git: {error}")))?;
    let git_bytes =
        fs::read(&git_path).map_err(|error| fail(format!("read admitted Git: {error}")))?;
    let git_version = Command::new(&git_path)
        .arg("--version")
        .output()
        .map_err(|error| fail(format!("inspect admitted Git: {error}")))?;
    if !git_version.status.success() {
        return Err(fail("admitted Git version probe failed"));
    }
    let version = String::from_utf8(git_version.stdout)
        .map_err(|_| fail("admitted Git version is not UTF-8"))?
        .trim()
        .to_owned();
    let executable_digest = Digest::of(&git_bytes).to_hex();
    let descriptor_digest =
        Digest::of(format!("{}\0{version}\0{executable_digest}", git_path.display()).as_bytes())
            .to_hex();
    let tools = vec![ExecutionToolV1 {
        schema_version: "v1alpha1".into(),
        tool_id: typed_id("etl", "offline-product-runner-git"),
        role: "git".into(),
        executable_path: git_path.display().to_string(),
        executable_digest,
        descriptor_digest,
        version,
    }];
    let now_unix_ms = authority.now_unix_ms();
    let execution_identity = ExecutionIdentity::observed();
    // The lease expiry is one 15 s TTL, renewed by heartbeat for the life of
    // the attempt. Pinning the envelope to that first TTL was invisible with
    // the simulator, which answers in milliseconds; a real turn takes over two
    // minutes, so the envelope expired mid-attempt and Candidate preparation
    // refused work that had already been done and gated. The envelope covers
    // the attempt the bridge is actually willing to supervise.
    let expires_at_unix_ms = authority
        .lease_expires_at_unix_ms()
        .max(now_unix_ms.saturating_add(
            u64::try_from(runner_supervision_ceiling().as_millis()).unwrap_or(u64::MAX),
        ));
    let source = CandidatePreparationSource {
        schema_version: "v1alpha1".into(),
        attempt_id: attempt.id.clone(),
        root_change: true,
        change_id: typed_id("chg", attempt.id.as_str()),
        parent_candidate_ids: Vec::new(),
        execution_envelope: ExecutionEnvelopeV1 {
            schema_version: "v1alpha1".into(),
            execution_envelope_id: typed_id("exe", "offline-product-runner-execution"),
            issuer: "bullet-kernel".into(),
            key_id: "execution-component-1".into(),
            signing_purpose: "execution-envelope-signing".into(),
            claims_domain: "execution.envelope.v1alpha1".into(),
            runner_id: attempt.runner_id.to_string(),
            runner_epoch: attempt.runner_epoch,
            provider: execution_identity.provider,
            model: execution_identity.model,
            adapter: execution_identity.adapter,
            provider_profile_id: typed_id("prf", &execution_identity.profile_seed),
            platform: "linux-x86_64".into(),
            containment_profile_id: typed_id("ctp", "offline-same-host-component"),
            environment_digest: Digest::of(b"offline-product-runner-environment-v1").to_hex(),
            toolchain_digest: execution_toolchain_digest(&tools)
                .map_err(|error| fail(format!("Candidate toolchain digest: {error}")))?,
            sandbox_image_digest: Digest::of(b"offline-component-no-image").to_hex(),
            tools,
            authority_epoch: authority.authority_epoch(),
            freeze_generation: authority.freeze_generation(),
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
        },
        ttl_ms: 15_000,
    };
    let request_digest = source
        .request_digest()
        .map_err(|error| fail(format!("Candidate source digest: {error}")))?;
    let registered = client
        .register_candidate_preparation_source(&source)
        .await
        .map_err(|error| fail(format!("register Candidate source: {error}")))?;
    if registered != request_digest {
        return Err(fail("registered Candidate source digest drifted"));
    }
    Ok(request_digest)
}

fn typed_id(prefix: &str, label: &str) -> String {
    format!("{prefix}_{}", Digest::of(label.as_bytes()).to_hex())
}

/// Select the provider the bridge drives.
///
/// The bridge defaults to `sim` so the offline component proof stays
/// deterministic and needs no account, no network and no spend. That default
/// is also the reason every Candidate this bridge has ever produced came from
/// a canned proposal, which is worth stating plainly rather than hiding
/// behind the word "offline".
///
/// Setting `BULLET_TXN_PROVIDER=claude` drives a REAL contained provider turn
/// instead. Every dogfood admission input must then be supplied by
/// environment; a missing one refuses here rather than letting the runner
/// start and discover it later. There is no partial mode and no fallback: if
/// the real provider cannot be admitted, the bridge does not quietly run the
/// simulator and call the result a Candidate.
fn apply_provider_selection(command: &mut Command) -> Result<(), String> {
    let provider = std::env::var("BULLET_TXN_PROVIDER").unwrap_or_else(|_| "sim".to_owned());
    if provider == "sim" {
        return Ok(());
    }
    if provider != "claude" {
        return Err(fail(format!(
            "BULLET_TXN_PROVIDER={provider} is not a provider this bridge can drive"
        )));
    }
    command.arg("--provider").arg("claude");
    for (variable, flag) in [
        ("BULLET_DOGFOOD_DATA_DIR", "--dogfood-data-dir"),
        ("BULLET_DOGFOOD_POLICY", "--dogfood-policy"),
        ("BULLET_DOGFOOD_BINDING", "--dogfood-binding"),
        ("BULLET_DOGFOOD_ENROLLMENT", "--dogfood-enrollment"),
        ("BULLET_DOGFOOD_ISSUER", "--dogfood-issuer"),
        ("BULLET_DOGFOOD_KEY_ID", "--dogfood-key-id"),
        ("BULLET_DOGFOOD_EXECUTABLE", "--dogfood-executable"),
        ("BULLET_DOGFOOD_RECEIPT", "--dogfood-receipt"),
        ("BULLET_DOGFOOD_MAX_BUDGET_USD", "--dogfood-max-budget-usd"),
    ] {
        let value = std::env::var(variable).map_err(|_| {
            fail(format!(
                "{variable} is required when BULLET_TXN_PROVIDER=claude ({flag})"
            ))
        })?;
        command.arg(flag).arg(value);
    }
    if let Ok(seconds) = std::env::var("BULLET_DOGFOOD_WALL_TIMEOUT_SECS") {
        command.arg("--dogfood-wall-timeout-secs").arg(seconds);
    }
    // Without a credential grant the contained provider starts, reports
    // "Not logged in", and exits after a wasted spawn. At least one grant is
    // therefore required rather than optional.
    let credentials = std::env::var("BULLET_DOGFOOD_CREDENTIALS").map_err(|_| {
        fail(
            "BULLET_DOGFOOD_CREDENTIALS is required when BULLET_TXN_PROVIDER=claude \
             (semicolon-separated source,target,blake3 grants)",
        )
    })?;
    let mut granted = 0usize;
    for grant in credentials.split(';').filter(|value| !value.is_empty()) {
        command.arg("--dogfood-credential").arg(grant);
        granted += 1;
    }
    if granted == 0 {
        return Err(fail(
            "BULLET_DOGFOOD_CREDENTIALS named no grant, so the provider would start unauthenticated",
        ));
    }
    Ok(())
}

/// How long the bridge waits for the product Runner to finish.
///
/// The default 30 s is sized for the simulator, which answers instantly. A
/// real contained provider turn takes roughly a minute, so under
/// `BULLET_TXN_PROVIDER=claude` the bridge was killing the Runner mid-turn and
/// reporting a timeout that looked like a Runner defect. The ceiling now
/// follows the turn ceiling the operator actually stated, plus slack for
/// clone, gate and preservation work on either side of the turn.
fn runner_supervision_ceiling() -> std::time::Duration {
    const SIMULATOR_CEILING: std::time::Duration = std::time::Duration::from_secs(30);
    const SURROUNDING_WORK: u64 = 120;
    if std::env::var("BULLET_TXN_PROVIDER")
        .as_deref()
        .unwrap_or("sim")
        == "sim"
    {
        return SIMULATOR_CEILING;
    }
    let turn = std::env::var("BULLET_DOGFOOD_WALL_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(600);
    std::time::Duration::from_secs(turn.saturating_add(SURROUNDING_WORK))
}

/// What actually executes the attempt, as recorded in the Candidate's
/// execution envelope.
///
/// This was hard-coded to `simulator` / `deterministic` / `simulator-v1`. With
/// the simulator that was true. Under a real provider it would have stamped a
/// Candidate produced by a real model with an envelope claiming a simulator
/// made it, which is the exact confusion the envelope exists to prevent.
struct ExecutionIdentity {
    provider: String,
    model: String,
    adapter: String,
    profile_seed: String,
}

impl ExecutionIdentity {
    fn observed() -> Self {
        let provider = std::env::var("BULLET_TXN_PROVIDER").unwrap_or_else(|_| "sim".to_owned());
        if provider == "sim" {
            return Self {
                provider: "simulator".into(),
                model: "deterministic".into(),
                adapter: "simulator-v1".into(),
                profile_seed: "offline-simulator-profile".into(),
            };
        }
        // The envelope is registered before the turn, so the exact model id is
        // not yet knowable: the provider selects it. Recording the enrolled
        // runtime is the honest, checkable fact available at this point.
        let runtime = std::env::var("BULLET_DOGFOOD_EXECUTABLE")
            .ok()
            .and_then(|path| {
                std::path::Path::new(&path)
                    .parent()
                    .and_then(std::path::Path::parent)
                    .and_then(std::path::Path::file_name)
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "unknown-runtime".to_owned());
        Self {
            model: std::env::var("BULLET_TXN_MODEL")
                .unwrap_or_else(|_| format!("provider-selected@{runtime}")),
            adapter: format!("dogfood-{provider}-v1"),
            profile_seed: format!("dogfood-{provider}-profile"),
            provider,
        }
    }
}
