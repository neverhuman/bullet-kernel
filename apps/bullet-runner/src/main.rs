//! Attempt runner CLI (ADR 0001): replays a Kernel-selected work-package lease,
//! spawns bullet-gitd for the private clone, drives a read-only provider
//! session, applies scope-checked PatchProposals through the daemon, runs
//! the deterministic gate, and reports the exact candidate.

mod protocol;
mod signed_in_cli;
mod supervisor;

use bullet_application::dogfood_run::{CredentialSpec, DogfoodReadOnlyOptions};
use bullet_domain::{RunnerId, WorkPackageId};
use bullet_harness_core::HarnessAdapter;
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, AttemptOutcome, CandidatePreparationAdmission,
    ExpectedLeaseServer, HttpLeaseClient, JournalSink, LeaseClient, MonotonicClock,
    SignedLeaseRpcClient,
};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use supervisor::Supervisor;

const LEASE_TRANSPORT_ADMISSION_UNAVAILABLE: &str = "LEASE_TRANSPORT_ADMISSION_UNAVAILABLE";
const LEASE_TRANSPORT_REPAIR: &str = "product Runner dispatch requires an authenticated, descriptor-bound, durable lease transport; the HTTP and Unix component clients are not admission";

#[derive(Parser)]
#[command(name = "bullet-runner", about = "Bullet Farm attempt runner")]
struct Args {
    /// farmd control-plane base URL. Not a lease-transport admission path.
    #[arg(long, default_value = "http://127.0.0.1:7420")]
    farmd: String,
    /// Absolute farmd lease-transport socket. Product admission requires this
    /// together with `--farmd-uid`, `--socket-gid`, and `--lease-recovery`.
    #[arg(long)]
    lease_socket: Option<PathBuf>,
    /// Pinned farmd service UID for UDS admission.
    #[arg(long)]
    farmd_uid: Option<u32>,
    /// Pinned lease-transport socket GID.
    #[arg(long)]
    socket_gid: Option<u32>,
    /// Absolute acquire-recovery file used by the admitted UDS client.
    #[arg(long)]
    lease_recovery: Option<PathBuf>,
    /// Exact digest of the registered Candidate-preparation source.
    #[arg(long)]
    candidate_request_digest: String,
    /// Absolute canonical protected public-key record for Candidate grants.
    #[arg(long)]
    candidate_verification_key: PathBuf,
    /// Exact runner identity (run_<32hex>).
    #[arg(long)]
    runner_id: String,
    /// Exact Kernel-selected work package to acquire/replay (wpk_<64hex>).
    #[arg(long)]
    work_package_id: String,
    /// Runner generation.
    #[arg(long, default_value_t = 1)]
    runner_epoch: u64,
    /// Provider adapter. `sim` is the deterministic simulator; `claude` drives
    /// a REAL contained provider turn and requires the dogfood admission flags
    /// below. There is no fallback: a real provider with missing admission
    /// refuses, it never degrades to the simulator.
    #[arg(long, default_value = "sim", value_parser = ["sim", "claude", "codex", "cursor", "agy", "antigravity"])]
    provider: String,
    /// Provider-native model id. Required for a real provider; `sim` may omit it.
    #[arg(long)]
    model: Option<String>,
    /// Absolute 0700 dogfood data directory. Required for a real provider.
    #[arg(long)]
    dogfood_data_dir: Option<PathBuf>,
    /// Absolute 0600 v1alpha2 dogfood policy. Required for a real provider.
    #[arg(long)]
    dogfood_policy: Option<PathBuf>,
    /// Absolute DogfoodBindingV1. Required for a real provider.
    #[arg(long)]
    dogfood_binding: Option<PathBuf>,
    /// Absolute provider enrollment. Required for a real provider.
    #[arg(long)]
    dogfood_enrollment: Option<PathBuf>,
    /// Operator issuer label. Required for a real provider.
    #[arg(long)]
    dogfood_issuer: Option<String>,
    /// Operator key id. Required for a real provider.
    #[arg(long)]
    dogfood_key_id: Option<String>,
    /// Absolute enrolled provider executable. Required for a real provider.
    #[arg(long)]
    dogfood_executable: Option<PathBuf>,
    /// Repeatable `source,target,blake3` credential grants.
    #[arg(long = "dogfood-credential")]
    dogfood_credentials: Vec<String>,
    /// Create-once receipt path for the real turn.
    #[arg(long)]
    dogfood_receipt: Option<PathBuf>,
    /// Hard spend ceiling in USD for the real turn. Required for a real
    /// provider: the runner never starts billable work without a stated cap.
    #[arg(long)]
    dogfood_max_budget_usd: Option<f64>,
    /// Optional wall-clock ceiling in seconds, bounded by the policy's own
    /// maximum attempt seconds.
    #[arg(long)]
    dogfood_wall_timeout_secs: Option<u64>,
    /// Absolute signed-in Codex/Cursor/agy executable. Never a simulator.
    #[arg(long)]
    signed_in_executable: Option<PathBuf>,
    /// Root for private clones and runtime dirs.
    #[arg(long)]
    workspace_root: PathBuf,
    /// Source repository bullet-gitd clones from.
    #[arg(long)]
    source_repo: PathBuf,
    /// Exact base commit SHA.
    #[arg(long)]
    base_sha: String,
    /// Exact new external directory for the successful Candidate preservation.
    #[arg(long)]
    preservation_destination: PathBuf,
    /// Mission objective for the prompt capsule.
    #[arg(long)]
    objective: String,
    /// Admitted fixed gate ID (repeatable, resolved by the sealed registry).
    #[arg(long = "gate-id", required = true)]
    gate_ids: Vec<String>,
    /// Granted scope prefix (repeatable).
    #[arg(long = "scope", required = true)]
    scope: Vec<String>,
    /// Checkpoint journal directory.
    #[arg(long, default_value = "./target/demo/runner")]
    data_dir: PathBuf,
    /// Exact idempotency key used by the Kernel's pre-acquisition.
    #[arg(long)]
    idempotency_key: String,
    /// Lease TTL seconds (self-kill deadline is 4/5 of this).
    #[arg(long, default_value_t = bullet_runner_core::lease::MAX_LEASE_TTL_SECONDS)]
    ttl_seconds: i64,
}

/// Resolve the provider adapter.
///
/// `sim` is the deterministic simulator. `claude` drives a REAL contained
/// provider turn through the same admission the `bullet dogfood read-only`
/// CLI uses. A real provider whose admission inputs are incomplete refuses
/// here: it must never fall back to the simulator, because a simulated
/// proposal that looks like a real one is the one outcome this whole design
/// exists to prevent.
fn adapter_for(provider: &str, args: &Args) -> Result<Arc<dyn HarnessAdapter>, String> {
    match provider {
        "sim" => Ok(Arc::new(bullet_harness_sim::SimAdapter::new())),
        "claude" => dogfood_options(args).map(|options| {
            Arc::new(bullet_application::dogfood_adapter::DogfoodClaudeAdapter::new(options))
                as Arc<dyn HarnessAdapter>
        }),
        "codex" | "cursor" | "agy" | "antigravity" => {
            require_model(args)?;
            let executable = args.signed_in_executable.clone().ok_or_else(|| {
                "--signed-in-executable is required for a signed-in provider".to_string()
            })?;
            signed_in_cli::SignedInCliAdapter::new(
                args.provider.clone(),
                executable,
                args.model.clone().unwrap_or_default(),
            )
            .map(|adapter| Arc::new(adapter) as Arc<dyn HarnessAdapter>)
        }
        other => Err(format!("unavailable provider {other}")),
    }
}

fn require_model(args: &Args) -> Result<(), String> {
    match args.model.as_deref() {
        Some(model) if !model.is_empty() => Ok(()),
        _ => Err("--model is required for a real provider".into()),
    }
}

/// Assemble the dogfood admission from the runner's flags, refusing by name
/// for anything absent.
fn dogfood_options(args: &Args) -> Result<DogfoodReadOnlyOptions, String> {
    fn need<T>(value: Option<T>, flag: &str) -> Result<T, String> {
        value.ok_or_else(|| format!("--{flag} is required for a real provider"))
    }
    // Every dogfood path is documented as absolute and is resolved by a
    // privileged validator later. A relative path here would be resolved
    // against whatever directory the runner happened to start in, so it is
    // refused at the argument boundary rather than carried inward.
    fn absolute(value: PathBuf, flag: &str) -> Result<PathBuf, String> {
        if value.is_absolute() {
            Ok(value)
        } else {
            Err(format!(
                "--{flag} must be an absolute path, got {}",
                value.display()
            ))
        }
    }
    fn need_absolute(value: Option<PathBuf>, flag: &str) -> Result<PathBuf, String> {
        absolute(need(value, flag)?, flag)
    }
    let max_budget_usd = need(args.dogfood_max_budget_usd, "dogfood-max-budget-usd")?;
    if !max_budget_usd.is_finite() || max_budget_usd <= 0.0 {
        return Err(format!(
            "--dogfood-max-budget-usd must be a positive finite amount, got {max_budget_usd}"
        ));
    }
    let credentials = args
        .dogfood_credentials
        .iter()
        .map(|value| {
            let parts: Vec<&str> = value.splitn(3, ',').collect();
            if parts.len() != 3 {
                return Err("--dogfood-credential must be source,target,blake3".to_string());
            }
            Ok(CredentialSpec {
                source: PathBuf::from(parts[0]),
                target: PathBuf::from(parts[1]),
                blake3: parts[2].to_owned(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(DogfoodReadOnlyOptions {
        provider: "claude".to_string(),
        data_dir: need_absolute(args.dogfood_data_dir.clone(), "dogfood-data-dir")?,
        policy: need_absolute(args.dogfood_policy.clone(), "dogfood-policy")?,
        binding: need_absolute(args.dogfood_binding.clone(), "dogfood-binding")?,
        enrollment: need_absolute(args.dogfood_enrollment.clone(), "dogfood-enrollment")?,
        issuer: need(args.dogfood_issuer.clone(), "dogfood-issuer")?,
        key_id: need(args.dogfood_key_id.clone(), "dogfood-key-id")?,
        executable: need_absolute(args.dogfood_executable.clone(), "dogfood-executable")?,
        gate_ids: args.gate_ids.clone(),
        credentials,
        workdir: absolute(args.workspace_root.clone(), "workspace-root")?,
        prompt: None,
        max_budget_usd: Some(max_budget_usd),
        wall_timeout_secs: args.dogfood_wall_timeout_secs,
        receipt: need_absolute(args.dogfood_receipt.clone(), "dogfood-receipt")?,
    })
}

fn parse_runner_id(raw: &str) -> Result<RunnerId, String> {
    RunnerId::parse(raw).map_err(|error| error.to_string())
}

fn parse_work_package_id(raw: &str) -> Result<WorkPackageId, String> {
    WorkPackageId::parse(raw).map_err(|error| error.to_string())
}

/// Bridges the runner loop's journal into the durable checkpoint supervisor.
struct SupervisorJournal {
    supervisor: Supervisor,
    session: String,
    started: AtomicBool,
}

impl SupervisorJournal {
    fn new(supervisor: Supervisor, session: String) -> Self {
        Self {
            supervisor,
            session,
            started: AtomicBool::new(false),
        }
    }

    fn close(&self) {
        let _ = self.supervisor.terminate(&self.session);
    }
}

impl JournalSink for SupervisorJournal {
    fn record(&self, stage: &str, detail: &str) {
        if let Err(err) = self.try_record(stage, detail) {
            eprintln!("journal error at {stage}: {err}");
        }
    }

    fn try_record(&self, stage: &str, detail: &str) -> Result<(), String> {
        let started = self.started.load(Ordering::SeqCst);
        let result = if started {
            self.supervisor.heartbeat(&self.session)
        } else {
            self.supervisor
                .dispatch(&self.session, Some(detail.to_string()))
        };
        match result {
            Ok(checkpoint) => {
                self.started.store(true, Ordering::SeqCst);
                eprintln!("journal seq {}: {stage}: {detail}", checkpoint.seq);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

fn outcome_json(outcome: &AttemptOutcome) -> serde_json::Value {
    serde_json::json!({
        "attempt_id": outcome.attempt_id.as_str(),
        "fence": outcome.fence,
        "repair_rounds": outcome.repair_rounds,
        "gate_passed": outcome.gates.iter().all(|gate| gate.passed()),
        "gates": outcome.gates,
        "candidate": outcome.candidate,
        "preservation": outcome.preservation,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    run(Args::parse()).await
}

async fn run(args: Args) -> ExitCode {
    // HttpLeaseClient stays compiler-checked and unreachable. Product dispatch
    // constructs SignedLeaseRpcClient::new_admitted only when every local
    // admission input exists.
    let _preserved_http_path = run_quarantined;
    // Provider admission is argument-only, so it is decided first: a real
    // provider with missing admission must refuse before any filesystem
    // canonicalization, socket admission, journal open or lease acquisition,
    // and it must never silently become the simulator.
    let adapter = match adapter_for(&args.provider, &args) {
        Ok(adapter) => adapter,
        Err(reason) => {
            eprintln!("bullet-runner: PROVIDER_ADMISSION_INCOMPLETE: {reason}");
            return ExitCode::from(2);
        }
    };
    let work_package_id = match parse_work_package_id(&args.work_package_id) {
        Ok(work_package_id) => work_package_id,
        Err(error) => {
            eprintln!("bullet-runner: INVALID_WORK_PACKAGE_ID: {error}");
            return ExitCode::from(2);
        }
    };
    let candidate_admission = match admit_candidate_authority(&args) {
        Ok(admission) => admission,
        Err(error) => {
            eprintln!("bullet-runner: {}: {error}", error.reason_code());
            return ExitCode::from(2);
        }
    };
    match admit_signed_lease_client(&args) {
        Ok(client) => {
            run_admitted(args, client, adapter, candidate_admission, work_package_id).await
        }
        Err((code, message)) => {
            eprintln!("bullet-runner: {code}: {message}");
            ExitCode::from(2)
        }
    }
}

fn admit_candidate_authority(
    args: &Args,
) -> Result<CandidatePreparationAdmission, bullet_runner_core::RunnerError> {
    CandidatePreparationAdmission::from_key_file(
        args.candidate_request_digest.clone(),
        &args.candidate_verification_key,
    )
}

fn admit_signed_lease_client(
    args: &Args,
) -> Result<std::sync::Arc<SignedLeaseRpcClient>, (&'static str, &'static str)> {
    let socket = args
        .lease_socket
        .as_ref()
        .ok_or_else(lease_transport_refusal)?;
    if !socket.is_absolute() {
        return Err(lease_transport_refusal());
    }
    let farmd_uid = args.farmd_uid.ok_or_else(lease_transport_refusal)?;
    let socket_gid = args.socket_gid.ok_or_else(lease_transport_refusal)?;
    let recovery = args
        .lease_recovery
        .as_ref()
        .ok_or_else(lease_transport_refusal)?;
    if !recovery.is_absolute() {
        return Err(lease_transport_refusal());
    }
    let runner_id = parse_runner_id(&args.runner_id).map_err(|_| lease_transport_refusal())?;
    SignedLeaseRpcClient::new_admitted(
        socket.clone(),
        runner_id,
        args.runner_epoch,
        ExpectedLeaseServer::new(farmd_uid, socket_gid),
    )
    .with_recovery_file(recovery)
    .map(std::sync::Arc::new)
    .map_err(|_| lease_transport_refusal())
}

async fn run_admitted(
    args: Args,
    client: std::sync::Arc<SignedLeaseRpcClient>,
    adapter: Arc<dyn HarnessAdapter>,
    candidate_admission: CandidatePreparationAdmission,
    work_package_id: WorkPackageId,
) -> ExitCode {
    let runner_id = match parse_runner_id(&args.runner_id) {
        Ok(runner_id) => runner_id,
        Err(error) => {
            eprintln!("bullet-runner: INVALID_RUNNER_ID: {error}");
            return ExitCode::from(2);
        }
    };
    let supervisor = match Supervisor::open(&args.data_dir) {
        Ok(supervisor) => supervisor,
        Err(err) => {
            eprintln!("bullet-runner: journal: {err}");
            return ExitCode::from(2);
        }
    };
    let session = runner_id.to_string();
    if let Ok(prior) = supervisor.salvage(&session) {
        eprintln!(
            "bullet-runner: prior checkpoint seq {} ({})",
            prior.seq, prior.last_command
        );
    }
    let journal = std::sync::Arc::new(SupervisorJournal::new(supervisor, session));
    execute(
        args,
        client,
        adapter,
        journal,
        runner_id,
        work_package_id,
        candidate_admission,
    )
    .await
}

fn lease_transport_refusal() -> (&'static str, &'static str) {
    (
        LEASE_TRANSPORT_ADMISSION_UNAVAILABLE,
        LEASE_TRANSPORT_REPAIR,
    )
}

async fn run_quarantined(args: Args) -> ExitCode {
    let candidate_admission = match admit_candidate_authority(&args) {
        Ok(admission) => admission,
        Err(error) => {
            eprintln!("bullet-runner: {}: {error}", error.reason_code());
            return ExitCode::from(2);
        }
    };
    let runner_id = match parse_runner_id(&args.runner_id) {
        Ok(runner_id) => runner_id,
        Err(error) => {
            eprintln!("bullet-runner: INVALID_RUNNER_ID: {error}");
            return ExitCode::from(2);
        }
    };
    let adapter = match adapter_for(&args.provider, &args) {
        Ok(adapter) => adapter,
        Err(reason) => {
            eprintln!("bullet-runner: PROVIDER_ADMISSION_INCOMPLETE: {reason}");
            return ExitCode::from(2);
        }
    };
    let client: Arc<dyn LeaseClient> = match HttpLeaseClient::new(&args.farmd) {
        Ok(client) => Arc::new(client),
        Err(err) => {
            eprintln!("bullet-runner: {err}");
            return ExitCode::from(2);
        }
    };
    let ready = match client.next_ready().await {
        Ok(Some(ready)) => ready,
        Ok(None) => {
            eprintln!("bullet-runner: no ready work package");
            return ExitCode::from(3);
        }
        Err(err) => {
            eprintln!("bullet-runner: {}: {err}", err.reason_code());
            return ExitCode::from(2);
        }
    };
    let work_package_id = match WorkPackageId::parse(&ready.work_package_id) {
        Ok(id) => id,
        Err(err) => {
            eprintln!("bullet-runner: ready view: {err}");
            return ExitCode::from(2);
        }
    };
    let supervisor = match Supervisor::open(&args.data_dir) {
        Ok(supervisor) => supervisor,
        Err(err) => {
            eprintln!("bullet-runner: journal: {err}");
            return ExitCode::from(2);
        }
    };
    let session = runner_id.to_string();
    if let Ok(prior) = supervisor.salvage(&session) {
        eprintln!(
            "bullet-runner: prior checkpoint seq {} ({})",
            prior.seq, prior.last_command
        );
    }
    let journal = Arc::new(SupervisorJournal::new(supervisor, session));
    execute(
        args,
        client,
        adapter,
        journal,
        runner_id,
        work_package_id,
        candidate_admission,
    )
    .await
}

async fn execute(
    args: Args,
    client: Arc<dyn LeaseClient>,
    adapter: Arc<dyn HarnessAdapter>,
    journal: Arc<SupervisorJournal>,
    runner_id: RunnerId,
    work_package_id: WorkPackageId,
    candidate_admission: CandidatePreparationAdmission,
) -> ExitCode {
    let request = AcquireRequest {
        work_package_id,
        runner_id,
        runner_epoch: args.runner_epoch,
        idempotency_key: args.idempotency_key.clone(),
        ttl_seconds: args.ttl_seconds,
    };
    let config = AttemptConfig::new(
        args.source_repo,
        args.base_sha,
        args.workspace_root,
        args.objective,
        args.scope,
        args.gate_ids,
    )
    .with_candidate_preparation(candidate_admission)
    .with_preservation_destination(args.preservation_destination);
    let config = match args.model.clone() {
        Some(model) => config.with_model(model),
        None => config,
    };
    let clock = Arc::new(MonotonicClock::new());
    let result = run_attempt(client, adapter, journal.clone(), clock, &request, &config).await;
    journal.close();
    match result {
        Ok(outcome) => {
            println!("{}", outcome_json(&outcome));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("bullet-runner: {}: {err}", err.reason_code());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
