//! Attempt runner CLI (ADR 0001): leases a ready work package from farmd,
//! spawns bullet-gitd for the private clone, drives a read-only provider
//! session, applies scope-checked PatchProposals through the daemon, runs
//! the deterministic gate, and reports the exact candidate.

mod protocol;
mod supervisor;

use bullet_domain::{RunnerId, WorkPackageId};
use bullet_harness_core::HarnessAdapter;
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, AttemptOutcome, HttpLeaseClient, JournalSink,
    LeaseClient, MonotonicClock,
};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use supervisor::Supervisor;

#[derive(Parser)]
#[command(name = "bullet-runner", about = "Bullet Farm attempt runner")]
struct Args {
    /// farmd control-plane base URL.
    #[arg(long, default_value = "http://127.0.0.1:7420")]
    farmd: String,
    /// Runner identity (run_<32hex>); any other string is used as a seed.
    #[arg(long)]
    runner_id: String,
    /// Runner generation.
    #[arg(long, default_value_t = 1)]
    runner_epoch: u64,
    /// Provider adapter: sim (default), claude, codex, cursor.
    #[arg(long, default_value = "sim")]
    provider: String,
    /// Root for private clones and runtime dirs.
    #[arg(long)]
    workspace_root: PathBuf,
    /// Source repository bullet-gitd clones from.
    #[arg(long)]
    source_repo: PathBuf,
    /// Exact base commit SHA.
    #[arg(long)]
    base_sha: String,
    /// Mission objective for the prompt capsule.
    #[arg(long)]
    objective: String,
    /// Deterministic gate command.
    #[arg(long)]
    gate: String,
    /// Granted scope prefix (repeatable).
    #[arg(long = "scope", required = true)]
    scope: Vec<String>,
    /// Checkpoint journal directory.
    #[arg(long, default_value = "./target/demo/runner")]
    data_dir: PathBuf,
    /// Idempotency key; omit for a fresh attempt.
    #[arg(long)]
    idempotency_key: Option<String>,
    /// Lease TTL seconds (self-kill deadline is 4/5 of this).
    #[arg(long, default_value_t = 30)]
    ttl_seconds: i64,
}

fn adapter_for(provider: &str) -> Option<Arc<dyn HarnessAdapter>> {
    match provider {
        "sim" => Some(Arc::new(bullet_harness_sim::SimAdapter::new())),
        "claude" => Some(Arc::new(bullet_harness_claude::ClaudeAdapter::new())),
        "codex" => Some(Arc::new(bullet_harness_codex::CodexAdapter::new())),
        "cursor" => Some(Arc::new(bullet_harness_cursor::CursorAdapter::new())),
        _ => None,
    }
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
        let result = if self.started.swap(true, Ordering::SeqCst) {
            self.supervisor.heartbeat(&self.session)
        } else {
            self.supervisor
                .dispatch(&self.session, Some(detail.to_string()))
        };
        match result {
            Ok(checkpoint) => eprintln!("journal seq {}: {stage}: {detail}", checkpoint.seq),
            Err(err) => eprintln!("journal error at {stage}: {err}"),
        }
    }
}

fn outcome_json(outcome: &AttemptOutcome) -> serde_json::Value {
    serde_json::json!({
        "attempt_id": outcome.attempt_id.as_str(),
        "fence": outcome.fence,
        "repair_rounds": outcome.repair_rounds,
        "gate_passed": outcome.gate.passed(),
        "candidate": outcome.candidate,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    run(Args::parse()).await
}

async fn run(args: Args) -> ExitCode {
    let Some(adapter) = adapter_for(&args.provider) else {
        eprintln!(
            "bullet-runner: unknown provider {} (sim|claude|codex|cursor)",
            args.provider
        );
        return ExitCode::from(2);
    };
    let client = match HttpLeaseClient::new(&args.farmd) {
        Ok(client) => Arc::new(client),
        Err(err) => {
            eprintln!("bullet-runner: {err}");
            return ExitCode::from(2);
        }
    };
    let runner_id =
        RunnerId::parse(&args.runner_id).unwrap_or_else(|_| RunnerId::from_seed(&args.runner_id));
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
    execute(args, client, adapter, journal, runner_id, work_package_id).await
}

async fn execute(
    args: Args,
    client: Arc<HttpLeaseClient>,
    adapter: Arc<dyn HarnessAdapter>,
    journal: Arc<SupervisorJournal>,
    runner_id: RunnerId,
    work_package_id: WorkPackageId,
) -> ExitCode {
    let idempotency_key = args.idempotency_key.clone().unwrap_or_else(|| {
        format!(
            "lease:{}",
            bullet_harness_core::synthetic_uuid("bullet-runner")
        )
    });
    let request = AcquireRequest {
        work_package_id,
        runner_id,
        runner_epoch: args.runner_epoch,
        idempotency_key,
        ttl_seconds: args.ttl_seconds,
    };
    let mut config = AttemptConfig::new(
        args.source_repo,
        args.base_sha,
        args.workspace_root,
        args.objective,
        args.scope,
        args.gate,
    );
    config.heartbeat.ttl_seconds = args.ttl_seconds;
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
