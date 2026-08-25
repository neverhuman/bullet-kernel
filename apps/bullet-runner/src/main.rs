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

const LEASE_TRANSPORT_ADMISSION_UNAVAILABLE: &str = "LEASE_TRANSPORT_ADMISSION_UNAVAILABLE";
const LEASE_TRANSPORT_REPAIR: &str = "product Runner dispatch requires an authenticated, descriptor-bound, durable lease transport; the HTTP and Unix component clients are not admission";

#[derive(Parser)]
#[command(name = "bullet-runner", about = "Bullet Farm attempt runner")]
struct Args {
    /// farmd control-plane base URL.
    #[arg(long, default_value = "http://127.0.0.1:7420")]
    farmd: String,
    /// Exact runner identity (run_<32hex>).
    #[arg(long)]
    runner_id: String,
    /// Runner generation.
    #[arg(long, default_value_t = 1)]
    runner_epoch: u64,
    /// Provider adapter. Wave-0 binaries expose simulator mode only.
    #[arg(long, default_value = "sim", value_parser = ["sim"])]
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
    /// Admitted fixed gate ID (repeatable, resolved by the sealed registry).
    #[arg(long = "gate-id", required = true)]
    gate_ids: Vec<String>,
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
    #[arg(long, default_value_t = bullet_runner_core::lease::MAX_LEASE_TTL_SECONDS)]
    ttl_seconds: i64,
}

fn adapter_for(provider: &str) -> Option<Arc<dyn HarnessAdapter>> {
    match provider {
        "sim" => Some(Arc::new(bullet_harness_sim::SimAdapter::new())),
        _ => None,
    }
}

fn parse_runner_id(raw: &str) -> Result<RunnerId, String> {
    RunnerId::parse(raw).map_err(|error| error.to_string())
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
        "gate_passed": outcome.gates.iter().all(|gate| gate.passed()),
        "gates": outcome.gates,
        "candidate": outcome.candidate,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    run(Args::parse()).await
}

async fn run(args: Args) -> ExitCode {
    // Keep the quarantined attempt path compiler-checked without making it reachable from the
    // product CLI. Re-enable only after the lease transport has mutual process authentication,
    // durable request/result reconciliation, and restart-safe read-back.
    let _preserved_adapter = adapter_for;
    let _preserved_runner_id_parser = parse_runner_id;
    let _preserved_attempt_path = run_quarantined;
    let _ = args;
    let (code, message) = lease_transport_refusal();
    eprintln!("bullet-runner: {code}: {message}");
    ExitCode::from(2)
}

fn lease_transport_refusal() -> (&'static str, &'static str) {
    (
        LEASE_TRANSPORT_ADMISSION_UNAVAILABLE,
        LEASE_TRANSPORT_REPAIR,
    )
}

async fn run_quarantined(args: Args) -> ExitCode {
    let runner_id = match parse_runner_id(&args.runner_id) {
        Ok(runner_id) => runner_id,
        Err(error) => {
            eprintln!("bullet-runner: INVALID_RUNNER_ID: {error}");
            return ExitCode::from(2);
        }
    };
    let Some(adapter) = adapter_for(&args.provider) else {
        eprintln!(
            "bullet-runner: unavailable provider {} (simulator-only quarantine)",
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
    let config = AttemptConfig::new(
        args.source_repo,
        args.base_sha,
        args.workspace_root,
        args.objective,
        args.scope,
        args.gate_ids,
    );
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
mod tests {
    use super::{lease_transport_refusal, parse_runner_id, run, Args};
    use bullet_domain::RunnerId;
    use std::process::ExitCode;

    #[tokio::test]
    async fn runner_identity_is_exact_and_never_derived_from_malformed_text() {
        let expected = RunnerId::from_seed("admitted-runner");
        assert_eq!(parse_runner_id(expected.as_str()).unwrap(), expected);

        for invalid in ["", "admitted-runner", "run_short", "run_not-hex"] {
            assert!(parse_runner_id(invalid).is_err(), "{invalid:?} must refuse");
        }

        let (code, message) = lease_transport_refusal();
        assert_eq!(code, "LEASE_TRANSPORT_ADMISSION_UNAVAILABLE");
        assert!(message.contains("authenticated"));
        assert!(message.contains("descriptor-bound"));
        assert!(message.contains("durable"));

        let root = std::env::temp_dir().join(format!(
            "bullet-runner-refusal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        assert!(!root.exists(), "test subject must begin absent");
        let workspace = root.join("must-not-create-workspace");
        let journal = root.join("must-not-create-journal");
        let status = run(Args {
            farmd: "not-a-url".into(),
            runner_id: "not-a-runner".into(),
            runner_epoch: 0,
            provider: "not-a-provider".into(),
            workspace_root: workspace.clone(),
            source_repo: root.join("missing-source"),
            base_sha: "not-an-oid".into(),
            objective: "must not dispatch".into(),
            gate_ids: vec!["not-a-gate".into()],
            scope: vec![".".into()],
            data_dir: journal.clone(),
            idempotency_key: None,
            ttl_seconds: 0,
        })
        .await;
        assert_eq!(status, ExitCode::from(2));
        assert!(!workspace.exists(), "workspace must remain absent");
        assert!(!journal.exists(), "supervisor journal must remain absent");
    }
}
