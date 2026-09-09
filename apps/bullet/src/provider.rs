//! `bullet provider live-conformance`: the operator entry point to the guarded
//! live-conformance path. It loads the on-disk policy (v1alpha1 or an
//! operator-ratified v1alpha2 generation, ADR 0012), reports its schema
//! version, generation, and digest, selects the provider adapter and the real
//! `bullet-harness-egress` backend, and drives
//! `bullet_application::run_live_conformance`. Under v1alpha1 every provider
//! refuses at `POLICY_LIVE_ADMISSION_DISABLED`; a valid v1alpha2 policy reaches
//! the production adapters' `RUNTIME_PROBE_UNAVAILABLE` refusal. Both are
//! neutral exit 78 before operator-key read, authority mutation, egress, or
//! provider spawn.

use bullet_adapters::SqliteLedger;
use bullet_application::policy_snapshot::load_policy_from_environment;
use bullet_application::{run_live_conformance, LiveConformanceOptions};
use bullet_harness_core::launch_grant::random_hex_64;
use bullet_harness_core::{
    EgressBackend, EgressIsolationEvidence, EgressProbe, EgressProbeOutcome, HarnessError,
    LiveDispatcher, LiveOutcome, PreparedEgress,
};
use bullet_harness_egress::{Containment, EgressPolicy, EgressSandbox, PreparedSandbox};
use chrono::Utc;
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

/// Neutral exit code for a designed policy or runtime-observation refusal.
const NEUTRAL_REFUSAL: u8 = 78;
const DEFAULT_MAX_COST_MICRO_USD: u64 = 50_000;

/// `bullet provider ...`
#[derive(Subcommand)]
pub(super) enum ProviderCommands {
    /// Run the guarded live-conformance path for one provider. Production
    /// adapters currently refuse (exit 78) before any provider is spawned.
    LiveConformance(Box<LiveConformanceArgs>),
}

/// Inputs for `provider live-conformance`.
#[derive(Args)]
pub(super) struct LiveConformanceArgs {
    /// Absolute Kernel data directory (ledger, key, policy, receipts).
    #[arg(long)]
    data_dir: PathBuf,
    /// Provider wire name.
    #[arg(long, value_parser = ["claude", "codex", "cursor", "agy"])]
    provider: String,
    /// Absolute executable path; defaults to the provider binary resolved on PATH.
    #[arg(long)]
    executable: Option<PathBuf>,
    /// Tightest cost cap in micro-USD.
    #[arg(long, default_value_t = DEFAULT_MAX_COST_MICRO_USD)]
    max_cost_micro_usd: u64,
}

pub(super) fn run(command: ProviderCommands) -> ExitCode {
    match command {
        ProviderCommands::LiveConformance(args) => match live_conformance(&args) {
            Ok(code) => ExitCode::from(code),
            Err(message) => {
                eprintln!("bullet: {message}");
                ExitCode::FAILURE
            }
        },
    }
}

fn live_conformance(args: &LiveConformanceArgs) -> Result<u8, String> {
    if !args.data_dir.is_absolute() {
        return Err("--data-dir must be absolute".into());
    }
    let dispatcher = select_dispatcher(&args.provider)?;
    let executable = resolve_executable(&args.provider, args.executable.clone())?;
    let options = default_options(
        &args.provider,
        executable,
        args.max_cost_micro_usd,
        dispatcher.as_ref(),
    )?;
    let policy = load_policy_from_environment(&args.data_dir)
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    println!(
        "policy: schema_version={} generation={} live_admission_enabled={} digest={}",
        policy.schema().as_str(),
        policy.generation(),
        policy.live_admission_enabled(),
        policy.digest()
    );
    let mut ledger = SqliteLedger::open(args.data_dir.join("ledger.sqlite"))
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    let egress = RealEgressBackend;
    let now = Utc::now();
    match run_live_conformance(
        &args.data_dir,
        &mut ledger,
        &policy,
        dispatcher.as_ref(),
        &egress,
        &options,
        now,
    ) {
        Ok(run) => {
            println!("receipt: {}", run.receipt_path.display());
            match run.receipt.outcome {
                LiveOutcome::Pong => {
                    println!("live-conformance {}: PONG", args.provider);
                    Ok(0)
                }
                LiveOutcome::Refused => {
                    println!(
                        "live-conformance {}: refused ({}); neutral",
                        args.provider,
                        run.receipt.refusal_reason.as_deref().unwrap_or("REFUSED")
                    );
                    Ok(NEUTRAL_REFUSAL)
                }
                LiveOutcome::Failed => {
                    eprintln!("live-conformance {}: failed", args.provider);
                    Ok(1)
                }
            }
        }
        Err(error) => {
            eprintln!(
                "bullet: live-conformance {} failed at {:?}: {}",
                args.provider, error.step, error
            );
            eprintln!("receipt: {}", error.receipt_path.display());
            Ok(1)
        }
    }
}

fn select_dispatcher(provider: &str) -> Result<Box<dyn LiveDispatcher>, String> {
    match provider {
        "claude" => Ok(Box::new(bullet_harness_claude::ClaudeAdapter::new())),
        "codex" => Ok(Box::new(bullet_harness_codex::CodexAdapter::new())),
        "cursor" => Ok(Box::new(bullet_harness_cursor::CursorAdapter::new())),
        "agy" => Ok(Box::new(
            bullet_harness_antigravity::AntigravityAdapter::new(),
        )),
        other => Err(format!("unknown provider {other:?}")),
    }
}

fn default_options(
    provider: &str,
    executable: PathBuf,
    max_cost_micro_usd: u64,
    dispatcher: &dyn LiveDispatcher,
) -> Result<LiveConformanceOptions, String> {
    let canary = random_hex_64().map_err(|error| format!("{}: {error}", error.reason_code()))?;
    Ok(LiveConformanceOptions {
        provider: provider.to_string(),
        executable,
        version: dispatcher.observed_runtime_version().to_string(),
        profile_email: "operator@bullet.farm".to_string(),
        adapter_label: format!("{provider}-adapter"),
        model: format!("{provider}-default"),
        credential_generation: 1,
        max_cost_micro_usd,
        wall_timeout: Duration::from_secs(180),
        ttl_ms: 15_000,
        issuer: "bullet-kernel".to_string(),
        key_id: "launch-grant-alpha".to_string(),
        seed: format!("live-conformance-{provider}"),
        canaries: vec![format!("bullet-live-conformance-canary-{canary}")],
    })
}

fn binary_name(provider: &str) -> &'static str {
    match provider {
        "cursor" => "cursor-agent",
        "codex" => "codex",
        "agy" => "agy",
        _ => "claude",
    }
}

fn resolve_executable(provider: &str, explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    let path = match explicit {
        Some(path) => {
            if !path.is_absolute() {
                return Err("--executable must be absolute".into());
            }
            path
        }
        None => resolve_on_path(binary_name(provider))?,
    };
    path.canonicalize()
        .map_err(|error| format!("resolve executable {}: {error}", path.display()))
}

fn resolve_on_path(name: &str) -> Result<PathBuf, String> {
    let paths = std::env::var_os("PATH").ok_or("PATH is not set")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("{name} was not found on PATH"))
}

/// Real egress backend wrapping `bullet-harness-egress`. Reached only under an
/// operator-ratified live-admission policy; under v1alpha1 the orchestrator
/// refuses before it is consulted.
struct RealEgressBackend;

fn egress_provider(provider: &str) -> &str {
    if provider == "agy" {
        "antigravity"
    } else {
        provider
    }
}

fn map_egress(error: &bullet_harness_egress::EgressError) -> HarnessError {
    HarnessError::Io {
        context: "egress backend".to_string(),
        reason: format!("{}: {}", error.reason_code(), error.detail),
    }
}

impl EgressBackend for RealEgressBackend {
    fn sandbox_manifest_digest(&self, provider: &str) -> Result<String, HarnessError> {
        let policy =
            EgressPolicy::for_provider(egress_provider(provider)).map_err(|e| map_egress(&e))?;
        Ok(policy.allowlist_digest())
    }

    fn prepare(
        &self,
        provider: &str,
        workdir: &Path,
    ) -> Result<Box<dyn PreparedEgress + '_>, HarnessError> {
        let policy =
            EgressPolicy::for_provider(egress_provider(provider)).map_err(|e| map_egress(&e))?;
        let sandbox = EgressSandbox::prepare(policy, workdir).map_err(|e| map_egress(&e))?;
        Ok(Box::new(RealPreparedEgress { sandbox }))
    }
}

struct RealPreparedEgress {
    sandbox: PreparedSandbox,
}

impl PreparedEgress for RealPreparedEgress {
    fn evidence(&self) -> EgressIsolationEvidence {
        let evidence = self.sandbox.receipt().evidence();
        EgressIsolationEvidence {
            receipt_digest: evidence.receipt_digest,
            ruleset_digest: evidence.ruleset_digest,
            allowlist_digest: evidence.allowlist_digest,
            probes: evidence
                .probes
                .into_iter()
                .map(|probe| EgressProbe {
                    name: probe.name,
                    outcome: match probe.outcome {
                        Containment::Refused => EgressProbeOutcome::Refused,
                        Containment::Unreachable => EgressProbeOutcome::Unreachable,
                        Containment::Reached => EgressProbeOutcome::Reached,
                        Containment::Unknown => EgressProbeOutcome::Unknown,
                    },
                })
                .collect(),
        }
    }

    fn command(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
        self.sandbox.command(program, args, env)
    }
}
