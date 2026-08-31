//! Bullet Farm CLI.

mod authority;
mod contracts;
#[path = "demo_live/mod.rs"]
mod demo_synthetic;
mod dogfood;
mod maintenance;
mod mission;
mod provider;
mod run;
mod transaction;

use bullet_adapters::SqliteLedger;
use bullet_application::run_demo;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "bullet", about = "Bullet Farm CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a local data directory.
    Farm {
        #[command(subcommand)]
        command: FarmCommands,
    },
    /// Run the first simulator demonstration.
    Demo,
    /// Run simulator-only integration scaffolding. This is not transaction proof.
    DemoSynthetic {
        /// Existing origin repository instead of the generated fixture.
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Generated-contract tooling. The YAML is the source of truth.
    Contracts {
        #[command(subcommand)]
        command: ContractsCommands,
    },
    /// Operator-held launch-grant authority: keygen and offline minting.
    Authority {
        #[command(subcommand)]
        command: authority::AuthorityCommands,
    },
    /// Materialize one plan revision into the local ledger and read it back.
    Mission {
        #[command(subcommand)]
        command: mission::MissionCommands,
    },
    /// Provider live-conformance: policy-gated and fail-closed at runtime observation.
    Provider {
        #[command(subcommand)]
        command: provider::ProviderCommands,
    },
    /// Read a run receipt back: verify its digest and chain, then render it.
    Run {
        #[command(subcommand)]
        command: run::RunCommands,
    },
    /// Five-plane transaction receipt. Currently ABSENT and ineligible.
    Transaction {
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Internal dogfood compose. Not a release profile and not live-conformance.
    Dogfood {
        #[command(subcommand)]
        command: dogfood::DogfoodCommands,
    },
}

#[derive(Subcommand)]
enum FarmCommands {
    /// Create the local ledger directory.
    Init,
    /// Create a consistent standalone SQLite snapshot and exact receipt.
    Backup {
        /// Existing Kernel ledger database.
        #[arg(long)]
        database: PathBuf,
        /// New standalone SQLite snapshot; must not exist.
        #[arg(long)]
        output: PathBuf,
        /// New JSON receipt file; must not exist.
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Reclaim every writer lease whose expiry has already passed. A running
    /// bullet-farmd already reaps on its own tick; this is for a stopped one.
    Reap {
        /// Existing Kernel ledger database.
        #[arg(long)]
        database: PathBuf,
    },
    /// Restore an exact receipt-bound snapshot into quarantine.
    Restore {
        /// Standalone SQLite snapshot created by `farm backup`.
        #[arg(long)]
        backup: PathBuf,
        /// Retained JSON receipt from `farm backup`.
        #[arg(long)]
        receipt: PathBuf,
        /// New database path; must not exist.
        #[arg(long)]
        destination: PathBuf,
    },
}

#[derive(Subcommand)]
enum ContractsCommands {
    /// Regenerate contracts/generated/api.ts from contracts/openapi.yaml.
    Generate,
    /// Fail when the generated TypeScript is stale.
    Check,
}

fn data_dir() -> PathBuf {
    std::env::var("BULLET_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./target/demo"))
}

#[cfg(target_os = "linux")]
fn ensure_private_data_dir(path: &std::path::Path) -> Result<(), String> {
    use rustix::fs::{fchmod, fstat, open, Mode, OFlags};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|err| format!("create private data dir: {err}"))?;

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| format!("open private data dir without following links: {err}"))?;
    let before = fstat(&descriptor).map_err(|err| format!("inspect private data dir: {err}"))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if before.st_uid != effective_uid {
        return Err(format!(
            "private data dir must be owned by effective uid {effective_uid}"
        ));
    }
    fchmod(&descriptor, Mode::from_raw_mode(0o700))
        .map_err(|err| format!("set private data dir mode 0700: {err}"))?;
    let after = fstat(&descriptor).map_err(|err| format!("reinspect private data dir: {err}"))?;
    let public = fs::symlink_metadata(path)
        .map_err(|err| format!("reinspect private data dir pathname: {err}"))?;
    if public.file_type().is_symlink()
        || public.dev() != after.st_dev
        || public.ino() != after.st_ino
        || public.uid() != effective_uid
        || public.mode() & 0o7777 != 0o700
        || after.st_mode & 0o7777 != 0o700
    {
        return Err("private data dir changed or remained unsafe during mode admission".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_private_data_dir(_path: &std::path::Path) -> Result<(), String> {
    Err("private authority data directories require Linux".into())
}

fn run(command: Commands) -> Result<(), String> {
    match command {
        Commands::Provider { .. } => unreachable!("provider is handled in main"),
        Commands::Transaction { .. } => unreachable!("transaction is handled in main"),
        Commands::Dogfood { .. } => unreachable!("dogfood is handled in main"),
        Commands::Farm { command } => match command {
            FarmCommands::Init => {
                let dir = data_dir();
                ensure_private_data_dir(&dir)?;
                let path = dir.join("ledger.sqlite");
                SqliteLedger::open(&path).map_err(|err| format!("init ledger: {err}"))?;
                println!("initialized {}", path.display());
                Ok(())
            }
            FarmCommands::Backup {
                database,
                output,
                receipt,
            } => maintenance::backup(&database, &output, &receipt),
            FarmCommands::Reap { database } => maintenance::reap(&database),
            FarmCommands::Restore {
                backup,
                receipt,
                destination,
            } => maintenance::restore(&backup, &receipt, &destination),
        },
        Commands::Demo => demo(),
        Commands::DemoSynthetic { target } => demo_synthetic::run(target, data_dir()),
        Commands::Contracts { command } => match command {
            ContractsCommands::Generate => contracts::generate(),
            ContractsCommands::Check => contracts::check(),
        },
        Commands::Authority { command } => authority::run(command),
        Commands::Mission { command } => mission::run(command),
        Commands::Run { command } => run::run(command),
    }
}

fn demo() -> Result<(), String> {
    let dir = data_dir();
    fs::create_dir_all(&dir).map_err(|err| format!("create data dir: {err}"))?;
    let path = dir.join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).map_err(|err| format!("open ledger: {err}"))?;
    let receipt = run_demo(&mut ledger).map_err(|err| format!("demo failed: {err}"))?;
    let json =
        serde_json::to_string_pretty(&receipt).map_err(|err| format!("encode receipt: {err}"))?;
    let receipt_path = dir.join("receipts.json");
    fs::write(&receipt_path, &json).map_err(|err| format!("write receipts: {err}"))?;
    println!("{json}");
    println!("receipts: {}", receipt_path.display());
    if !receipt.stale_refused || !receipt.materialize_idempotent {
        return Err("demo receipt failed its own safety checks".into());
    }
    if receipt.fence_second != receipt.fence_first + 1 {
        return Err(format!(
            "fence progression broken: {} then {}",
            receipt.fence_first, receipt.fence_second
        ));
    }
    if receipt.candidate_head != "NOT_PRODUCED"
        || receipt.evidence_result != "NOT_RUN"
        || receipt.effect_outcome != "NOT_DISPATCHED"
        || receipt.effect_unknown_outcome != "NOT_DISPATCHED"
    {
        return Err("component demo fabricated a production transaction subject".into());
    }
    eprintln!(
        "bullet: COMPONENT_ONLY: transaction_gate_eligible=false; Candidate, Evidence, and Effect were not produced"
    );
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Provider { command } => provider::run(command),
        Commands::Dogfood { command } => dogfood::run(command),
        Commands::Transaction { json } => {
            if !json {
                eprintln!("bullet: TRANSACTION_PROOF_UNAVAILABLE: --json is required");
                return ExitCode::from(2);
            }
            transaction::run_json()
        }
        other => match run(other) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("bullet: {message}");
                ExitCode::FAILURE
            }
        },
    }
}
