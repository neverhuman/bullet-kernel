//! Bullet Farm CLI.

mod contracts;
#[path = "demo_live/mod.rs"]
mod demo_synthetic;
mod maintenance;

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

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Farm { command } => match command {
            FarmCommands::Init => {
                let dir = data_dir();
                fs::create_dir_all(&dir).map_err(|err| format!("create data dir: {err}"))?;
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
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bullet: {message}");
            ExitCode::FAILURE
        }
    }
}
