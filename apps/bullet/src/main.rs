//! Bullet Farm CLI.

use bullet_adapters::SqliteLedger;
use bullet_application::run_demo;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

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
}

#[derive(Subcommand)]
enum FarmCommands {
    /// Create the local ledger directory.
    Init,
}

fn data_dir() -> PathBuf {
    std::env::var("BULLET_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./target/demo"))
}

fn main() {
    let cli = Cli::parse();
    let dir = data_dir();
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("create data dir: {err}"));
    match cli.command {
        Commands::Farm {
            command: FarmCommands::Init,
        } => {
            let path = dir.join("ledger.sqlite");
            SqliteLedger::open(&path).unwrap_or_else(|err| panic!("init ledger: {err}"));
            println!("initialized {}", path.display());
        }
        Commands::Demo => {
            let path = dir.join("ledger.sqlite");
            let mut ledger =
                SqliteLedger::open(&path).unwrap_or_else(|err| panic!("open ledger: {err}"));
            let receipt = run_demo(&mut ledger).unwrap_or_else(|err| panic!("demo failed: {err}"));
            let json = serde_json::to_string_pretty(&receipt)
                .unwrap_or_else(|err| panic!("encode receipt: {err}"));
            let receipt_path = dir.join("receipts.json");
            fs::write(&receipt_path, &json).unwrap_or_else(|err| panic!("write receipts: {err}"));
            println!("{json}");
            println!("receipts: {}", receipt_path.display());
            if !receipt.stale_refused || !receipt.materialize_idempotent {
                std::process::exit(1);
            }
        }
    }
}
