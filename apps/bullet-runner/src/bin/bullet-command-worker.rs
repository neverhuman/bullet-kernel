//! Single-run, peer-authenticated public-command component worker.

#[path = "bullet-command-worker/child.rs"]
mod child;
#[path = "bullet-command-worker/claim_fd.rs"]
mod claim_fd;
#[path = "bullet-command-worker/error.rs"]
mod error;
#[path = "bullet-command-worker/manifest.rs"]
mod manifest;
#[path = "bullet-command-worker/receipt.rs"]
mod receipt;
#[path = "bullet-command-worker/state.rs"]
mod state;
#[path = "bullet-command-worker/worker.rs"]
mod worker;

use bullet_domain::RunnerId;
use bullet_runner_core::{ExpectedLeaseServer, SignedLeaseRpcClient};
use clap::Parser;
use error::WorkerError;
use manifest::AdmittedManifest;
use state::StateStore;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "bullet-command-worker")]
struct Args {
    #[arg(long)]
    lease_socket: PathBuf,
    #[arg(long)]
    farmd_uid: u32,
    #[arg(long)]
    socket_gid: u32,
    #[arg(long)]
    runner_id: String,
    #[arg(long)]
    runner_epoch: u64,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    binary_manifest: PathBuf,
    #[arg(
        long,
        default_value_t = 600_000,
        value_parser = clap::value_parser!(u64).range(1_000..=900_000)
    )]
    deadline_ms: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(worked) => {
            println!(
                "{}",
                if worked {
                    "COMMAND_UNKNOWN"
                } else {
                    "NO_COMMAND"
                }
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bullet-command-worker: {}: {}", error.code(), error);
            ExitCode::from(2)
        }
    }
}

async fn run(args: Args) -> Result<bool, WorkerError> {
    let runner_id = RunnerId::parse(&args.runner_id)
        .map_err(|error| WorkerError::input("RUNNER_ID_INVALID", error.to_string()))?;
    if args.runner_epoch == 0 || args.runner_epoch > 9_007_199_254_740_991 {
        return Err(WorkerError::input(
            "RUNNER_EPOCH_INVALID",
            "runner epoch must be a positive safe integer",
        ));
    }
    let store = StateStore::admit(&args.state_dir)?;
    let manifest = AdmittedManifest::admit(&args.binary_manifest)?;
    let client = SignedLeaseRpcClient::new_admitted(
        args.lease_socket,
        runner_id.clone(),
        args.runner_epoch,
        ExpectedLeaseServer::new(args.farmd_uid, args.socket_gid),
    );
    worker::run_once(
        &client,
        &store,
        &manifest,
        Duration::from_millis(args.deadline_ms),
        &runner_id,
        args.runner_epoch,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e2e_args(deadline_ms: &str) -> Vec<String> {
        [
            "bullet-command-worker",
            "--lease-socket",
            "/tmp/bullet/lease.sock",
            "--farmd-uid",
            "1000",
            "--socket-gid",
            "1000",
            "--runner-id",
            "run_1111111111111111111111111111111111111111111111111111111111111111",
            "--runner-epoch",
            "1",
            "--state-dir",
            "/tmp/bullet/worker",
            "--binary-manifest",
            "/tmp/bullet/manifest.json",
            "--deadline-ms",
            deadline_ms,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn exact_e2e_deadlines_parse_as_u64_without_panic() {
        for (value, expected) in [("600000", 600_000), ("900000", 900_000)] {
            let parsed = Args::try_parse_from(e2e_args(value)).unwrap();
            assert_eq!(parsed.deadline_ms, expected);
        }
    }

    #[test]
    fn out_of_range_deadlines_refuse_without_panic() {
        for value in ["999", "900001"] {
            assert!(Args::try_parse_from(e2e_args(value)).is_err());
        }
    }
}
