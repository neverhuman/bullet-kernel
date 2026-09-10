use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct ConnectionArgs {
    /// Private session saved by bullet auth login.
    #[arg(long)]
    pub(super) state_dir: Option<PathBuf>,
    /// Optional destination check; must match the saved authenticated endpoint.
    #[arg(long)]
    pub(super) farmd: Option<String>,
}

#[derive(Subcommand)]
pub(crate) enum CodingCommands {
    /// Discover this operator's durable commands, including after local journal loss.
    List {
        #[command(flatten)]
        connection: ConnectionArgs,
        /// Submission cursor returned by the previous page; zero starts discovery.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=9_007_199_254_740_991))]
        after: u64,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Submit run_coding using the private saved operator session.
    Submit {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[arg(long)]
        account: String,
        #[arg(long, value_parser = ["claude", "codex", "cursor", "antigravity"])]
        provider: String,
        #[arg(long)]
        model: String,
        #[arg(long, default_value_t = 1)]
        expected_revision: u64,
        /// Reuse this key to retry the exact journaled request after response loss.
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Read one durable command subject.
    Status {
        #[command(flatten)]
        connection: ConnectionArgs,
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Read the atomic operator board.
    Board {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Poll the same atomic board; this client does not own farm work.
    Watch {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[arg(long)]
        command: Option<String>,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        #[arg(long)]
        json: bool,
    },
    /// Inspect local CLI configuration; this does not establish daemon admission.
    HarnessCheck {
        #[arg(long)]
        json: bool,
    },
    /// Refuse until durable native cancellation is implemented.
    Stop,
}
