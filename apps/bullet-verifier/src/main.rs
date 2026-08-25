//! Independent verifier process. Input is CLI flags or a JSON request on
//! stdin; output is one typed evidence record on stdout. The process
//! refuses to run under the writer identity.

use bullet_verifier_core::{execute, GateId, VerifierError, VerifierRequest};
use clap::Parser;
use std::io::Read;

#[derive(Parser)]
#[command(
    name = "bullet-verifier",
    about = "Clean-room Candidate verification producing typed E2 evidence"
)]
struct Args {
    /// Read the full JSON request from stdin instead of flags.
    #[arg(long)]
    stdin: bool,
    /// Path of the workspace repository to reconstruct from.
    #[arg(long)]
    workspace_repo_path: Option<String>,
    /// Candidate base commit SHA.
    #[arg(long)]
    base_sha: Option<String>,
    /// Candidate head commit SHA.
    #[arg(long)]
    head_sha: Option<String>,
    /// Candidate tree SHA.
    #[arg(long)]
    tree_sha: Option<String>,
    /// Kernel-catalog gate selected by policy.
    #[arg(long)]
    gate_id: Option<GateId>,
    /// Attempt that authored the Candidate.
    #[arg(long)]
    author_attempt_id: Option<String>,
}

fn request_from(args: Args) -> Result<VerifierRequest, VerifierError> {
    if args.stdin {
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .map_err(|err| VerifierError::Io(format!("read stdin: {err}")))?;
        return serde_json::from_str(&raw)
            .map_err(|err| VerifierError::BadInput(format!("stdin json: {err}")));
    }
    let missing = |name: &str| VerifierError::BadInput(format!("--{name} is required"));
    Ok(VerifierRequest {
        workspace_repo_path: args
            .workspace_repo_path
            .ok_or_else(|| missing("workspace-repo-path"))?,
        base_sha: args.base_sha.ok_or_else(|| missing("base-sha"))?,
        head_sha: args.head_sha.ok_or_else(|| missing("head-sha"))?,
        tree_sha: args.tree_sha.ok_or_else(|| missing("tree-sha"))?,
        gate_id: args.gate_id.ok_or_else(|| missing("gate-id"))?,
        author_attempt_id: args
            .author_attempt_id
            .ok_or_else(|| missing("author-attempt-id"))?,
    })
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let overlap = std::env::var("BULLET_VERIFIER_AUTHOR_OVERLAP").as_deref() == Ok("1");
    let result = match request_from(args) {
        Ok(request) => execute(&request, overlap).await,
        Err(err) => Err(err),
    };
    match result {
        Ok(record) => {
            println!(
                "{}",
                serde_json::to_string(&record).expect("evidence record encodes")
            );
        }
        Err(err) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "reason_code": err.reason_code(),
                    "message": err.to_string(),
                })
            );
            std::process::exit(2);
        }
    }
}
