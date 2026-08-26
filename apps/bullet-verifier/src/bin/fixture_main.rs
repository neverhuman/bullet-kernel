//! Credential-free verifier fixture for component demos and tests. This is
//! not an independently admitted verifier and cannot emit Bullet Evidence.

use bullet_verifier_core::{execute, GateId, VerifierError, VerifierRequest};
use clap::Parser;
use serde_json::{json, Value};
use std::io::Read;

const MAX_STDIN_REQUEST_BYTES: usize = 64 * 1024;
const FIXTURE_SCHEMA: &str = "bullet.verifier-fixture.v1";

#[derive(Parser)]
#[command(
    name = "bullet-verifier-fixture",
    about = "Unsigned component-only Candidate verification fixture"
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
        if args.workspace_repo_path.is_some()
            || args.base_sha.is_some()
            || args.head_sha.is_some()
            || args.tree_sha.is_some()
            || args.gate_id.is_some()
            || args.author_attempt_id.is_some()
        {
            return Err(VerifierError::BadInput(
                "--stdin cannot be combined with request flags".into(),
            ));
        }
        return request_from_reader(std::io::stdin().lock());
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

fn request_from_reader(reader: impl Read) -> Result<VerifierRequest, VerifierError> {
    let limit = u64::try_from(MAX_STDIN_REQUEST_BYTES + 1).expect("request limit fits u64");
    let mut raw = Vec::with_capacity(MAX_STDIN_REQUEST_BYTES.min(8 * 1024));
    reader
        .take(limit)
        .read_to_end(&mut raw)
        .map_err(|err| VerifierError::Io(format!("read stdin: {err}")))?;
    if raw.len() > MAX_STDIN_REQUEST_BYTES {
        return Err(VerifierError::BadInput(format!(
            "stdin request exceeds {MAX_STDIN_REQUEST_BYTES}-byte limit"
        )));
    }

    serde_json::from_slice(&raw).map_err(|err| {
        VerifierError::BadInput(format!("stdin must contain one JSON request: {err}"))
    })
}

fn observation(outcome: Value, record: Value) -> Value {
    json!({
        "schema_version": FIXTURE_SCHEMA,
        "evidence_class": "COMPONENT_PROOF",
        "independent_evidence_eligible": false,
        "signing_trust": "UNSIGNED_FIXTURE",
        "transaction_gate_eligible": false,
        "outcome": outcome,
        "record": record,
    })
}

fn refusal(err: &VerifierError) -> Value {
    json!({
        "schema_version": FIXTURE_SCHEMA,
        "evidence_class": "COMPONENT_PROOF",
        "independent_evidence_eligible": false,
        "signing_trust": "UNSIGNED_FIXTURE",
        "transaction_gate_eligible": false,
        "reason_code": err.reason_code(),
        "message": err.to_string(),
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
            let record = serde_json::to_value(record).expect("fixture record encodes");
            let outcome = record
                .get("outcome")
                .cloned()
                .expect("fixture record has an outcome");
            println!("{}", observation(outcome, record));
        }
        Err(err) => {
            eprintln!("{}", refusal(&err));
            std::process::exit(2);
        }
    }
}
