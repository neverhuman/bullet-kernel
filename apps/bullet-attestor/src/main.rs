//! Independent attestor process. Publishes one check for one exact SHA.
//! The process cannot push and refuses to run without its own credential.

use bullet_effects_core::{attest, attestor_push, AttestorCredential, CheckPublication};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "bullet-attestor",
    about = "Publish one check for one exact SHA; cannot push"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish one check bound to one SHA and one proof root.
    Attest {
        /// Path to the attestor credential file (mode 0600).
        #[arg(long)]
        credential_file: PathBuf,
        /// Exact commit SHA.
        #[arg(long)]
        sha: String,
        /// Check name.
        #[arg(long)]
        name: String,
        /// Proof root echoed on read-back.
        #[arg(long)]
        proof_root: String,
    },
    /// Always refused. The attestor is not a forge writer.
    Push,
}

fn main() -> ExitCode {
    match Args::parse().command {
        Command::Push => refuse(attestor_push().expect_err("push is always refused")),
        Command::Attest {
            credential_file,
            sha,
            name,
            proof_root,
        } => match AttestorCredential::load(&credential_file) {
            Ok(credential) => {
                let publication = CheckPublication {
                    sha: sha.clone(),
                    name,
                    proof_root,
                };
                match attest(&credential, &publication, &sha) {
                    Ok(receipt) => {
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::json!({
                                "sha": receipt.sha,
                                "name": receipt.name,
                                "proof_root": receipt.proof_root,
                                "produced_by": "bullet-attestor",
                            }))
                            .expect("receipt encodes")
                        );
                        ExitCode::SUCCESS
                    }
                    Err(error) => refuse(error),
                }
            }
            Err(error) => refuse(error),
        },
    }
}

fn refuse(error: bullet_effects_core::EffectsError) -> ExitCode {
    eprintln!(
        "{}",
        serde_json::json!({
            "reason_code": error.reason_code(),
            "message": error.to_string(),
        })
    );
    ExitCode::from(2)
}
