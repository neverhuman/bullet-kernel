//! Independent attestor process boundary. Production publication stays
//! unavailable until an authenticated forge adapter, attestor signature, and
//! exact read-back are wired.

use bullet_effects_core::{
    attestor_push, validate_attestation_request, AttestorCredential, CheckPublication, EffectsError,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "bullet-attestor",
    about = "Attestor boundary; production forge transport is not yet admitted"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a check subject, then refuse until forge transport is admitted.
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
                if let Err(error) = validate_attestation_request(&credential, &publication, &sha) {
                    return refuse(error);
                }
                refuse(EffectsError::LiveAdmissionUnavailable(
                    "no authenticated attestor forge adapter, signature, and exact read-back are configured"
                        .into(),
                ))
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
