//! `bullet dogfood read-only`: compose one contained plan-mode turn.
//!
//! Not live-conformance. Issuer/key are operator-supplied and never default
//! to `launch-grant-alpha`. Exit 78 is designed-neutral.

use bullet_application::{
    run_dogfood_read_only, CredentialSpec, DogfoodReadOnlyOptions, DogfoodRunStatus,
};
use clap::Subcommand;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub(crate) enum DogfoodCommands {
    /// One contained read-only propose. Never applies.
    ReadOnly {
        /// Absolute 0700 data directory.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Absolute 0600 v1alpha2 policy.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Absolute DogfoodBindingV1 JSON.
        #[arg(long)]
        binding: Option<PathBuf>,
        /// Absolute enrollment; must be `<data-dir>/policy/enrollments/claude.json`.
        #[arg(long)]
        enrollment: Option<PathBuf>,
        /// Operator issuer. Never hardcoded.
        #[arg(long)]
        issuer: Option<String>,
        /// Operator key id. Live-conformance fixture keys are refused.
        #[arg(long)]
        key_id: Option<String>,
        /// Absolute enrolled executable.
        #[arg(long)]
        executable: Option<PathBuf>,
        /// Repeatable `source,target,blake3` grants.
        #[arg(long = "credential")]
        credentials: Vec<String>,
        /// Absolute family working directory.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// Plan-mode prompt.
        #[arg(long)]
        prompt: Option<String>,
        /// Optional USD cap at or below the enrollment max.
        #[arg(long)]
        max_budget_usd: Option<f64>,
        /// Create-once receipt path.
        #[arg(long)]
        receipt: Option<PathBuf>,
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Dispatch `bullet dogfood`.
pub(crate) fn run(command: DogfoodCommands) -> ExitCode {
    match command {
        DogfoodCommands::ReadOnly {
            data_dir,
            policy,
            binding,
            enrollment,
            issuer,
            key_id,
            executable,
            credentials,
            workdir,
            prompt,
            max_budget_usd,
            receipt,
            json,
        } => {
            if let Some(code) = missing(
                json,
                &[
                    ("data-dir", data_dir.is_some()),
                    ("policy", policy.is_some()),
                    ("binding", binding.is_some()),
                    ("enrollment", enrollment.is_some()),
                    (
                        "issuer",
                        issuer.as_ref().is_some_and(|value| !value.is_empty()),
                    ),
                    (
                        "key-id",
                        key_id.as_ref().is_some_and(|value| !value.is_empty()),
                    ),
                    ("executable", executable.is_some()),
                    ("workdir", workdir.is_some()),
                    ("receipt", receipt.is_some()),
                ],
            ) {
                return code;
            }
            let credentials = match parse_credentials(&credentials) {
                Ok(credentials) => credentials,
                Err(detail) => {
                    return fail(json, "DOGFOOD_CREDENTIAL", &detail);
                }
            };
            let options = DogfoodReadOnlyOptions {
                data_dir: data_dir.expect("checked"),
                policy: policy.expect("checked"),
                binding: binding.expect("checked"),
                enrollment: enrollment.expect("checked"),
                issuer: issuer.expect("checked"),
                key_id: key_id.expect("checked"),
                executable: executable.expect("checked"),
                credentials,
                workdir: workdir.expect("checked"),
                prompt,
                max_budget_usd,
                receipt: receipt.expect("checked"),
            };
            match run_dogfood_read_only(options) {
                Ok(DogfoodRunStatus::Succeeded { receipt, proposal }) => {
                    emit(
                        json,
                        0,
                        json!({
                            "ok": true,
                            "receipt": receipt,
                            "proposal": proposal,
                            "applied": false,
                            "eligibility": false
                        }),
                    );
                    eprintln!("proposal: {}", proposal.display());
                    eprintln!("receipt: {}", receipt.display());
                    ExitCode::SUCCESS
                }
                Ok(DogfoodRunStatus::Neutral { code, detail }) => {
                    emit(
                        json,
                        78,
                        json!({ "ok": false, "code": code, "detail": detail }),
                    );
                    ExitCode::from(78)
                }
                Err(error) => fail(json, error.code, &error.detail),
            }
        }
    }
}

fn parse_credentials(values: &[String]) -> Result<Vec<CredentialSpec>, String> {
    let mut grants = Vec::new();
    for value in values {
        let parts: Vec<&str> = value.splitn(3, ',').collect();
        if parts.len() != 3 {
            return Err("credential must be source,target,blake3".into());
        }
        grants.push(CredentialSpec {
            source: PathBuf::from(parts[0]),
            target: PathBuf::from(parts[1]),
            blake3: parts[2].to_owned(),
        });
    }
    Ok(grants)
}

fn missing(json_out: bool, fields: &[(&str, bool)]) -> Option<ExitCode> {
    for (name, present) in fields {
        if !present {
            emit(
                json_out,
                78,
                json!({
                    "ok": false,
                    "code": "DOGFOOD_INPUT_MISSING",
                    "detail": format!("{name} is required")
                }),
            );
            return Some(ExitCode::from(78));
        }
    }
    None
}

fn fail(json_out: bool, code: &str, detail: &str) -> ExitCode {
    emit(
        json_out,
        1,
        json!({ "ok": false, "code": code, "detail": detail }),
    );
    ExitCode::FAILURE
}

fn emit(json_out: bool, _exit: u8, value: serde_json::Value) {
    if json_out {
        println!("{value}");
    } else {
        eprintln!("bullet: {value}");
    }
}

#[cfg(test)]
mod tests {
    use super::parse_credentials;

    #[test]
    fn credential_spec_is_source_target_blake3() {
        let grants = parse_credentials(&["/abs/src,.config/oauth,aa".into()]).unwrap();
        assert_eq!(grants[0].target.to_str(), Some(".config/oauth"));
        assert!(parse_credentials(&["only-two,parts".into()]).is_err());
    }
}
