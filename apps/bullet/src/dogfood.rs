//! `bullet dogfood read-only`: compose one contained plan-mode turn.
//!
//! Not live-conformance. Issuer/key are operator-supplied and never default
//! to `launch-grant-alpha`. Exit 78 is designed-neutral.

use bullet_application::dogfood_produce::{
    produce_binding, produce_enrollment, produce_passport, produce_policy, EnrollmentFacts,
};
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
        /// Provider to dispatch: claude, codex, cursor, or antigravity.
        /// Only claude has a wired dogfood dispatch today; the rest refuse
        /// with DOGFOOD_PROVIDER_UNIMPLEMENTED until their M2 lanes land.
        #[arg(long, default_value = "claude")]
        provider: String,
        /// Absolute 0700 data directory.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Absolute 0600 v1alpha2 policy.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Absolute DogfoodBindingV1 JSON.
        #[arg(long)]
        binding: Option<PathBuf>,
        /// Absolute enrollment: `<data-dir>/policy/enrollments/<provider>.json`.
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
        /// Absolute owner-private snapshot directory (mode 0700) holding the
        /// exact subject the turn may read. Never the live family root: the
        /// filesystem validator denylists `/home/<user>/<dir>` roots including
        /// `/home/ubuntu/bullet`, so pass a private clone or snapshot instead.
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
    /// Produce the one admitted DogfoodBindingV1 document (canonical, 0600, create-once).
    ProduceBinding {
        /// Absolute output path.
        #[arg(long)]
        out: PathBuf,
    },
    /// Produce the v1alpha2 generation-2 dogfood policy from an operator base
    /// and the IssuerKeyV1 printed by `authority keygen`. live_admission stays false.
    ProducePolicy {
        /// Absolute operator-ratified base policy (v1alpha1 JSON).
        #[arg(long)]
        base: PathBuf,
        /// Absolute IssuerKeyV1 JSON saved from `authority keygen`.
        #[arg(long)]
        issuer_key: PathBuf,
        /// Absolute output path.
        #[arg(long)]
        out: PathBuf,
    },
    /// Produce `<data-dir>/policy/enrollments/<provider>.json` and prove it by
    /// loading it through the compose's own enrollment loader.
    ProduceEnrollment {
        /// Absolute 0700 data directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Provider name: claude, codex, cursor, or antigravity.
        #[arg(long)]
        provider: String,
        /// Absolute frozen executable (the staged deployment entrypoint).
        #[arg(long)]
        executable: PathBuf,
        /// Exact runtime version the operator observed and confirms.
        #[arg(long)]
        version: String,
        /// Frozen protocol wire label (e.g. claude_stream_json).
        #[arg(long)]
        protocol: String,
        /// Kernel profile id (`prf_` + 64 lowercase hex).
        #[arg(long)]
        profile_id: String,
        /// Tightest per-turn cost cap in micro-USD.
        #[arg(long)]
        budget_micro_usd_max: u64,
        /// Validity window in days from now (exclusive expiry).
        #[arg(long, default_value_t = 90)]
        valid_days: u64,
        /// Free-text author label; fixture identities are refused.
        #[arg(long)]
        enrolled_by: String,
    },
    /// Produce a canonical RuntimePassportV1 describing a staged deployment tree.
    ProducePassport {
        /// Absolute staged tree to walk (may differ from the final root).
        #[arg(long)]
        staged_root: PathBuf,
        /// Exact final immutable root (`/usr/lib/bullet/providers/<p>/<v>`).
        #[arg(long)]
        recorded_root: String,
        /// Provider wire name recorded in the passport.
        #[arg(long)]
        provider: String,
        /// Frozen protocol wire label.
        #[arg(long)]
        protocol: String,
        /// Exact packaged version (must equal the root's version segment).
        #[arg(long)]
        version: String,
        /// Root-relative entrypoint path.
        #[arg(long)]
        entrypoint: String,
        /// Absolute output path (install as `<recorded_root>.passport.json`).
        #[arg(long)]
        out: PathBuf,
    },
}

/// Dispatch `bullet dogfood`.
pub(crate) fn run(command: DogfoodCommands) -> ExitCode {
    match command {
        DogfoodCommands::ReadOnly {
            provider,
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
                provider,
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
        DogfoodCommands::ProduceBinding { out } => produced(produce_binding(&out)),
        DogfoodCommands::ProducePolicy {
            base,
            issuer_key,
            out,
        } => produced(produce_policy(&base, &issuer_key, &out)),
        DogfoodCommands::ProduceEnrollment {
            data_dir,
            provider,
            executable,
            version,
            protocol,
            profile_id,
            budget_micro_usd_max,
            valid_days,
            enrolled_by,
        } => {
            let now = unix_ms_now();
            let facts = EnrollmentFacts {
                provider,
                executable,
                version,
                protocol,
                profile_id,
                budget_micro_usd_max,
                valid_from_unix_ms: now,
                valid_until_unix_ms: now + valid_days * 24 * 60 * 60 * 1000,
                enrolled_by,
            };
            produced(produce_enrollment(&data_dir, &facts, now))
        }
        DogfoodCommands::ProducePassport {
            staged_root,
            recorded_root,
            provider,
            protocol,
            version,
            entrypoint,
            out,
        } => produced(produce_passport(
            &staged_root,
            &recorded_root,
            &provider,
            &protocol,
            &version,
            &entrypoint,
            &out,
        )),
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

fn produced(
    result: Result<String, bullet_application::dogfood_produce::DogfoodProduceError>,
) -> ExitCode {
    match result {
        Ok(digest) => {
            println!("{digest}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
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
