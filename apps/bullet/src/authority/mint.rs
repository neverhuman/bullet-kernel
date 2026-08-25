//! `bullet authority mint-launch-grant`: policy (reported on stderr with its
//! schema version and generation, and required to be active now), operator
//! key, exact receipt, durable lease, then one signed grant on stdout. No
//! process is spawned.

use super::MintArgs;
use bullet_adapters::SqliteLedger;
use bullet_application::launch_grant::{
    LaunchGrantIssuer, LaunchGrantRequest, LedgerLaunchGrantIssuer,
};
use bullet_application::policy_snapshot::load_policy_from_environment;
use bullet_domain::AttemptId;
use bullet_harness_core::launch_grant::{load_signing_key, LAUNCH_GRANT_AUDIENCE};
use bullet_harness_core::{executable_digest, ProviderConformanceReceipt};
use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

pub(super) fn run(args: &MintArgs) -> Result<(), String> {
    if !args.data_dir.is_absolute() || !args.receipt.is_absolute() || !args.executable.is_absolute()
    {
        return Err("--data-dir, --receipt, and --executable must be absolute".into());
    }
    let now = Utc::now();
    let now_unix_ms = u64::try_from(now.timestamp_millis())
        .map_err(|_| "system clock precedes the epoch".to_string())?;
    let policy = load_policy_from_environment(&args.data_dir).map_err(coded)?;
    eprintln!(
        "bullet: policy schema_version={} generation={} live_admission_enabled={} digest={}",
        policy.schema().as_str(),
        policy.generation(),
        policy.live_admission_enabled(),
        policy.digest()
    );
    policy.validate_at(now_unix_ms).map_err(coded)?;
    let key = load_signing_key(&args.data_dir, &args.issuer, &args.key_id).map_err(coded)?;
    let admitted = policy
        .authority_key_at(
            &args.issuer,
            &args.key_id,
            LAUNCH_GRANT_AUDIENCE,
            now_unix_ms,
        )
        .map_err(coded)?;
    if admitted.public_key_hex() != key.public_key_hex() {
        return Err(format!(
            "LAUNCH_GRANT_KEY_UNKNOWN: operator key {}/{} does not match the policy-admitted public key",
            args.issuer, args.key_id
        ));
    }
    let receipt = load_receipt(&args.receipt)?;
    let executable = args.executable.to_string_lossy().into_owned();
    if receipt.provider != args.provider
        || receipt.executable != executable
        || receipt.profile_id != args.profile
    {
        return Err(
            "ADMISSION_REFUSED: receipt provider, executable, or profile differs from the request"
                .into(),
        );
    }
    let digest = executable_digest(&args.executable).map_err(coded)?;
    if digest != receipt.executable_blake3 {
        return Err("ADMISSION_REFUSED: executable bytes differ from the receipt".into());
    }
    let attempt_id =
        AttemptId::parse(&args.attempt).map_err(|error| format!("INVALID_ID: {error}"))?;
    let request = LaunchGrantRequest {
        attempt_id,
        provider: receipt.provider.clone(),
        adapter: args
            .adapter
            .clone()
            .unwrap_or_else(|| format!("{}-adapter", receipt.provider)),
        provider_profile_id: receipt.profile_id.clone(),
        model: args.model.clone(),
        credential_generation: args.credential_generation,
        protocol: receipt.current_protocol.as_str().to_string(),
        executable_path: executable,
        executable_digest: receipt.executable_blake3.clone(),
        descriptor_digest: receipt.descriptor_blake3.clone(),
        capability_digest: receipt.capability_blake3.clone(),
        sandbox_manifest_digest: args.sandbox_manifest_digest.clone(),
        environment_digest: args.environment_digest.clone(),
        gate_ids: args.gate_ids.clone(),
        max_invocations: args.budget_invocations,
        max_wall_clock_ms: args.budget_wall_ms,
        max_cost_micro_usd: args.budget_cost_micro_usd,
        ttl_ms: args.ttl_ms,
    };
    let mut ledger = SqliteLedger::open(args.data_dir.join("ledger.sqlite"))
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    let mut issuer = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy.binding());
    let grant = issuer
        .mint(&request, now)
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&grant).map_err(|error| error.to_string())?
    );
    if !policy.live_admission_enabled() {
        eprintln!(
            "bullet: policy generation {} keeps sandbox_policy.live_admission_enabled = false; \
             this grant will be refused as POLICY_LIVE_ADMISSION_DISABLED at admission",
            policy.generation()
        );
    }
    Ok(())
}

fn load_receipt(path: &Path) -> Result<ProviderConformanceReceipt, String> {
    let bytes = read_regular_bounded(path)?;
    let receipt: ProviderConformanceReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| format!("ADMISSION_REFUSED: invalid conformance receipt: {error}"))?;
    receipt.verify().map_err(coded)?;
    Ok(receipt)
}

#[cfg(unix)]
fn read_regular_bounded(path: &Path) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open receipt without following symlinks: {error}"))?;
    if !input
        .metadata()
        .map_err(|error| format!("inspect receipt: {error}"))?
        .is_file()
    {
        return Err("receipt is not a regular file".into());
    }
    let mut bytes = Vec::new();
    input
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read receipt: {error}"))?;
    if u64::try_from(bytes.len()).map_err(|error| error.to_string())? > MAX_RECEIPT_BYTES {
        return Err(format!("receipt exceeds {MAX_RECEIPT_BYTES} bytes"));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_regular_bounded(_path: &Path) -> Result<Vec<u8>, String> {
    Err("safe receipt admission is unsupported on this platform".into())
}

fn coded(error: bullet_harness_core::HarnessError) -> String {
    format!("{}: {error}", error.reason_code())
}
