//! Offline operator authority CLI: generate the launch-grant signing key and
//! mint one grant from the durable active lease. Neither command spawns a
//! provider, opens a socket, or accepts lease facts from the operator.

mod mint;

use bullet_harness_core::launch_grant::{signing_key_path, write_new_signing_key};
use chrono::Utc;
use clap::{Args, Subcommand};
use std::path::PathBuf;

const DEFAULT_ISSUER: &str = "bullet-kernel";
const DEFAULT_KEY_ID: &str = "launch-grant-alpha";
const KEY_VALIDITY_MS: u64 = 365 * 24 * 60 * 60 * 1000;
const KEY_RETENTION_GRACE_MS: u64 = 24 * 60 * 60 * 1000;

/// `bullet authority ...`
#[derive(Subcommand)]
pub(super) enum AuthorityCommands {
    /// Create `<data-dir>/authority/launch-grant.key` (0600) and print the
    /// `IssuerKeyV1` the operator must ratify into policy. Never overwrites.
    Keygen {
        /// Absolute Kernel data directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Issuer label recorded in policy and every grant.
        #[arg(long, default_value = DEFAULT_ISSUER)]
        issuer: String,
        /// Key label recorded in policy and every grant.
        #[arg(long, default_value = DEFAULT_KEY_ID)]
        key_id: String,
    },
    /// Mint one signed launch grant bound to the durable active lease of an
    /// Attempt and to an exact local conformance receipt. Never spawns.
    MintLaunchGrant(Box<MintArgs>),
}

/// Inputs for `mint-launch-grant`. Lease facts are read from the ledger.
#[derive(Args)]
pub(super) struct MintArgs {
    /// Absolute Kernel data directory holding ledger, key, and policy.
    #[arg(long)]
    pub(super) data_dir: PathBuf,
    /// Attempt (`atm_` + 64 hex) whose active lease the grant binds.
    #[arg(long)]
    pub(super) attempt: String,
    /// Absolute path to the `ProviderConformanceReceipt` JSON of the exact
    /// evaluated admission.
    #[arg(long)]
    pub(super) receipt: PathBuf,
    /// Provider wire name; must equal the receipt provider.
    #[arg(long)]
    pub(super) provider: String,
    /// Absolute canonical executable path; re-digested and matched.
    #[arg(long)]
    pub(super) executable: PathBuf,
    /// Credential profile id (`prf_` + 64 hex); must equal the receipt.
    #[arg(long)]
    pub(super) profile: String,
    /// Model label.
    #[arg(long)]
    pub(super) model: String,
    /// Adapter label (defaults to `<provider>-adapter`).
    #[arg(long)]
    pub(super) adapter: Option<String>,
    /// Credential material generation.
    #[arg(long, default_value_t = 1)]
    pub(super) credential_generation: u64,
    /// Digest of the sandbox manifest the child will run under.
    #[arg(long)]
    pub(super) sandbox_manifest_digest: String,
    /// `environment_digest` of the live admission's child environment.
    #[arg(long)]
    pub(super) environment_digest: String,
    /// Maximum provider invocations.
    #[arg(long)]
    pub(super) budget_invocations: u64,
    /// Maximum wall clock in milliseconds.
    #[arg(long)]
    pub(super) budget_wall_ms: u64,
    /// Maximum spend in micro-USD.
    #[arg(long)]
    pub(super) budget_cost_micro_usd: u64,
    /// Gate identifiers (`gat_` + 64 hex); repeatable, 1..=16.
    #[arg(long = "gate-id", required = true)]
    pub(super) gate_ids: Vec<String>,
    /// Grant window in milliseconds; clamped to the lease and 15000.
    #[arg(long, default_value_t = 15_000)]
    pub(super) ttl_ms: u64,
    /// Issuer label of the operator key.
    #[arg(long, default_value = DEFAULT_ISSUER)]
    pub(super) issuer: String,
    /// Key label of the operator key.
    #[arg(long, default_value = DEFAULT_KEY_ID)]
    pub(super) key_id: String,
}

pub(super) fn run(command: AuthorityCommands) -> Result<(), String> {
    match command {
        AuthorityCommands::Keygen {
            data_dir,
            issuer,
            key_id,
        } => keygen(&data_dir, &issuer, &key_id),
        AuthorityCommands::MintLaunchGrant(args) => mint::run(&args),
    }
}

fn keygen(data_dir: &std::path::Path, issuer: &str, key_id: &str) -> Result<(), String> {
    if !data_dir.is_absolute() {
        return Err("--data-dir must be absolute".into());
    }
    let key = write_new_signing_key(data_dir, issuer, key_id)
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    let now = u64::try_from(Utc::now().timestamp_millis())
        .map_err(|_| "system clock precedes the epoch".to_string())?;
    let expires = now + KEY_VALIDITY_MS;
    let issuer_key = serde_json::json!({
        "schema_version": "v1alpha1",
        "issuer": issuer,
        "key_id": key_id,
        "key_purpose": "authority-signing",
        "algorithm": "paseto-v4.public",
        "public_key": key.public_key_hex(),
        "audiences": ["provider-runner"],
        "activates_at_unix_ms": now,
        "expires_at_unix_ms": expires,
        "revoked_at_unix_ms": null,
        "retain_until_unix_ms": expires + KEY_RETENTION_GRACE_MS,
    });
    println!("key_file: {}", signing_key_path(data_dir).display());
    println!("public_key_hex: {}", key.public_key_hex());
    println!(
        "issuer_key_v1: {}",
        serde_json::to_string_pretty(&issuer_key).map_err(|error| error.to_string())?
    );
    eprintln!(
        "bullet: ratify the printed IssuerKeyV1 into a new policy generation; \
         v1alpha1 policy keeps live admission disabled regardless"
    );
    Ok(())
}
