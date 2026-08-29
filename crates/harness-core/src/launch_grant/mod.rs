//! Signed launch grants: the Kernel-issued, short-lived PASETO v4.public
//! authority that is the only evidence able to clear the
//! `SIGNED_ADMISSION_UNAVAILABLE` blocker in provider admission.
//!
//! Contract (shared with bullet-wire `authority::launch`): RFC 8785 payload of
//! `LaunchGrantClaims`, canonical footer
//! `{schema_version, issuer, key_id, purpose: "launch-grant-signing"}`, implicit
//! assertion `bullet-farm.launch-grant.v1alpha1`, TTL at most 15 s, audience
//! `provider-runner`, operation `launch-provider`. The verifier binds the exact
//! durable lease, the exact evaluated admission, the exact loaded policy, and a
//! single-use nonce. Policy v1alpha1 keeps `live_admission_enabled` false, so a
//! fully valid grant still ends in `POLICY_LIVE_ADMISSION_DISABLED` today.

pub mod canonical;
pub mod claims;
pub mod expectation;
pub mod keyfile;
pub mod keys;
pub mod nonce;
pub mod probe_grant;
pub mod verify;

pub use canonical::{
    canonical_json, decode_canonical, hash_canonical, hash_framed_bytes, is_lower_hex_64,
};
pub use claims::{
    protocol_of, validate_label, LaunchGrantClaims, SignedLaunchGrant, ENVIRONMENT_DOMAIN,
    LAUNCH_GRANT_AUDIENCE, LAUNCH_GRANT_CLAIMS_DOMAIN, LAUNCH_GRANT_ENVELOPE_DOMAIN,
    LAUNCH_GRANT_IMPLICIT_ASSERTION, LAUNCH_GRANT_KEY_PURPOSE, LAUNCH_GRANT_OPERATION,
    LAUNCH_GRANT_SCHEMA_VERSION, MAX_GATE_IDS, MAX_LAUNCH_GRANT_TTL_MS, MAX_SAFE_INTEGER,
    POLICY_SNAPSHOT_DOMAIN, WORKSPACE_NONCE_DOMAIN,
};
pub use expectation::{
    environment_digest, policy_snapshot_digest, workspace_nonce_digest, LaunchGrantExpectation,
    LeaseBinding, PolicyBinding, ProviderBinding,
};
pub use keyfile::{
    load_signing_key, signing_key_path, write_new_signing_key, LAUNCH_GRANT_KEY_FILE,
};
pub use keys::{
    LaunchGrantSigningKey, LaunchGrantVerificationKey, SIGNING_KEY_BYTES, VERIFICATION_KEY_BYTES,
};
pub use nonce::{LaunchGrantNonceLedger, MemoryNonceLedger, NonceConsumption};
pub use probe_grant::{
    mint_probe_grant, probe_grant_footer, verify_probe_grant, ProbeExpectation, ProbeGrantClaims,
    ProbeGrantError, ProbePurpose, SignedProbeGrant, MAX_PROBE_GRANT_TTL_MS, MAX_PROBE_TOKEN_BYTES,
    PROBE_GRANT_CLAIMS_DOMAIN, PROBE_GRANT_IMPLICIT_ASSERTION, PROBE_GRANT_KEY_PURPOSE,
    PROBE_GRANT_NONCE_SCOPE, PROBE_GRANT_SCHEMA,
};
pub use verify::{verify_launch_grant, VerifiedLaunchGrant};

/// Fill `bytes` from operating-system entropy.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` when the operating system refuses entropy.
pub fn fill_random(bytes: &mut [u8]) -> Result<(), crate::error::HarnessError> {
    getrandom::fill(bytes).map_err(|error| crate::error::HarnessError::LaunchGrantInvalid {
        reason: format!("operating-system entropy unavailable: {error}"),
    })
}

/// Fresh 64-hex identifier from 32 random bytes.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` when the operating system refuses entropy.
pub fn random_hex_64() -> Result<String, crate::error::HarnessError> {
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes)?;
    Ok(hex::encode(bytes))
}
