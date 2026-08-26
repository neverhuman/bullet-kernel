//! Launch-grant issuance port and nonce persistence port.
//!
//! The issuer mints only from the durable active lease (coherently checked
//! with the store's clock), binds caller-supplied provider facts, persists a
//! single-use nonce, and signs with the operator-held key. Verification lives
//! in `bullet_harness_core::launch_grant`; this crate supplies the durable
//! nonce store that makes replay refusal (`LAUNCH_GRANT_REPLAYED`) durable.

pub mod issuer;
pub mod nonce;

pub use bullet_harness_core::launch_grant::{
    verify_launch_grant, LaunchGrantClaims, LaunchGrantExpectation, LaunchGrantSigningKey,
    LaunchGrantVerificationKey, LeaseBinding, PolicyBinding, ProviderBinding, SignedLaunchGrant,
    VerifiedLaunchGrant,
};
pub use bullet_harness_core::ProviderProtocol;
pub use issuer::{
    datetime_unix_ms, durable_lease_binding, rfc3339_unix_ms, DurableLeaseBinding,
    LaunchGrantIssueError, LaunchGrantIssuer, LaunchGrantRequest, LedgerLaunchGrantIssuer,
    GENESIS_AUTHORITY_EPOCH, GENESIS_FREEZE_GENERATION,
};
pub use nonce::{
    classify_stored_nonce, LaunchGrantNonceRecord, LaunchGrantNonceStore, NonceConsumption,
    StoreNonceLedger, StoredLaunchGrantNonce,
};
