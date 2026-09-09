//! Kernel-side launch-grant issuer. Every lease-binding claim is read from
//! the durable active lease inside the coherent lease check; the caller only
//! supplies the evaluated provider facts, the sandbox digests, and budgets.

use super::nonce::{LaunchGrantNonceRecord, LaunchGrantNonceStore};
use crate::authority::ActiveLeaseSubject;
use crate::graph_delta::graph_digest;
use crate::leases::LeaseService;
use crate::store::{Ledger, LedgerError};
use bullet_domain::AttemptId;
use bullet_harness_core::launch_grant::{
    hash_canonical, is_lower_hex_64, random_hex_64, workspace_nonce_digest, LaunchGrantClaims,
    LaunchGrantSigningKey, LeaseBinding, PolicyBinding, SignedLaunchGrant, LAUNCH_GRANT_AUDIENCE,
    LAUNCH_GRANT_OPERATION, LAUNCH_GRANT_SCHEMA_VERSION, MAX_LAUNCH_GRANT_TTL_MS,
};
use bullet_harness_core::HarnessError;
use chrono::{DateTime, Utc};
use serde::Serialize;

/// Initial durable epoch written once into an empty `authority_revisions` row.
/// Grant minting reads [`crate::Ledger::current_authority`], never this constant.
pub const GENESIS_AUTHORITY_EPOCH: u64 = 1;
/// Initial freeze generation written with the genesis authority row.
pub const GENESIS_FREEZE_GENERATION: u64 = 0;
const BUDGET_RESERVATION_DOMAIN: &str = "launch-grant.budget-reservation.v1alpha1";

/// Caller-supplied half of a mint request. Lease facts are never accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchGrantRequest {
    /// Attempt whose durable lease the grant must bind.
    pub attempt_id: AttemptId,
    /// Provider wire name.
    pub provider: String,
    /// Adapter label.
    pub adapter: String,
    /// Authorized credential profile (`prf_` + 64 hex).
    pub provider_profile_id: String,
    /// Model label.
    pub model: String,
    /// Credential generation.
    pub credential_generation: u64,
    /// Protocol observed by the runtime probe.
    pub protocol: String,
    /// Absolute canonical executable path.
    pub executable_path: String,
    /// Exact executable digest.
    pub executable_digest: String,
    /// Exact descriptor digest.
    pub descriptor_digest: String,
    /// Exact capability digest.
    pub capability_digest: String,
    /// Sandbox manifest digest.
    pub sandbox_manifest_digest: String,
    /// Launch-grant environment digest of the evaluated child environment.
    pub environment_digest: String,
    /// 1..=16 unique gate identifiers.
    pub gate_ids: Vec<String>,
    /// Maximum provider invocations.
    pub max_invocations: u64,
    /// Maximum wall clock in milliseconds.
    pub max_wall_clock_ms: u64,
    /// Maximum spend in micro-USD.
    pub max_cost_micro_usd: u64,
    /// Requested window length; clamped to the lease and 15 s.
    pub ttl_ms: u64,
}

/// Issuer failure.
#[derive(Debug, thiserror::Error)]
pub enum LaunchGrantIssueError {
    /// Durable store failure or stale authority.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Claim shape, signing, or entropy failure.
    #[error(transparent)]
    Harness(#[from] HarnessError),
    /// Typed issuer refusal with no durable side effect.
    #[error("launch grant refused: {reason}")]
    Refused {
        /// Non-secret refusal detail.
        reason: String,
    },
}

impl LaunchGrantIssueError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Ledger(error) => error.reason_code(),
            Self::Harness(error) => error.reason_code(),
            Self::Refused { .. } => "LAUNCH_GRANT_REFUSED",
        }
    }
}

/// Mint port. Implementations bind the durable lease and persist the nonce.
pub trait LaunchGrantIssuer {
    /// Mint one grant for `request` at `now`.
    ///
    /// # Errors
    ///
    /// Typed refusal when the Attempt has no coherent active lease, the
    /// request is malformed, or persistence/signing fails.
    fn mint(
        &mut self,
        request: &LaunchGrantRequest,
        now: DateTime<Utc>,
    ) -> Result<SignedLaunchGrant, LaunchGrantIssueError>;
}

/// The durable lease facts a grant binds plus the lease expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableLeaseBinding {
    /// Fields read from the ledger.
    pub binding: LeaseBinding,
    /// Lease expiry as unix milliseconds.
    pub lease_expires_at_unix_ms: u64,
}

/// Read the coherent active lease for `attempt_id` and its graph facts.
///
/// # Errors
///
/// `StaleAuthority` (via the ledger) when no coherent active lease exists;
/// `Refused` when the Attempt or its graph is missing.
pub fn durable_lease_binding<L: Ledger>(
    ledger: &mut L,
    attempt_id: &AttemptId,
) -> Result<DurableLeaseBinding, LaunchGrantIssueError> {
    let attempt = ledger
        .get_attempt(attempt_id)?
        .ok_or_else(|| refused("attempt is not durable"))?;
    let lease = ledger
        .get_lease(&attempt.variant_id)?
        .ok_or_else(|| refused("attempt variant has no active lease"))?;
    if lease.attempt_id != attempt.id || lease.fence != attempt.fence {
        return Err(refused(
            "active lease is held by another attempt incarnation (stale fence)",
        ));
    }
    ledger.check_active_lease(&ActiveLeaseSubject::from_attempt(&attempt))?;
    let graph = ledger
        .list_missions()?
        .into_iter()
        .filter_map(|mission| ledger.get_graph(&mission.id).transpose())
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|graph| {
            graph
                .variants
                .iter()
                .any(|variant| variant.id == attempt.variant_id)
        })
        .ok_or_else(|| refused("attempt variant is not in any durable graph"))?;
    let lease_expires_at_unix_ms = rfc3339_unix_ms(&lease.expires_at)?;
    let authority = ledger.current_authority()?;
    Ok(DurableLeaseBinding {
        binding: LeaseBinding {
            mission_id: graph.mission.id.to_string(),
            repository_id: graph.mission.repository_id.to_string(),
            graph_revision_id: format!("grf_{}", graph_digest(&graph).to_hex()),
            work_package_id: attempt.work_package_id.to_string(),
            variant_id: attempt.variant_id.to_string(),
            attempt_id: attempt.id.to_string(),
            attempt_fence: attempt.fence,
            runner_id: attempt.runner_id.to_string(),
            runner_epoch: attempt.runner_epoch,
            workspace_id: attempt.workspace_id.to_string(),
            workspace_nonce_digest: workspace_nonce_digest(&attempt.workspace_nonce)?,
            authority_epoch: authority.authority_epoch(),
            freeze_generation: authority.freeze_generation(),
        },
        lease_expires_at_unix_ms,
    })
}

/// Issuer over one ledger, one operator key, and one loaded policy.
pub struct LedgerLaunchGrantIssuer<'a, L> {
    ledger: &'a mut L,
    key: &'a LaunchGrantSigningKey,
    policy: PolicyBinding,
}

impl<'a, L: Ledger + LaunchGrantNonceStore> LedgerLaunchGrantIssuer<'a, L> {
    /// Bind the issuer to its durable ledger, key, and policy facts.
    pub fn new(ledger: &'a mut L, key: &'a LaunchGrantSigningKey, policy: PolicyBinding) -> Self {
        Self {
            ledger,
            key,
            policy,
        }
    }
}

impl<L: Ledger + LaunchGrantNonceStore> LaunchGrantIssuer for LedgerLaunchGrantIssuer<'_, L> {
    fn mint(
        &mut self,
        request: &LaunchGrantRequest,
        now: DateTime<Utc>,
    ) -> Result<SignedLaunchGrant, LaunchGrantIssueError> {
        validate_request(request)?;
        let now_unix_ms = datetime_unix_ms(now)?;
        let durable = durable_lease_binding(self.ledger, &request.attempt_id)?;
        let requested_expiry = now_unix_ms
            .checked_add(request.ttl_ms)
            .ok_or_else(|| refused("grant expiry overflows"))?;
        let expires_at_unix_ms = requested_expiry.min(durable.lease_expires_at_unix_ms);
        if expires_at_unix_ms <= now_unix_ms {
            return Err(refused(
                "active lease expires before the grant window would open",
            ));
        }
        let grant_id = random_hex_64()?;
        let grant_nonce = random_hex_64()?;
        let lease = &durable.binding;
        let budget_reservation_id = hash_canonical(
            BUDGET_RESERVATION_DOMAIN,
            &BudgetReservationSubject {
                grant_id: &grant_id,
                attempt_id: &lease.attempt_id,
                attempt_fence: lease.attempt_fence,
                max_invocations: request.max_invocations,
                max_wall_clock_ms: request.max_wall_clock_ms,
                max_cost_micro_usd: request.max_cost_micro_usd,
            },
        )?;
        let claims = LaunchGrantClaims {
            schema_version: LAUNCH_GRANT_SCHEMA_VERSION.to_string(),
            grant_id: grant_id.clone(),
            audience: LAUNCH_GRANT_AUDIENCE.to_string(),
            operation: LAUNCH_GRANT_OPERATION.to_string(),
            issuer: self.key.issuer().to_string(),
            key_id: self.key.key_id().to_string(),
            issued_at_unix_ms: now_unix_ms,
            not_before_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            grant_nonce: grant_nonce.clone(),
            mission_id: lease.mission_id.clone(),
            repository_id: lease.repository_id.clone(),
            graph_revision_id: lease.graph_revision_id.clone(),
            work_package_id: lease.work_package_id.clone(),
            variant_id: lease.variant_id.clone(),
            attempt_id: lease.attempt_id.clone(),
            attempt_fence: lease.attempt_fence,
            runner_id: lease.runner_id.clone(),
            runner_epoch: lease.runner_epoch,
            workspace_id: lease.workspace_id.clone(),
            workspace_nonce_digest: lease.workspace_nonce_digest.clone(),
            authority_epoch: lease.authority_epoch,
            freeze_generation: lease.freeze_generation,
            provider: request.provider.clone(),
            adapter: request.adapter.clone(),
            provider_profile_id: request.provider_profile_id.clone(),
            model: request.model.clone(),
            credential_generation: request.credential_generation,
            protocol: request.protocol.clone(),
            executable_path: request.executable_path.clone(),
            executable_digest: request.executable_digest.clone(),
            descriptor_digest: request.descriptor_digest.clone(),
            capability_digest: request.capability_digest.clone(),
            policy_snapshot_digest: self.policy.policy_snapshot_digest.clone(),
            policy_generation: self.policy.policy_generation,
            sandbox_manifest_digest: request.sandbox_manifest_digest.clone(),
            environment_digest: request.environment_digest.clone(),
            gate_ids: request.gate_ids.clone(),
            budget_reservation_id,
            max_invocations: request.max_invocations,
            max_wall_clock_ms: request.max_wall_clock_ms,
            max_cost_micro_usd: request.max_cost_micro_usd,
        };
        claims.validate_shape()?;
        self.ledger
            .record_launch_grant_nonce(&LaunchGrantNonceRecord {
                grant_nonce,
                grant_id,
                attempt_id: request.attempt_id.clone(),
                attempt_fence: lease.attempt_fence,
                expires_at_unix_ms,
                issued_at: LeaseService::rfc3339(now),
            })?;
        Ok(self.key.sign(&claims)?)
    }
}

#[derive(Serialize)]
struct BudgetReservationSubject<'a> {
    grant_id: &'a str,
    attempt_id: &'a str,
    attempt_fence: u64,
    max_invocations: u64,
    max_wall_clock_ms: u64,
    max_cost_micro_usd: u64,
}

fn validate_request(request: &LaunchGrantRequest) -> Result<(), LaunchGrantIssueError> {
    if request.ttl_ms == 0 || request.ttl_ms > MAX_LAUNCH_GRANT_TTL_MS {
        return Err(refused("ttl_ms must be within 1..=15000"));
    }
    for (name, value) in [
        ("executable_digest", &request.executable_digest),
        ("descriptor_digest", &request.descriptor_digest),
        ("capability_digest", &request.capability_digest),
        ("sandbox_manifest_digest", &request.sandbox_manifest_digest),
        ("environment_digest", &request.environment_digest),
    ] {
        if !is_lower_hex_64(value) {
            return Err(refused(&format!(
                "{name} must be 64 lowercase hex characters"
            )));
        }
    }
    Ok(())
}

/// Unix milliseconds of an RFC 3339 instant.
///
/// # Errors
///
/// `Refused` for an unparseable or pre-epoch instant.
pub fn rfc3339_unix_ms(value: &str) -> Result<u64, LaunchGrantIssueError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| refused("active lease expiry is not RFC 3339"))?;
    u64::try_from(parsed.timestamp_millis()).map_err(|_| refused("instant precedes the epoch"))
}

/// Unix milliseconds of a UTC instant.
///
/// # Errors
///
/// `Refused` for a pre-epoch instant.
pub fn datetime_unix_ms(value: DateTime<Utc>) -> Result<u64, LaunchGrantIssueError> {
    u64::try_from(value.timestamp_millis()).map_err(|_| refused("instant precedes the epoch"))
}

fn refused(reason: &str) -> LaunchGrantIssueError {
    LaunchGrantIssueError::Refused {
        reason: reason.to_string(),
    }
}
