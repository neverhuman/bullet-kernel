//! Exact selected-Variant acquisition seam for the synthetic dogfood fixture.

use super::grant_resolution::grant_truth_for_variant;
use super::{KernelLeaseTransport, SignedAcquireBody, SignedLeaseError};
use crate::records::LeaseGrant;
use crate::store::Ledger;
use bullet_domain::VariantId;
use bullet_harness_core::lease_transport::LeaseTransportOperation;

#[cfg(all(feature = "test-seams", debug_assertions))]
use crate::records::validate_lease_ttl;
#[cfg(all(feature = "test-seams", debug_assertions))]
use bullet_domain::{Digest, RunnerId, WorkPackageId};
#[cfg(all(feature = "test-seams", debug_assertions))]
use bullet_harness_core::launch_grant::{hash_canonical, is_lower_hex_64, MAX_SAFE_INTEGER};
#[cfg(all(feature = "test-seams", debug_assertions))]
use bullet_harness_core::lease_transport::LeaseTransportError;
#[cfg(all(feature = "test-seams", debug_assertions))]
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "test-seams", debug_assertions))]
const SELECTED_ACQUIRE_SCHEMA: &str = "bullet.synthetic-selected-acquire.component.v1";
#[cfg(all(feature = "test-seams", debug_assertions))]
const SELECTED_ACQUIRE_BINDING_DOMAIN: &str =
    "lease-transport.synthetic-selected-acquire.component.v1";
#[cfg(all(feature = "test-seams", debug_assertions))]
const SELECTED_KEY_PREFIX: &str = "synthetic-selected-v1:";
#[cfg(all(feature = "test-seams", debug_assertions))]
const MAX_SELECTED_KEY_BYTES: usize = 96;

/// Closed feature-only request for one synthetic selected-Variant acquire.
///
/// The caller supplies no idempotency key. The key is derived from the exact
/// selection subject, so the inner ordinary body cannot be rebound to another
/// selected Variant without failing [`Self::validate_binding`].
#[cfg(all(feature = "test-seams", debug_assertions))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticSelectedAcquireBody {
    schema_version: String,
    selection_digest: Digest,
    selected_variant_id: VariantId,
    binding_digest: String,
    inner: SignedAcquireBody,
}

#[cfg(all(feature = "test-seams", debug_assertions))]
#[derive(Serialize)]
struct SelectedAcquireBinding<'a> {
    schema_version: &'static str,
    selection_digest: &'a Digest,
    work_package_id: &'a WorkPackageId,
    runner_id: &'a RunnerId,
    runner_epoch: u64,
    selected_variant_id: &'a VariantId,
    ttl_seconds: i64,
}

#[cfg(all(feature = "test-seams", debug_assertions))]
impl SyntheticSelectedAcquireBody {
    /// Construct one exact selected-acquire request and derive its inner key.
    ///
    /// # Errors
    /// `INVALID_LEASE_TTL` outside `1..=15`, or `LEASE_TRANSPORT_INVALID`
    /// for an unbounded or placeholder subject.
    pub fn new(
        selection_digest: Digest,
        work_package_id: WorkPackageId,
        runner_id: RunnerId,
        runner_epoch: u64,
        selected_variant_id: VariantId,
        ttl_seconds: i64,
    ) -> Result<Self, SignedLeaseError> {
        validate_subject(&selection_digest, runner_epoch, ttl_seconds)?;
        let binding_digest = binding_digest(
            &selection_digest,
            &work_package_id,
            &runner_id,
            runner_epoch,
            &selected_variant_id,
            ttl_seconds,
        )?;
        let idempotency_key = format!("{SELECTED_KEY_PREFIX}{binding_digest}");
        let request = Self {
            schema_version: SELECTED_ACQUIRE_SCHEMA.into(),
            selection_digest,
            selected_variant_id,
            binding_digest,
            inner: SignedAcquireBody {
                work_package_id,
                runner_id,
                runner_epoch,
                idempotency_key,
                ttl_seconds,
            },
        };
        request.validate_binding()?;
        Ok(request)
    }

    /// Inner ordinary acquire body retained in the Runner recovery tag.
    #[must_use]
    pub fn inner(&self) -> &SignedAcquireBody {
        &self.inner
    }

    /// Exact selected Variant the Kernel must resolve transaction-locally.
    #[must_use]
    pub fn selected_variant_id(&self) -> &VariantId {
        &self.selected_variant_id
    }

    /// Immutable selection/plan subject bound into this request.
    #[must_use]
    pub fn selection_digest(&self) -> &Digest {
        &self.selection_digest
    }

    /// Domain-separated digest copied into the durable Runner intent.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    /// Recompute and validate the complete selected-acquire binding.
    ///
    /// # Errors
    /// Typed TTL or strict binding refusal. Validation grants no authority.
    pub fn validate_binding(&self) -> Result<(), SignedLeaseError> {
        if self.schema_version != SELECTED_ACQUIRE_SCHEMA {
            return Err(invalid("selected acquire schema is unsupported"));
        }
        validate_subject(
            &self.selection_digest,
            self.inner.runner_epoch,
            self.inner.ttl_seconds,
        )?;
        let expected = binding_digest(
            &self.selection_digest,
            &self.inner.work_package_id,
            &self.inner.runner_id,
            self.inner.runner_epoch,
            &self.selected_variant_id,
            self.inner.ttl_seconds,
        )?;
        if !is_lower_hex_64(&self.binding_digest) || self.binding_digest != expected {
            return Err(invalid("selected acquire binding digest differs"));
        }
        let key = format!("{SELECTED_KEY_PREFIX}{expected}");
        if key.len() > MAX_SELECTED_KEY_BYTES || self.inner.idempotency_key != key {
            return Err(invalid("selected acquire idempotency key differs"));
        }
        Ok(())
    }
}

#[cfg(all(feature = "test-seams", debug_assertions))]
fn validate_subject(
    selection_digest: &Digest,
    runner_epoch: u64,
    ttl_seconds: i64,
) -> Result<(), SignedLeaseError> {
    validate_lease_ttl(ttl_seconds).map_err(|error| SignedLeaseError::Ledger(error.into()))?;
    if selection_digest.as_bytes().iter().all(|byte| *byte == 0) || runner_epoch > MAX_SAFE_INTEGER
    {
        return Err(invalid("selected acquire subject is outside bounds"));
    }
    Ok(())
}

#[cfg(all(feature = "test-seams", debug_assertions))]
fn binding_digest(
    selection_digest: &Digest,
    work_package_id: &WorkPackageId,
    runner_id: &RunnerId,
    runner_epoch: u64,
    selected_variant_id: &VariantId,
    ttl_seconds: i64,
) -> Result<String, SignedLeaseError> {
    hash_canonical(
        SELECTED_ACQUIRE_BINDING_DOMAIN,
        &SelectedAcquireBinding {
            schema_version: SELECTED_ACQUIRE_SCHEMA,
            selection_digest,
            work_package_id,
            runner_id,
            runner_epoch,
            selected_variant_id,
            ttl_seconds,
        },
    )
    .map_err(|_| invalid("selected acquire binding could not be canonicalized"))
}

#[cfg(all(feature = "test-seams", debug_assertions))]
fn invalid(reason: &str) -> SignedLeaseError {
    SignedLeaseError::Transport(LeaseTransportError::Invalid {
        reason: reason.into(),
    })
}

impl KernelLeaseTransport {
    /// Acquire one explicitly selected member of a synthetic package.
    /// Available only to tests and `test-seams` builds.
    ///
    /// # Errors
    /// Typed transport, graph-membership, or ledger refusal.
    pub fn acquire_selected_variant<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAcquireBody,
        variant: &VariantId,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        let prepare = |txn: &dyn crate::store::LeaseTransportTxn| {
            grant_truth_for_variant(
                txn,
                LeaseTransportOperation::Acquire,
                body,
                variant,
                now_unix_ms,
            )
        };
        self.admit(ledger, prepare, |txn, expected, truth| {
            let grant = txn.acquire_lease(&truth.request)?;
            let record = truth.bind(grant)?;
            txn.put_transport_grant(&expected.idempotency_digest, &record)?;
            Ok(record.grant)
        })
    }
}

#[cfg(test)]
mod tests;
