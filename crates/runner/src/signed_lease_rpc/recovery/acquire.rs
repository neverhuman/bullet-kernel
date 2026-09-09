//! Closed acquire-intent identity persisted before the first socket write.

#[cfg(all(feature = "test-seams", debug_assertions))]
use super::rpc_err;
use super::validate_body;
use crate::RunnerError;
use bullet_application::lease_transport::SignedAcquireBody;
#[cfg(all(feature = "test-seams", debug_assertions))]
use bullet_application::lease_transport::SyntheticSelectedAcquireBody;
use bullet_domain::{RunnerId, VariantId};
use bullet_harness_core::lease_transport::request_digest;

/// Durable method discriminator. Recovery never infers this from a key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::signed_lease_rpc) enum AcquireIntent {
    /// Ordinary package acquisition; the Kernel must resolve exactly one Variant.
    Ordinary {
        /// Exact body persisted before send.
        body: SignedAcquireBody,
    },
    /// Debug-only exact selected-Variant acquisition.
    #[cfg(all(feature = "test-seams", debug_assertions))]
    SyntheticSelected {
        /// Canonical selected request.
        request: Box<SyntheticSelectedAcquireBody>,
        /// Redundant inner body, cross-checked on every load.
        body: SignedAcquireBody,
        /// Redundant binding digest, cross-checked on every load.
        binding_digest: String,
    },
}

impl AcquireIntent {
    pub(in crate::signed_lease_rpc) fn ordinary(body: SignedAcquireBody) -> Self {
        Self::Ordinary { body }
    }

    #[cfg(all(feature = "test-seams", debug_assertions))]
    pub(in crate::signed_lease_rpc) fn synthetic(
        request: SyntheticSelectedAcquireBody,
    ) -> Result<Self, RunnerError> {
        request.validate_binding().map_err(application_refusal)?;
        Ok(Self::SyntheticSelected {
            body: request.inner().clone(),
            binding_digest: request.binding_digest().to_string(),
            request: Box::new(request),
        })
    }

    pub(in crate::signed_lease_rpc) fn body(&self) -> &SignedAcquireBody {
        match self {
            Self::Ordinary { body } => body,
            #[cfg(all(feature = "test-seams", debug_assertions))]
            Self::SyntheticSelected { body, .. } => body,
        }
    }

    pub(in crate::signed_lease_rpc) fn method(&self) -> &'static str {
        match self {
            Self::Ordinary { .. } => "acquire",
            #[cfg(all(feature = "test-seams", debug_assertions))]
            Self::SyntheticSelected { .. } => "synthetic_acquire_selected_variant",
        }
    }

    pub(in crate::signed_lease_rpc) fn expected_variant(&self) -> Option<&VariantId> {
        match self {
            Self::Ordinary { .. } => None,
            #[cfg(all(feature = "test-seams", debug_assertions))]
            Self::SyntheticSelected { request, .. } => Some(request.selected_variant_id()),
        }
    }

    pub(in crate::signed_lease_rpc) fn digest(&self) -> Result<String, RunnerError> {
        request_digest(self)
            .map_err(|error| RunnerError::Protocol(format!("acquire intent digest: {error}")))
    }

    pub(in crate::signed_lease_rpc) fn validate(
        &self,
        runner: &RunnerId,
        epoch: u64,
    ) -> Result<(), RunnerError> {
        validate_body(self.body(), runner, epoch)?;
        match self {
            Self::Ordinary { .. } => Ok(()),
            #[cfg(all(feature = "test-seams", debug_assertions))]
            Self::SyntheticSelected {
                request,
                body,
                binding_digest,
            } => {
                request.validate_binding().map_err(application_refusal)?;
                if request.inner() == body && request.binding_digest() == binding_digest {
                    Ok(())
                } else {
                    Err(rpc_err(
                        "LEASE_RECOVERY_CORRUPT",
                        "selected acquire intent binding differs from its durable body",
                    ))
                }
            }
        }
    }
}

#[cfg(all(feature = "test-seams", debug_assertions))]
fn application_refusal(
    error: bullet_application::lease_transport::SignedLeaseError,
) -> RunnerError {
    rpc_err(error.reason_code(), &error.to_string())
}
