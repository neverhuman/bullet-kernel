//! Restart-safe acquire reconciliation shared by ordinary and selected seams.

use super::*;
use recovery::validate_grant;

impl SignedLeaseRpcClient {
    pub(super) async fn reconcile_acquire(
        &self,
        intent: AcquireIntent,
    ) -> Result<AcquireGrant, RunnerError> {
        let (meta, is_new) = self.reserve_tagged_intent(intent)?;
        let first = if is_new {
            Some(self.send_acquire(&meta).await)
        } else {
            None
        };
        match self.active_readback(&meta).await {
            Ok(grant) => return self.publish_grant(&meta, grant),
            Err(error) if Self::recorded_absence(&error) => {}
            Err(error) => return Err(Self::outcome_unknown(&error)),
        }
        if let Some(Err(refusal @ RunnerError::Lease { .. })) = first {
            self.forget_intent(&meta.body)?;
            return Err(refusal);
        }
        let replay = self.send_acquire(&meta).await;
        match self.active_readback(&meta).await {
            Ok(grant) => self.publish_grant(&meta, grant),
            Err(error) if Self::recorded_absence(&error) => {
                if let Err(refusal @ RunnerError::Lease { .. }) = replay {
                    self.forget_intent(&meta.body)?;
                    return Err(refusal);
                }
                Err(Self::outcome_unknown(&error))
            }
            Err(error) => Err(Self::outcome_unknown(&error)),
        }
    }

    async fn send_acquire(&self, meta: &AcquireMeta) -> Result<AcquireGrant, RunnerError> {
        match &meta.intent {
            AcquireIntent::Ordinary { .. } => self.call(meta.intent.method(), &meta.body).await,
            #[cfg(all(feature = "test-seams", debug_assertions))]
            AcquireIntent::SyntheticSelected { request, .. } => {
                self.call(meta.intent.method(), request).await
            }
        }
    }

    fn publish_grant(
        &self,
        meta: &AcquireMeta,
        grant: AcquireGrant,
    ) -> Result<AcquireGrant, RunnerError> {
        validate_grant(meta, &grant).map_err(|error| Self::outcome_unknown(&error))?;
        self.record_acquire_grant(&meta.body, grant.clone())
            .map_err(|error| Self::outcome_unknown(&error))?;
        Ok(grant)
    }

    fn outcome_unknown(error: &RunnerError) -> RunnerError {
        RunnerError::AcquireOutcomeUnknown {
            message: format!("active readback failed with {}", error.reason_code()),
        }
    }

    fn recorded_absence(error: &RunnerError) -> bool {
        matches!(
            error,
            RunnerError::Lease { code, .. } if code == "LEASE_TRANSPORT_GRANT_ABSENT"
        )
    }
}
