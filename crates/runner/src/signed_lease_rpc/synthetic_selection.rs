//! Debug-only exact selected-Variant acquire over the authenticated UDS.

use super::*;
use bullet_application::lease_transport::SyntheticSelectedAcquireBody;

impl SignedLeaseRpcClient {
    /// Acquire one exact synthetic Variant with a durably tagged recovery intent.
    ///
    /// # Errors
    /// Binding, recovery-custody, transport, reconciliation, or grant refusal.
    pub async fn acquire_synthetic_selected(
        &self,
        request: &SyntheticSelectedAcquireBody,
    ) -> Result<AcquireGrant, RunnerError> {
        let intent = AcquireIntent::synthetic(request.clone())?;
        self.reconcile_acquire(intent).await
    }
}
