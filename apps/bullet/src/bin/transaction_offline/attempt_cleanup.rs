//! Durable authority cleanup for a failed first offline Attempt.

use super::support::{fail, LeaseHeartbeatGuard};
use bullet_adapters::SqliteLedger;
use bullet_application::Ledger;
use bullet_domain::AttemptState;
use bullet_runner_core::lease::{AcquireGrant, LeaseClient, ReleaseCall};
use bullet_runner_core::SignedLeaseRpcClient;
use std::path::Path;
use std::sync::Arc;

pub(super) async fn cleanup_failed_attempt(
    heartbeat: Option<LeaseHeartbeatGuard>,
    client: &Arc<SignedLeaseRpcClient>,
    database: &Path,
    grant: &AcquireGrant,
) -> Result<(), String> {
    settle_attempt(heartbeat, client, database, grant, AttemptState::Cancelled).await
}

pub(super) async fn settle_attempt(
    heartbeat: Option<LeaseHeartbeatGuard>,
    client: &Arc<SignedLeaseRpcClient>,
    database: &Path,
    grant: &AcquireGrant,
    outcome: AttemptState,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Some(heartbeat) = heartbeat {
        if let Err(error) = heartbeat.stop().await {
            errors.push(format!("stop failed Attempt heartbeat: {error}"));
        }
    }
    if let Err(error) = client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome,
            requeue: true,
        })
        .await
    {
        errors.push(format!("cancel failed Attempt lease: {error}"));
    }
    match SqliteLedger::open(database) {
        Err(error) => errors.push(format!("reopen failed Attempt ledger: {error}")),
        Ok(ledger) => {
            match ledger.get_lease(&grant.lease.variant_id) {
                Ok(None) => {}
                Ok(Some(_)) => errors.push("failed Attempt lease remained active".into()),
                Err(error) => errors.push(format!("read failed Attempt active lease: {error}")),
            }
            match ledger.get_attempt(&grant.attempt.id) {
                Ok(Some(attempt)) if attempt.state == outcome => {}
                Ok(Some(attempt)) => errors.push(format!(
                    "settled Attempt ended as {:?}, expected {outcome:?}",
                    attempt.state,
                )),
                Ok(None) => errors.push("settled Attempt disappeared".into()),
                Err(error) => errors.push(format!("read settled Attempt: {error}")),
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(fail(errors.join("; ")))
    }
}

pub(super) async fn failed_attempt(
    heartbeat: Option<LeaseHeartbeatGuard>,
    client: &Arc<SignedLeaseRpcClient>,
    database: &Path,
    grant: &AcquireGrant,
    failure: String,
) -> String {
    match cleanup_failed_attempt(heartbeat, client, database, grant).await {
        Ok(()) => failure,
        Err(cleanup) => fail(format!("{failure}; failure cleanup failed: {cleanup}")),
    }
}
