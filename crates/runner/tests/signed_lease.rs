//! Feature-gated simulator: permit required; unsigned HTTP unused.

use bullet_application::store::ProjectionReader;
use bullet_application::{materialize_plan, MemoryLedger, PlanInput};
use bullet_domain::{AttemptState, RunnerId, TaskClass};
use bullet_harness_core::lease_transport::LeaseTransportSigningKey;
use bullet_runner_core::{
    AcquireRequest, HeartbeatCall, LeaseClient, ReleaseCall, RunnerError, SignedLeaseClient,
};
use std::sync::{Arc, Mutex};

fn seeded() -> (Arc<Mutex<MemoryLedger>>, AcquireRequest) {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let graph = materialize_plan(
        &mut ledger,
        "signed-client",
        &PlanInput {
            title: "signed client".into(),
            objective: "permit then mutate".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        &now,
    )
    .unwrap();
    let request = AcquireRequest {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("signed-runner"),
        runner_epoch: 1,
        idempotency_key: "client-once".into(),
        ttl_seconds: 15,
    };
    (Arc::new(Mutex::new(ledger)), request)
}

#[tokio::test]
async fn signed_acquire_heartbeat_and_release() {
    let (ledger, request) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let client = SignedLeaseClient::new(ledger.clone(), key).unwrap();
    let grant = client.acquire(&request).await.unwrap();
    assert_eq!(grant.lease.runner_id, request.runner_id);
    client
        .heartbeat(&HeartbeatCall::for_grant(&grant).unwrap())
        .await
        .unwrap();
    client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Failed,
            requeue: false,
        })
        .await
        .unwrap();
    assert!(ledger.lock().unwrap().list_leases().unwrap().is_empty());
}

#[tokio::test]
async fn signed_advance_is_refused() {
    let (ledger, request) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let client = SignedLeaseClient::new(ledger, key).unwrap();
    let grant = client.acquire(&request).await.unwrap();
    let error = client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap_err();
    match error {
        RunnerError::Lease { code, .. } => {
            assert_eq!(code, "LEASE_TRANSPORT_UNSUPPORTED");
        }
        other => panic!("expected lease refusal, got {other:?}"),
    }
}
