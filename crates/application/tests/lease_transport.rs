//! Test-seam simulation of signed internal lease transport. Public routes
//! stay absent; a valid permit is required before the ledger mutates.

use bullet_application::lease_transport::{
    issue_operation_permit, issue_permit, SignedAcquireBody, SignedLeaseService,
};
use bullet_application::records::{HeartbeatRequest, ReleaseRequest};
use bullet_application::store::ProjectionReader;
use bullet_application::{materialize_plan, MemoryLedger, PlanInput};
use bullet_domain::{AttemptState, RunnerId, TaskClass, WorkPackageId};
use bullet_harness_core::lease_transport::{
    LeaseTransportOperation, LeaseTransportSigningKey, LEASE_TRANSPORT_AUDIENCE,
};

fn body(work_package_id: WorkPackageId) -> SignedAcquireBody {
    SignedAcquireBody {
        work_package_id,
        runner_id: RunnerId::from_seed("signed-runner"),
        runner_epoch: 1,
        idempotency_key: "acquire-once".into(),
        ttl_seconds: 15,
    }
}

fn seeded() -> (MemoryLedger, SignedAcquireBody) {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let graph = materialize_plan(
        &mut ledger,
        "signed-lease",
        &PlanInput {
            title: "signed lease".into(),
            objective: "permit then acquire".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        &now,
    )
    .unwrap();
    (ledger, body(graph.packages[0].id.clone()))
}

#[test]
fn acquire_then_readback_returns_the_same_grant() {
    let (mut ledger, body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let now = 1_700_000_000_000;
    let acquire = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    let first = service.acquire(&mut ledger, &acquire, &body, now).unwrap();
    let readback = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Readback,
        &body,
        now,
    )
    .unwrap();
    let second = service.readback(&readback, &body, now).unwrap();
    assert_eq!(first.attempt.id, second.attempt.id);
    assert_eq!(first.lease.fence, second.lease.fence);
}

#[test]
fn replayed_acquire_permit_does_not_mint_a_sibling() {
    let (mut ledger, body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let now = 1_700_000_000_000;
    let acquire = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    let first = service.acquire(&mut ledger, &acquire, &body, now).unwrap();
    let replayed = service
        .acquire(&mut ledger, &acquire, &body, now)
        .unwrap_err();
    assert_eq!(replayed.reason_code(), "LEASE_TRANSPORT_REPLAYED");
    let again = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    let replay = service.acquire(&mut ledger, &again, &body, now).unwrap();
    assert_eq!(first.attempt.id, replay.attempt.id);
}

#[test]
fn wrong_runner_is_refused_before_the_ledger_changes() {
    let (mut ledger, mut body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let now = 1_700_000_000_000;
    let acquire = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    body.runner_id = RunnerId::from_seed("other-runner");
    let error = service
        .acquire(&mut ledger, &acquire, &body, now)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_SUBJECT_MISMATCH");
    assert!(ledger.list_leases().unwrap().is_empty());
}

#[test]
fn acquire_permit_cannot_be_used_as_readback() {
    let (ledger, body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let now = 1_700_000_000_000;
    let acquire = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    let error = service.readback(&acquire, &body, now).unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_OPERATION_MISMATCH");
    assert!(ledger.list_leases().unwrap().is_empty());
}

#[test]
fn launch_grant_audience_is_rejected() {
    assert_eq!(LEASE_TRANSPORT_AUDIENCE, "lease-runner");
    assert_ne!(LEASE_TRANSPORT_AUDIENCE, "provider-runner");
}

#[test]
fn heartbeat_covers_the_six_column_request() {
    let (mut ledger, body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let now = 1_700_000_000_000;
    let acquire = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    let grant = service.acquire(&mut ledger, &acquire, &body, now).unwrap();
    let call = HeartbeatRequest {
        variant_id: grant.lease.variant_id.clone(),
        attempt_id: grant.lease.attempt_id.clone(),
        fence: grant.lease.fence,
        runner_id: grant.lease.runner_id.clone(),
        runner_epoch: grant.lease.runner_epoch,
        workspace_nonce: grant.lease.workspace_nonce,
        ttl_seconds: 15,
    };
    let permit = issue_operation_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Heartbeat,
        &call.runner_id,
        call.runner_epoch,
        body.work_package_id.as_str(),
        &body.idempotency_key,
        &call,
        now,
    )
    .unwrap();
    service
        .heartbeat(
            &mut ledger,
            &permit,
            &body.work_package_id,
            &body.idempotency_key,
            &call,
            now,
        )
        .unwrap();
}

#[test]
fn acquire_permit_cannot_heartbeat() {
    let (mut ledger, body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let now = 1_700_000_000_000;
    let acquire = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    let grant = service.acquire(&mut ledger, &acquire, &body, now).unwrap();
    let call = HeartbeatRequest {
        variant_id: grant.lease.variant_id.clone(),
        attempt_id: grant.lease.attempt_id.clone(),
        fence: grant.lease.fence,
        runner_id: grant.lease.runner_id.clone(),
        runner_epoch: grant.lease.runner_epoch,
        workspace_nonce: grant.lease.workspace_nonce,
        ttl_seconds: 15,
    };
    let error = service
        .heartbeat(
            &mut ledger,
            &acquire,
            &body.work_package_id,
            &body.idempotency_key,
            &call,
            now,
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_OPERATION_MISMATCH");
}

#[test]
fn signed_release_closes_the_lease() {
    let (mut ledger, body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let now = 1_700_000_000_000;
    let acquire = issue_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Acquire,
        &body,
        now,
    )
    .unwrap();
    let grant = service.acquire(&mut ledger, &acquire, &body, now).unwrap();
    let call = ReleaseRequest {
        variant_id: grant.lease.variant_id.clone(),
        attempt_id: grant.attempt.id.clone(),
        final_state: AttemptState::Failed,
        requeue: false,
    };
    let permit = issue_operation_permit(
        &key,
        &mut service,
        LeaseTransportOperation::Release,
        &body.runner_id,
        body.runner_epoch,
        body.work_package_id.as_str(),
        &body.idempotency_key,
        &call,
        now,
    )
    .unwrap();
    service
        .release(
            &mut ledger,
            &permit,
            &body.runner_id,
            body.runner_epoch,
            &body.work_package_id,
            &body.idempotency_key,
            &call,
            now,
        )
        .unwrap();
    assert!(ledger.list_leases().unwrap().is_empty());
}

#[test]
fn unsigned_envelope_is_refused() {
    let (mut ledger, body) = seeded();
    let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
    let mut service = SignedLeaseService::new(key.verification_key().unwrap());
    let permit = bullet_harness_core::lease_transport::SignedLeasePermit {
        schema_version: bullet_harness_core::lease_transport::LEASE_TRANSPORT_SCHEMA_VERSION
            .to_string(),
        issuer: key.issuer().to_string(),
        key_id: key.key_id().to_string(),
        paseto: "v4.public.not-a-signature".into(),
    };
    let error = service
        .acquire(&mut ledger, &permit, &body, 1_700_000_000_000)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_INVALID");
    assert!(ledger.list_leases().unwrap().is_empty());
}
