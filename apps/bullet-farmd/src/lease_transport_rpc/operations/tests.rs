use super::super::RpcRequest;
use super::*;
use bullet_application::lease_transport::AdvanceSettlementRequest;
use bullet_application::{materialize_plan, MemoryLedger, PlanInput};
use bullet_domain::TaskClass;

fn request<T: Serialize>(method: &str, body: &T) -> RpcRequest {
    RpcRequest {
        id: Some(1),
        method: method.into(),
        params: serde_json::to_value(body).unwrap(),
    }
}

#[test]
fn terminal_readback_has_a_distinct_exact_absence_code() {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let graph = materialize_plan(
        &mut ledger,
        "farmd-settlement-absence",
        &PlanInput {
            title: "settlement absence".into(),
            objective: "preserve terminal outcome truth".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        &now,
    )
    .unwrap();
    let runner = RunnerId::from_seed("farmd-settlement-absence-runner");
    let body = LeaseSettlementRequest::Advance(AdvanceSettlementRequest {
        acquire_request_digest: "a".repeat(64),
        work_package_id: graph.packages[0].id.clone(),
        runner_id: runner.clone(),
        runner_epoch: 3,
        idempotency_key: "farmd-settlement-absence-key".into(),
        variant_id: graph.variants[0].id.clone(),
        attempt_id: bullet_domain::AttemptId::from_seed("farmd-settlement-absence-key"),
        attempt_fence: 1,
        expected_state: bullet_domain::AttemptState::Starting,
        target_state: bullet_domain::AttemptState::Running,
    });
    let transport = KernelLeaseTransport::generate().unwrap();

    let missing = call(
        &mut ledger,
        &transport,
        &runner,
        3,
        &request("settlement_readback", &body),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(missing.0, "LEASE_TRANSPORT_SETTLEMENT_ABSENT");

    let wrong_peer = call(
        &mut ledger,
        &transport,
        &RunnerId::from_seed("another-runner"),
        3,
        &request("settlement_readback", &body),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(wrong_peer.0, "LEASE_TRANSPORT_SUBJECT_MISMATCH");
}

#[test]
fn active_readback_distinguishes_absent_row_from_unresolvable_graph() {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let graph = materialize_plan(
        &mut ledger,
        "farmd-grant-absence",
        &PlanInput {
            title: "grant absence".into(),
            objective: "preserve exact readback truth".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        &now,
    )
    .unwrap();
    let body = SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("farmd-grant-absence-runner"),
        runner_epoch: 3,
        idempotency_key: "farmd-grant-absence-key".into(),
        ttl_seconds: 15,
    };
    let transport = KernelLeaseTransport::generate().unwrap();

    let missing = call(
        &mut ledger,
        &transport,
        &body.runner_id,
        body.runner_epoch,
        &request("readback_active", &body),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(missing.0, "LEASE_TRANSPORT_GRANT_ABSENT");

    call(
        &mut ledger,
        &transport,
        &body.runner_id,
        body.runner_epoch,
        &request("acquire", &body),
    )
    .unwrap()
    .unwrap();
    let mut unavailable = ledger.get_graph(&graph.mission.id).unwrap().unwrap();
    unavailable.packages.clear();
    unavailable.variants.clear();
    ledger.put_graph(&unavailable).unwrap();

    let drift = call(
        &mut ledger,
        &transport,
        &body.runner_id,
        body.runner_epoch,
        &request("readback_active", &body),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(drift.0, "LEASE_NOT_ACTIVE");
    assert!(Ledger::get_lease(&ledger, &graph.variants[0].id)
        .unwrap()
        .is_some());
}
