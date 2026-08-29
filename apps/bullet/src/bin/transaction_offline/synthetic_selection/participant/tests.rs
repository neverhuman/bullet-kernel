use super::*;
use bullet_application::{
    materialize_synthetic_selection, LeaseRequest, LeaseService, Ledger, MemoryLedger, PlanInput,
};
use bullet_domain::{Digest, TaskClass, WorkPackageId, WorkspaceId};
use bullet_runner_core::ExpectedLeaseServer;

struct Fixture {
    _root: tempfile::TempDir,
    participant: SelectionParticipantClient,
    selected: SyntheticSelectedAcquireBody,
    request: AcquireRequest,
    grant: AcquireGrant,
}

fn fixture() -> Fixture {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let graph = materialize_synthetic_selection(
        &mut ledger,
        "participant-hostile",
        &PlanInput {
            title: "participant hostile".into(),
            objective: "prove cached selected grant boundaries".into(),
            packages: vec![("one".into(), TaskClass::BoundedBugFix)],
        },
        &now,
    )
    .expect("graph");
    let selected = SyntheticSelectedAcquireBody::new(
        Digest::of(b"participant-plan"),
        graph.packages[0].id.clone(),
        bullet_domain::RunnerId::from_seed("participant-runner"),
        4,
        graph.variants[0].id.clone(),
        9,
    )
    .expect("selected");
    let body = selected.inner();
    let acquired = ledger
        .acquire_lease(&LeaseRequest {
            idempotency_key: body.idempotency_key.clone(),
            mission_id: graph.mission.id.clone(),
            variant_id: selected.selected_variant_id().clone(),
            attempt_seed: body.idempotency_key.clone(),
            runner_id: body.runner_id.clone(),
            runner_epoch: body.runner_epoch,
            workspace_id: WorkspaceId::from_seed(&body.idempotency_key),
            workspace_nonce: *Digest::of(body.idempotency_key.as_bytes()).as_bytes(),
            scope_revision: 1,
            context_revision: 1,
            ttl_seconds: body.ttl_seconds,
        })
        .expect("grant");
    let grant = AcquireGrant {
        authority_token: LeaseService::token_for(&graph, &acquired.attempt).expect("token"),
        attempt: acquired.attempt,
        lease: acquired.lease,
    };
    let request = AcquireRequest {
        work_package_id: body.work_package_id.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        idempotency_key: body.idempotency_key.clone(),
        ttl_seconds: body.ttl_seconds,
    };
    let root = tempfile::tempdir().expect("tempdir");
    let signed = Arc::new(SignedLeaseRpcClient::new_admitted(
        root.path().join("absent.sock"),
        body.runner_id.clone(),
        body.runner_epoch,
        ExpectedLeaseServer::new(0, 0),
    ));
    let participant = SelectionParticipantClient::new(signed, selected.clone()).expect("client");
    Fixture {
        _root: root,
        participant,
        selected,
        request,
        grant,
    }
}

fn prime(fixture: &Fixture) {
    let mut state = fixture.participant.lock().expect("state");
    state.phase = Phase::Primed;
    state.current = Some(AttemptState::Starting);
    state.grant = Some(fixture.grant.clone());
}

fn lease_code(error: &RunnerError) -> &str {
    match error {
        RunnerError::Lease { code, .. } => code,
        other => panic!("expected lease refusal, found {other}"),
    }
}

#[tokio::test]
async fn unprimed_acquire_and_abort_refuse_before_socket() {
    let fixture = fixture();
    let acquire = fixture
        .participant
        .acquire(&fixture.request)
        .await
        .expect_err("unprimed acquire");
    assert_eq!(lease_code(&acquire), PARTICIPANT_REFUSED);
    let abort = fixture
        .participant
        .abort_primed_failed()
        .await
        .expect_err("unprimed abort");
    assert_eq!(lease_code(&abort), PARTICIPANT_REFUSED);
}

#[tokio::test]
async fn cached_grant_is_consumed_exactly_once() {
    let fixture = fixture();
    prime(&fixture);
    assert_eq!(
        fixture
            .participant
            .acquire(&fixture.request)
            .await
            .expect("cached acquire")
            .attempt,
        fixture.grant.attempt
    );
    let double = fixture
        .participant
        .acquire(&fixture.request)
        .await
        .expect_err("double acquire");
    assert_eq!(lease_code(&double), PARTICIPANT_REFUSED);
}

#[test]
fn every_runner_request_field_is_checked_before_socket() {
    let fixture = fixture();
    let mut changed = Vec::new();
    let mut package = fixture.request.clone();
    package.work_package_id = WorkPackageId::from_seed("other-package");
    changed.push(package);
    let mut runner = fixture.request.clone();
    runner.runner_id = bullet_domain::RunnerId::from_seed("other-runner");
    changed.push(runner);
    let mut epoch = fixture.request.clone();
    epoch.runner_epoch += 1;
    changed.push(epoch);
    let mut idempotency = fixture.request.clone();
    idempotency.idempotency_key.push_str("-drift");
    changed.push(idempotency);
    let mut ttl = fixture.request.clone();
    ttl.ttl_seconds += 1;
    changed.push(ttl);
    for request in changed {
        let error = require_request(fixture.selected.inner(), &request).expect_err("field drift");
        assert_eq!(lease_code(&error), PARTICIPANT_REFUSED);
    }
}

#[tokio::test]
async fn unreconciled_terminal_transport_enters_unknown_once() {
    let fixture = fixture();
    prime(&fixture);
    let error = fixture
        .participant
        .abort_primed_failed()
        .await
        .expect_err("missing signed recovery is unknown");
    assert_eq!(lease_code(&error), "LEASE_RECOVERY_UNCONFIGURED");
    assert_eq!(
        fixture.participant.lock().expect("state").phase,
        Phase::Unknown
    );
    assert!(matches!(
        fixture.participant.settlement_request().expect("request"),
        LeaseSettlementRequest::Release(ref body)
            if body.expected_state == AttemptState::Starting
                && body.final_state == AttemptState::Failed
                && body.requeue
    ));
    let retry = fixture
        .participant
        .abort_primed_failed()
        .await
        .expect_err("unknown cannot retry locally");
    assert_eq!(lease_code(&retry), PARTICIPANT_REFUSED);
}
