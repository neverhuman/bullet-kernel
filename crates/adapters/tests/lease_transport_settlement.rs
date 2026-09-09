use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{
    AdvanceSettlementRequest, KernelLeaseTransport, LeaseSettlementOutcome, LeaseSettlementRequest,
    ReleaseSettlementRequest, SignedAcquireBody,
};
use bullet_application::{materialize_plan, Ledger, MemoryLedger, PlanInput};
use bullet_domain::{AttemptState, RunnerId, TaskClass};
use rusqlite::params;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const NOW: u64 = 1_700_000_000_000;

struct Fixture {
    path: PathBuf,
    ledger: SqliteLedger,
    kernel: KernelLeaseTransport,
    advance: LeaseSettlementRequest,
}

impl Fixture {
    fn open(root: &Path, seed: &str) -> Self {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join(format!("{seed}.db"));
        let mut ledger = SqliteLedger::open(&path).unwrap();
        let now = "2026-08-27T00:00:00Z";
        let graph = materialize_plan(
            &mut ledger,
            seed,
            &PlanInput {
                title: "terminal settlement".into(),
                objective: "persist one exact mutation outcome".into(),
                packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
            },
            now,
        )
        .unwrap();
        let acquire = SignedAcquireBody {
            work_package_id: graph.packages[0].id.clone(),
            runner_id: RunnerId::from_seed(&format!("{seed}-runner")),
            runner_epoch: 7,
            idempotency_key: format!("{seed}-acquire"),
            ttl_seconds: 15,
        };
        let kernel = KernelLeaseTransport::generate().unwrap();
        let grant = kernel.acquire(&mut ledger, &acquire, NOW).unwrap();
        assert_eq!(grant.attempt.state, AttemptState::Starting);
        let advance = LeaseSettlementRequest::Advance(AdvanceSettlementRequest {
            acquire_request_digest: acquire.request_digest().unwrap(),
            work_package_id: acquire.work_package_id.clone(),
            runner_id: acquire.runner_id.clone(),
            runner_epoch: acquire.runner_epoch,
            idempotency_key: acquire.idempotency_key.clone(),
            variant_id: grant.attempt.variant_id.clone(),
            attempt_id: grant.attempt.id.clone(),
            attempt_fence: grant.attempt.fence,
            expected_state: AttemptState::Starting,
            target_state: AttemptState::Running,
        });
        Self {
            path,
            ledger,
            kernel,
            advance,
        }
    }

    fn release(&self) -> LeaseSettlementRequest {
        let advance = match &self.advance {
            LeaseSettlementRequest::Advance(body) => body,
            LeaseSettlementRequest::Release(_) => unreachable!(),
        };
        LeaseSettlementRequest::Release(ReleaseSettlementRequest {
            acquire_request_digest: advance.acquire_request_digest.clone(),
            work_package_id: advance.work_package_id.clone(),
            runner_id: advance.runner_id.clone(),
            runner_epoch: advance.runner_epoch,
            idempotency_key: advance.idempotency_key.clone(),
            variant_id: advance.variant_id.clone(),
            attempt_id: advance.attempt_id.clone(),
            attempt_fence: advance.attempt_fence,
            expected_state: AttemptState::Running,
            final_state: AttemptState::Failed,
            requeue: false,
        })
    }
}

#[test]
fn advance_release_replay_and_reopen_return_only_exact_immutable_outcomes() {
    let root = tempfile::tempdir().unwrap();
    let mut fx = Fixture::open(root.path(), "settlement-reopen");
    let advanced = fx.kernel.settle(&mut fx.ledger, &fx.advance, NOW).unwrap();
    assert!(matches!(
        advanced.outcome,
        LeaseSettlementOutcome::Advanced(ref attempt) if attempt.state == AttemptState::Running
    ));
    assert_eq!(
        fx.kernel.settle(&mut fx.ledger, &fx.advance, NOW).unwrap(),
        advanced
    );

    let release = fx.release();
    let released = fx.kernel.settle(&mut fx.ledger, &release, NOW).unwrap();
    assert!(matches!(
        released.outcome,
        LeaseSettlementOutcome::Released(ref attempt) if attempt.state == AttemptState::Failed
    ));
    assert_eq!(
        fx.kernel.settle(&mut fx.ledger, &release, NOW).unwrap(),
        released
    );
    assert!(fx
        .ledger
        .get_lease(match &release {
            LeaseSettlementRequest::Release(body) => &body.variant_id,
            LeaseSettlementRequest::Advance(_) => unreachable!(),
        })
        .unwrap()
        .is_none());
    let settled_events = fx
        .ledger
        .list_events()
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "lease_transport_settled")
        .count();
    assert_eq!(settled_events, 2, "replay must not duplicate audit events");

    let path = fx.path.clone();
    drop(fx.ledger);
    let mut reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        fx.kernel
            .settlement_readback(&mut reopened, &fx.advance, NOW + 1)
            .unwrap(),
        advanced
    );
    assert_eq!(
        fx.kernel
            .settlement_readback(&mut reopened, &release, NOW + 1)
            .unwrap(),
        released
    );
    drop(reopened);
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(raw
        .execute(
            "UPDATE lease_transport_settlements SET record_json = '{}'
             WHERE settlement_id = ?1",
            [&advanced.settlement_id],
        )
        .is_err());
    assert!(raw
        .execute(
            "DELETE FROM lease_transport_settlements WHERE settlement_id = ?1",
            [&advanced.settlement_id],
        )
        .is_err());
}

#[test]
fn injected_failure_between_mutation_and_record_rolls_everything_back() {
    let root = tempfile::tempdir().unwrap();
    let mut fx = Fixture::open(root.path(), "settlement-rollback");
    fx.ledger.set_lease_transport_settlement_failpoint(0);
    let error = fx
        .kernel
        .settle(&mut fx.ledger, &fx.advance, NOW)
        .unwrap_err();
    assert!(error.to_string().contains("injected"));
    let attempt_id = match &fx.advance {
        LeaseSettlementRequest::Advance(body) => &body.attempt_id,
        LeaseSettlementRequest::Release(_) => unreachable!(),
    };
    assert_eq!(
        fx.ledger.get_attempt(attempt_id).unwrap().unwrap().state,
        AttemptState::Starting
    );
    assert_eq!(
        fx.kernel
            .settlement_readback(&mut fx.ledger, &fx.advance, NOW)
            .unwrap_err()
            .reason_code(),
        "LEASE_TRANSPORT_SETTLEMENT_ABSENT"
    );
    assert!(!fx
        .ledger
        .list_events()
        .unwrap()
        .iter()
        .any(|event| event.kind == "lease_transport_settled"));
}

#[test]
fn strict_corrupt_row_and_changed_expected_state_never_launder_success() {
    let root = tempfile::tempdir().unwrap();
    let fx = Fixture::open(root.path(), "settlement-hostile");
    let settlement_id = fx.advance.settlement_id().unwrap();
    let request_digest = fx.advance.digest().unwrap();
    let path = fx.path.clone();
    drop(fx.ledger);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO lease_transport_settlements
             (settlement_id, request_digest, record_json, recorded_at)
             VALUES (?1, ?2, '{}', '2026-08-27T00:00:00Z')",
            params![settlement_id, request_digest],
        )
        .unwrap();
    drop(connection);

    let mut reopened = SqliteLedger::open(&path).unwrap();
    let error = fx
        .kernel
        .settlement_readback(&mut reopened, &fx.advance, NOW)
        .unwrap_err();
    assert_eq!(error.reason_code(), "STORE_FAILURE");

    let mut changed = fx.advance.clone();
    if let LeaseSettlementRequest::Advance(body) = &mut changed {
        body.expected_state = AttemptState::Paused;
    }
    assert_ne!(
        changed.settlement_id().unwrap(),
        fx.advance.settlement_id().unwrap()
    );
    assert_eq!(
        fx.kernel
            .settlement_readback(&mut reopened, &changed, NOW)
            .unwrap_err()
            .reason_code(),
        "LEASE_TRANSPORT_SETTLEMENT_ABSENT"
    );
}

#[test]
fn historic_outcome_survives_authority_movement_but_new_settlement_refuses() {
    let root = tempfile::tempdir().unwrap();
    let mut fx = Fixture::open(root.path(), "settlement-authority");
    let advanced = fx.kernel.settle(&mut fx.ledger, &fx.advance, NOW).unwrap();
    let release = fx.release();
    let path = fx.path.clone();
    drop(fx.ledger);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE authority_revisions
             SET authority_epoch = authority_epoch + 1,
                 freeze_generation = freeze_generation + 1
             WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(connection);

    let mut reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        fx.kernel
            .settlement_readback(&mut reopened, &fx.advance, NOW + 1)
            .unwrap(),
        advanced
    );
    let refusal = fx
        .kernel
        .settle(&mut reopened, &release, NOW + 1)
        .unwrap_err();
    assert_eq!(refusal.reason_code(), "LEASE_TRANSPORT_SUBJECT_MISMATCH");
    let variant = match &release {
        LeaseSettlementRequest::Release(body) => &body.variant_id,
        LeaseSettlementRequest::Advance(_) => unreachable!(),
    };
    assert!(reopened.get_lease(variant).unwrap().is_some());
    assert_eq!(
        fx.kernel
            .settlement_readback(&mut reopened, &release, NOW + 1)
            .unwrap_err()
            .reason_code(),
        "LEASE_TRANSPORT_SETTLEMENT_ABSENT"
    );
}

#[test]
fn memory_port_matches_replay_event_and_strict_codec_semantics() {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let graph = materialize_plan(
        &mut ledger,
        "settlement-memory",
        &PlanInput {
            title: "memory settlement".into(),
            objective: "match the durable transaction port".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        &now,
    )
    .unwrap();
    let acquire = SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("settlement-memory-runner"),
        runner_epoch: 5,
        idempotency_key: "settlement-memory-acquire".into(),
        ttl_seconds: 15,
    };
    let kernel = KernelLeaseTransport::generate().unwrap();
    let grant = kernel.acquire(&mut ledger, &acquire, NOW).unwrap();
    let request = LeaseSettlementRequest::Advance(AdvanceSettlementRequest {
        acquire_request_digest: acquire.request_digest().unwrap(),
        work_package_id: acquire.work_package_id.clone(),
        runner_id: acquire.runner_id.clone(),
        runner_epoch: acquire.runner_epoch,
        idempotency_key: acquire.idempotency_key.clone(),
        variant_id: grant.attempt.variant_id.clone(),
        attempt_id: grant.attempt.id.clone(),
        attempt_fence: grant.attempt.fence,
        expected_state: AttemptState::Starting,
        target_state: AttemptState::Running,
    });
    let record = kernel.settle(&mut ledger, &request, NOW).unwrap();
    assert_eq!(kernel.settle(&mut ledger, &request, NOW).unwrap(), record);
    assert_eq!(
        kernel
            .settlement_readback(&mut ledger, &request, NOW + 1)
            .unwrap(),
        record
    );
    assert_eq!(
        ledger
            .list_events()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "lease_transport_settled")
            .count(),
        1
    );

    ledger
        .transport_settlement_rows_mut()
        .insert(record.settlement_id.clone(), "{}".into());
    assert_eq!(
        kernel
            .settlement_readback(&mut ledger, &request, NOW + 2)
            .unwrap_err()
            .reason_code(),
        "STORE_FAILURE"
    );
}
