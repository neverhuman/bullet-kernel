use bullet_adapters::sqlite::mutation_authority::{MutationCompletion, MutationDisposition};
use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, ActiveLeaseSubject, LeaseGrant, LeaseService, Ledger, MutationReserveRequest,
    PlanInput, StoredGraph,
};
use bullet_domain::{CommandPhase, Digest, TaskClass, WorkPackageState};
use rusqlite::Connection;
use std::path::Path;

#[path = "lease_command_atomicity/authority_restart.rs"]
mod authority_restart;

const AT: &str = "2026-01-01T00:00:00.000Z";

fn setup(path: &Path, seed: &str) -> (StoredGraph, bullet_application::LeaseRequest) {
    let mut ledger = SqliteLedger::open(path).expect("open");
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "lease command atomicity".into(),
            objective: "recover to the exact prior or complete next state".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        AT,
    )
    .expect("materialize");
    let request =
        LeaseService::request_for(&graph, 0, &format!("{seed}-lease"), 5).expect("request");
    (graph, request)
}

#[test]
fn every_lease_command_boundary_reopens_old_or_complete_and_replays_once() {
    for fail_after in 0..=9 {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("lease-command.sqlite3");
        let seed = format!("lease-command-{fail_after}");
        let (graph, request) = setup(&path, &seed);
        let mut ledger = SqliteLedger::open(&path).expect("reopen");
        ledger.set_lease_acquisition_failpoint(fail_after);
        let error = ledger.acquire_lease(&request).expect_err("failpoint");
        assert_eq!(error.reason_code(), "STORE_FAILURE");
        drop(ledger);

        let mut recovered = SqliteLedger::open(&path).expect("recover");
        if fail_after < 9 {
            assert!(recovered
                .get_command(&request.idempotency_key)
                .expect("command")
                .is_none());
            assert!(recovered
                .get_attempt(&bullet_domain::AttemptId::from_seed(&request.attempt_seed))
                .expect("attempt")
                .is_none());
            assert!(recovered
                .get_lease(&request.variant_id)
                .expect("lease")
                .is_none());
            let prior = recovered
                .get_graph(&graph.mission.id)
                .expect("graph")
                .expect("stored graph");
            assert_eq!(prior.packages[0].state, WorkPackageState::Ready);
            assert_eq!(prior.variants[0].fence_counter, 0);
            assert_eq!(recovered.ready_rows().expect("ready").len(), 1);
            assert_eq!(recovered.list_events().expect("events").len(), 1);
            assert!(recovered.outbox_all().expect("outbox").is_empty());
        } else {
            let record = recovered
                .get_command(&request.idempotency_key)
                .expect("command")
                .expect("committed command");
            assert_eq!(record.phase, CommandPhase::Applied);
            assert!(record.response.is_some());
        }

        let grant = recovered
            .acquire_lease(&request)
            .expect("recover or replay");
        let command = recovered
            .get_command(&request.idempotency_key)
            .expect("command")
            .expect("stored command");
        assert_eq!(
            recovered.get_command_by_id(&command.id).expect("id lookup"),
            Some(command.clone())
        );
        let outbox = recovered
            .outbox_for_command(&command.id)
            .expect("correlated outbox");
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].command_id.as_ref(), Some(&command.id));
        assert_eq!(recovered.list_events().expect("events").len(), 2);
        assert_eq!(grant.attempt.fence, 1);

        let replay = recovered.acquire_lease(&request).expect("exact replay");
        assert_eq!(grant_bytes(&replay), grant_bytes(&grant));
        assert_eq!(recovered.list_events().expect("events").len(), 2);
        assert_eq!(
            recovered
                .outbox_for_command(&command.id)
                .expect("outbox replay")
                .len(),
            1
        );
    }
}

#[test]
fn sqlite_replay_binds_kind_and_corrupt_command_truth_fails_closed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("command-integrity.sqlite3");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let first =
        bullet_application::CommandRequest::from_json("key", "first", "{}").expect("first request");
    ledger.record_command(&first).expect("record");
    let changed = bullet_application::CommandRequest::from_json("key", "second", "{}")
        .expect("changed request");
    assert_eq!(
        ledger
            .record_command(&changed)
            .expect_err("kind conflict")
            .reason_code(),
        "IDEMPOTENCY_CONFLICT"
    );
    drop(ledger);

    Connection::open(&path)
        .expect("raw open")
        .execute(
            "UPDATE commands SET payload_digest = '00' WHERE idempotency_key = 'key'",
            [],
        )
        .expect("corrupt fixture");
    let reopened = SqliteLedger::open(path).expect("schema remains valid");
    assert_eq!(
        reopened
            .get_command("key")
            .expect_err("corrupt truth")
            .reason_code(),
        "STORE_FAILURE"
    );

    durable_mutation_authority_replays_and_invalidates();
    for movement in ["authority-epoch", "freeze-generation", "restore-epoch"] {
        stale_lease_refuses_after(movement);
    }
    for singleton in ["authority_revisions", "restore_state"] {
        authority_restart::missing_singleton_refuses_lease(singleton);
    }
    for corruption in [
        "variant_id = 'var_short'",
        "runner_id = 'run_0000000000000000000000000000000000000000000000000000000000000000'",
        "runner_epoch = 9007199254740992",
        "disposition = 'SETTLED', completion_digest = NULL",
        "authority_epoch = authority_epoch + 1",
    ] {
        corrupted_mutation_refuses_replay(corruption);
    }
}

fn durable_mutation_authority_replays_and_invalidates() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("mutation-authority.sqlite3");
    let (_graph, lease_request) = setup(&path, "mutation-authority");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let grant = ledger.acquire_lease(&lease_request).expect("active lease");
    let subject = ActiveLeaseSubject::from_attempt(&grant.attempt);

    for (mutation_id, operation) in [
        ("mut_short".into(), "apply-patch".into()),
        (format!("mut_{}", "A".repeat(64)), "apply-patch".into()),
        (
            format!("mut_{}", Digest::of(b"legacy-operation").to_hex()),
            "apply_change".into(),
        ),
        (
            format!("mut_{}", Digest::of(b"unknown-operation").to_hex()),
            "unknown-operation".into(),
        ),
    ] {
        let invalid = MutationReserveRequest {
            mutation_id,
            operation,
            request_digest: Digest::of(b"invalid-request").to_hex(),
        };
        let refusal = ledger
            .reserve_mutation(&subject, &invalid)
            .expect_err("noncanonical durable request");
        assert_eq!(refusal.reason_code(), "MUTATION_AUTHORITY_INVALID_REQUEST");
        assert!(ledger
            .mutation_disposition(&invalid.mutation_id)
            .expect("invalid readback")
            .is_none());
    }

    let request = mutation_request("reserved");
    let reserved = ledger
        .reserve_mutation(&subject, &request)
        .expect("reserve");
    assert_eq!(reserved.disposition, MutationDisposition::Reserved);
    assert_eq!(
        ledger.reserve_mutation(&subject, &request).expect("replay"),
        reserved
    );
    let mut changed = request.clone();
    changed.operation = "checkpoint".into();
    assert_eq!(
        ledger
            .reserve_mutation(&subject, &changed)
            .expect_err("changed replay")
            .reason_code(),
        "MUTATION_AUTHORITY_CONFLICT"
    );
    let mut stale = subject.clone();
    stale.fence += 1;
    let stale_request = mutation_request("stale");
    assert_eq!(
        ledger
            .reserve_mutation(&stale, &stale_request)
            .expect_err("stale lease")
            .reason_code(),
        "STALE_AUTHORITY"
    );
    assert!(ledger
        .mutation_disposition(&stale_request.mutation_id)
        .expect("no row")
        .is_none());

    let consumed = ledger
        .consume_mutation(&subject, &reserved.permit)
        .expect("consume");
    assert_eq!(consumed.disposition, MutationDisposition::Consumed);
    assert_eq!(
        ledger
            .consume_mutation(&subject, &reserved.permit)
            .expect_err("second consume")
            .reason_code(),
        "MUTATION_AUTHORITY_STATE_ILLEGAL"
    );
    drop(ledger);

    let mut ledger = SqliteLedger::open(&path).expect("reopen consumed");
    assert_eq!(
        ledger
            .mutation_disposition(&request.mutation_id)
            .expect("observe")
            .expect("row")
            .disposition,
        MutationDisposition::Consumed
    );
    let settled_digest = Digest::of(b"authoritative-ref-readback").to_hex();
    let completion = MutationCompletion::Settled {
        result_digest: settled_digest.clone(),
    };
    let settled = ledger
        .complete_mutation(&subject, &reserved.permit, &completion)
        .expect("settle");
    assert_eq!(settled.disposition, MutationDisposition::Settled);
    assert_eq!(
        settled.completion_digest.as_deref(),
        Some(settled_digest.as_str())
    );
    assert_eq!(
        ledger
            .complete_mutation(&subject, &reserved.permit, &completion)
            .expect("settlement replay"),
        settled
    );

    let unknown_request = mutation_request("unknown");
    let unknown_permit = ledger
        .reserve_mutation(&subject, &unknown_request)
        .expect("unknown reservation")
        .permit;
    ledger
        .consume_mutation(&subject, &unknown_permit)
        .expect("unknown consume");
    let unknown_completion = MutationCompletion::Unknown {
        observation_digest: Digest::of(b"readback-response-lost").to_hex(),
    };
    let explicit_unknown = ledger
        .complete_mutation(&subject, &unknown_permit, &unknown_completion)
        .expect("unknown completion");
    assert_eq!(explicit_unknown.disposition, MutationDisposition::Unknown);
    assert_eq!(
        ledger
            .complete_mutation(&subject, &unknown_permit, &unknown_completion)
            .expect("unknown replay"),
        explicit_unknown
    );

    drop(ledger);

    let raw = Connection::open(&path).expect("raw terminal state");
    assert!(raw
        .execute(
            "UPDATE mutation_authority SET disposition = 'CONSUMED', completion_digest = NULL
             WHERE mutation_id = ?1",
            [&request.mutation_id],
        )
        .is_err());
    assert!(raw
        .execute(
            "DELETE FROM mutation_authority WHERE mutation_id = ?1",
            [&request.mutation_id],
        )
        .is_err());
}

fn stale_lease_refuses_after(movement: &str) {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join(format!("stale-{movement}.sqlite3"));
    let (_graph, lease_request) = setup(&path, movement);
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let grant = ledger.acquire_lease(&lease_request).expect("active lease");
    let subject = ActiveLeaseSubject::from_attempt(&grant.attempt);
    let before = mutation_request(&format!("before-{movement}"));
    let permit = ledger
        .reserve_mutation(&subject, &before)
        .expect("pre-movement reservation")
        .permit;
    drop(ledger);

    let raw = Connection::open(&path).expect("raw authority movement");
    match movement {
        "authority-epoch" => raw
            .execute(
                "UPDATE authority_revisions SET authority_epoch = authority_epoch + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("advance authority epoch"),
        "freeze-generation" => raw
            .execute(
                "UPDATE authority_revisions SET freeze_generation = freeze_generation + 1
                 WHERE singleton = 1",
                [],
            )
            .expect("advance freeze generation"),
        "restore-epoch" => raw
            .execute(
                "UPDATE restore_state
                 SET restore_epoch = 1, source_snapshot_digest = ?1, restored_at = ?2
                 WHERE singleton = 1",
                (Digest::of(b"restored-snapshot").to_hex(), AT),
            )
            .expect("advance restore epoch"),
        _ => panic!("unknown movement"),
    };
    drop(raw);

    let mut ledger = SqliteLedger::open(&path).expect("reopen after movement");
    assert_eq!(
        ledger
            .consume_mutation(&subject, &permit)
            .expect_err("pre-movement permit")
            .reason_code(),
        "MUTATION_AUTHORITY_INVALIDATED"
    );
    let after = mutation_request(&format!("after-{movement}"));
    let first = ledger
        .reserve_mutation(&subject, &after)
        .expect_err("stale issuance");
    assert_eq!(first.reason_code(), "STALE_AUTHORITY");
    assert!(ledger
        .mutation_disposition(&after.mutation_id)
        .expect("refused row readback")
        .is_none());
    let first_bytes = first.to_string();
    drop(ledger);

    let mut reopened = SqliteLedger::open(&path).expect("second reopen");
    let replay = reopened
        .reserve_mutation(&subject, &after)
        .expect_err("stale issuance replay");
    assert_eq!(replay.reason_code(), "STALE_AUTHORITY");
    assert_eq!(replay.to_string(), first_bytes);
    assert!(reopened
        .mutation_disposition(&after.mutation_id)
        .expect("replay refused row readback")
        .is_none());
}

fn corrupted_mutation_refuses_replay(corruption: &str) {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("corrupt-mutation.sqlite3");
    let (_graph, request) = setup(&path, corruption);
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let grant = ledger.acquire_lease(&request).expect("lease");
    let subject = ActiveLeaseSubject::from_attempt(&grant.attempt);
    let mutation = mutation_request(corruption);
    ledger
        .reserve_mutation(&subject, &mutation)
        .expect("reserve");
    drop(ledger);

    let raw = Connection::open(&path).expect("raw mutation corruption");
    let trigger: String = raw
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'mutation_authority_legal_update'",
            [],
            |row| row.get(0),
        )
        .expect("mutation update trigger");
    raw.execute_batch(
        "DROP TRIGGER mutation_authority_legal_update; PRAGMA ignore_check_constraints = ON;",
    )
    .expect("disable fixture guards");
    raw.execute(&format!("UPDATE mutation_authority SET {corruption}"), [])
        .expect("corrupt persisted mutation");
    raw.execute_batch(&format!(
        "PRAGMA ignore_check_constraints = OFF; {trigger};"
    ))
    .expect("restore fixture guards");
    drop(raw);

    let mut first_bytes = None;
    for _ in 0..2 {
        let ledger = SqliteLedger::open(&path).expect("reopen corrupt row");
        let error = ledger
            .mutation_disposition(&mutation.mutation_id)
            .expect_err("corrupt row readback");
        assert_eq!(error.reason_code(), "STORE_FAILURE");
        if let Some(expected) = &first_bytes {
            assert_eq!(&error.to_string(), expected);
        } else {
            first_bytes = Some(error.to_string());
        }
    }
}

fn mutation_request(seed: &str) -> MutationReserveRequest {
    MutationReserveRequest {
        mutation_id: format!("mut_{}", Digest::of(seed.as_bytes()).to_hex()),
        operation: "apply-patch".into(),
        request_digest: Digest::of(format!("request-{seed}").as_bytes()).to_hex(),
    }
}

fn grant_bytes(grant: &LeaseGrant) -> Vec<u8> {
    serde_json::to_vec(grant).expect("grant json")
}
