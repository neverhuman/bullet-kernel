use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, LeaseGrant, LeaseService, Ledger, PlanInput, StoredGraph,
};
use bullet_domain::{CommandPhase, TaskClass, WorkPackageState};
use rusqlite::{params, Connection};
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
        let directory = secure_tempdir();
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
    let directory = secure_tempdir();
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

    for singleton in ["authority_revisions", "restore_state"] {
        authority_restart::missing_singleton_refuses_lease(singleton);
    }
}

fn grant_bytes(grant: &LeaseGrant) -> Vec<u8> {
    serde_json::to_vec(grant).expect("grant json")
}

#[test]
fn direct_nonempty_schema17_upgrade_rolls_back() {
    let conn = Connection::open_in_memory().expect("memory database");
    for sql in SCHEMA_THROUGH_17 {
        conn.execute_batch(sql).expect("prior migration");
    }
    conn.execute_batch("DROP TRIGGER mutation_authority_fresh_lease_insert;")
        .expect("fixture guard");
    let id = |prefix: &str| format!("{prefix}_{}", "a".repeat(64));
    conn.execute(
        "INSERT INTO mutation_authority (
           reservation_id, mutation_id, operation, request_digest, variant_id, attempt_id,
           work_package_id, fence, runner_id, runner_epoch, workspace_id, workspace_nonce,
           scope_revision, context_revision, authority_epoch, freeze_generation, restore_epoch,
           disposition, completion_digest, created_at, updated_at
         ) VALUES (?1, ?2, 'apply-patch', ?3, ?4, ?5, ?6, 1, ?7, 1, ?8, ?9,
                   1, 1, 1, 0, 0, 'RESERVED', NULL, ?10, ?10)",
        params![
            id("rsv"),
            id("mut"),
            "a".repeat(64),
            id("var"),
            id("atm"),
            id("wpk"),
            id("run"),
            id("wsp"),
            vec![0_u8; 32],
            "2026-08-26T00:00:00.000Z",
        ],
    )
    .expect("prototype row");
    conn.execute_batch("BEGIN IMMEDIATE")
        .expect("begin upgrade");
    assert!(conn.execute_batch(MIGRATION_18).is_err());
    conn.execute_batch("ROLLBACK").expect("rollback upgrade");
    let new_columns: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('mutation_authority')
             WHERE name = 'graph_revision'",
            [],
            |row| row.get(0),
        )
        .expect("column count");
    assert_eq!(new_columns, 0);
    let presentation_table: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'mutation_permit_presentations'",
            [],
            |row| row.get(0),
        )
        .expect("table count");
    assert_eq!(presentation_table, 0);
}

const MIGRATION_18: &str =
    include_str!("../../../db/migrations/0018_mutation_permit_presentation.sql");
const SCHEMA_THROUGH_17: &[&str] = &[
    include_str!("../../../db/migrations/0001_ledger.sql"),
    include_str!("../../../db/migrations/0002_authority.sql"),
    include_str!("../../../db/migrations/0003_effects.sql"),
    include_str!("../../../db/migrations/0004_event_time.sql"),
    include_str!("../../../db/migrations/0005_lease_ttl.sql"),
    include_str!("../../../db/migrations/0006_command_correlation.sql"),
    include_str!("../../../db/migrations/0007_restore_epoch.sql"),
    include_str!("../../../db/migrations/0008_identity_contract.sql"),
    include_str!("../../../db/migrations/0009_effect_receipt_identity.sql"),
    include_str!("../../../db/migrations/0010_launch_grants.sql"),
    include_str!("../../../db/migrations/0011_context_capsules.sql"),
    include_str!("../../../db/migrations/0012_lease_transport.sql"),
    include_str!("../../../db/migrations/0013_nonce_ledger.sql"),
    include_str!("../../../db/migrations/0014_reservations.sql"),
    include_str!("../../../db/migrations/0015_normalized_authority.sql"),
    include_str!("../../../db/migrations/0016_predecessor_constraints.sql"),
    include_str!("../../../db/migrations/0017_mutation_authority.sql"),
];

fn secure_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure tempdir mode");
    }
    directory
}
