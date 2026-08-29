//! SQLite projection reads: parity with the memory ledger after one shared
//! scenario, atomic watermark reads, and fail-closed corrupt rows.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::store::ProjectionReader;
use bullet_application::{
    materialize_plan, run_demo, EffectIntentRecord, EffectReceiptRecord, EffectState, LeaseService,
    Ledger, MemoryLedger, PlanInput, ReceiptVerdict, ZERO_OID,
};
use bullet_domain::{AttemptId, EffectId, EffectReceiptId, TaskClass};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::Connection;

fn scenario<L: Ledger + ProjectionReader>(ledger: &mut L) {
    run_demo(ledger).expect("demo");
    let intent = EffectIntentRecord {
        id: EffectId::from_seed("proj-intent"),
        logical_effect_key: "push:proj".into(),
        provider: "local-bare".into(),
        target_identity: "refs/heads/bullet/candidate/proj".into(),
        desired_state_hash: "b".repeat(40),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: AttemptId::from_seed("proj-attempt"),
        fence: 1,
        policy_version: "policy-v1".into(),
        payload_hash: String::new(),
        provider_idempotency_key: None,
        state: EffectState::Proposed,
        unknown_retries: 0,
        created_at: "2026-08-25T00:00:01.000Z".into(),
    };
    ledger.record_effect_intent(&intent).expect("intent");
    ledger
        .transition_effect(&intent.id, EffectState::Authorized)
        .expect("authorize");
    ledger
        .record_effect_receipt(&EffectReceiptRecord {
            id: EffectReceiptId::from_seed("proj-receipt"),
            effect_intent_id: intent.id.clone(),
            observed_remote_identity: "refs/heads/bullet/candidate/proj".into(),
            observed_state_hash: None,
            verification_method: "read-back".into(),
            verification_result: ReceiptVerdict::Absent,
            adopted_after_unknown: false,
            recorded_at: "2026-08-25T00:00:02.000Z".into(),
        })
        .expect("receipt");
}

#[test]
fn sqlite_and_memory_project_identical_row_sets_after_one_scenario() {
    let dir = support::private_tempdir();
    let mut sqlite = SqliteLedger::open(dir.path().join("proj.sqlite")).expect("open");
    let mut memory = MemoryLedger::new();
    scenario(&mut sqlite);
    scenario(&mut memory);

    assert_eq!(
        sqlite.list_candidates().expect("sqlite"),
        memory.list_candidates().expect("memory")
    );
    assert_eq!(
        sqlite.list_evidence().expect("sqlite"),
        memory.list_evidence().expect("memory")
    );
    assert_eq!(
        sqlite.list_effects().expect("sqlite"),
        memory.list_effects().expect("memory")
    );
    let attempts = |ledger: &dyn ProjectionReader| -> Vec<(String, u64, String)> {
        ledger
            .list_all_attempts()
            .expect("attempts")
            .iter()
            .map(|a| (a.id.to_string(), a.fence, a.state.as_str().to_string()))
            .collect()
    };
    let expected = attempts(&memory);
    assert!(expected.len() >= 2);
    assert_eq!(attempts(&sqlite), expected);
    let intents = |ledger: &dyn ProjectionReader| -> Vec<(String, EffectState)> {
        ledger
            .list_effect_intents()
            .expect("intents")
            .iter()
            .map(|i| (i.id.to_string(), i.state))
            .collect()
    };
    assert_eq!(intents(&sqlite), intents(&memory));
    assert_eq!(
        intents(&sqlite),
        vec![(
            EffectId::from_seed("proj-intent").to_string(),
            EffectState::Authorized
        )]
    );
    assert_eq!(
        sqlite.list_effect_receipts().expect("sqlite"),
        memory.list_effect_receipts().expect("memory")
    );
    assert_eq!(sqlite.list_effect_receipts().expect("sqlite").len(), 1);
}

#[test]
fn sqlite_projection_reads_share_one_watermark_and_a_canonical_clock() {
    let dir = support::private_tempdir();
    let mut sqlite = SqliteLedger::open(dir.path().join("atomic.sqlite")).expect("open");
    let (empty, zero) = sqlite
        .read_snapshot(|ledger| {
            Ok((
                ledger.list_leases()?.len()
                    + ledger.list_all_attempts()?.len()
                    + ledger.list_candidates()?.len()
                    + ledger.list_evidence()?.len()
                    + ledger.list_effects()?.len()
                    + ledger.list_effect_intents()?.len()
                    + ledger.list_effect_receipts()?.len(),
                ledger.authority_time()?,
            ))
        })
        .expect("empty snapshot");
    assert_eq!((empty.0, zero), (0, 0));
    let clock = DateTime::parse_from_rfc3339(&empty.1).expect("canonical clock");
    assert_eq!(
        clock
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        empty.1
    );

    scenario(&mut sqlite);
    let (rows, watermark) = sqlite
        .read_snapshot(|ledger| Ok((ledger.list_candidates()?, ledger.list_all_attempts()?)))
        .expect("snapshot");
    assert_eq!(watermark, sqlite.latest_event_sequence().expect("latest"));
    assert!(watermark > 0);
    assert!(rows.0.is_empty());
    assert!(rows.1.len() >= 2);
}

#[test]
fn sqlite_lists_the_live_lease_row_with_its_database_window() {
    let dir = support::private_tempdir();
    let mut sqlite = SqliteLedger::open(dir.path().join("lease.sqlite")).expect("open");
    let graph = materialize_plan(
        &mut sqlite,
        "proj-lease",
        &PlanInput {
            title: "lease".into(),
            objective: "list the lease".into(),
            packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
        },
        "2026-08-25T00:00:00.000Z",
    )
    .expect("materialize");
    let (attempt, _, grant) =
        LeaseService::acquire(&mut sqlite, &graph, 0, "lease-a", 7).expect("acquire");
    let leases = sqlite.list_leases().expect("leases");
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0], grant.lease);
    assert_eq!(leases[0].attempt_id, attempt.id);
    assert_eq!(leases[0].ttl_seconds, 7);
    let clock = sqlite.authority_time().expect("clock");
    assert!(leases[0].heartbeat_at <= clock);
    assert!(clock < leases[0].expires_at);
}

#[test]
fn corrupt_persisted_rows_fail_closed_instead_of_shrinking_the_list() {
    let dir = support::private_tempdir();
    let path = dir.path().join("corrupt.sqlite");
    let sqlite = SqliteLedger::open(&path).expect("open");
    let raw = Connection::open(&path).expect("raw");
    raw.execute(
        "INSERT INTO candidates (id, body) VALUES ('can_corrupt', 'not json')",
        [],
    )
    .expect("corrupt candidate");
    assert!(sqlite.list_candidates().is_err());
    raw.execute(
        "INSERT INTO attempts (id, variant_id, work_package_id, fence, runner_id, runner_epoch,
                               workspace_id, workspace_nonce, scope_revision, context_revision,
                               state)
         VALUES ('atm_bad', 'var_bad', 'wpk_bad', 1, 'run_bad', 1, 'wsp_bad', x'00', 1, 1,
                 'running')",
        [],
    )
    .expect("corrupt attempt");
    assert!(sqlite.list_all_attempts().is_err());
    assert!(sqlite.list_leases().expect("no leases").is_empty());
}
