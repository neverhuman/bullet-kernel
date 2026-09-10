use super::*;

mod corruption;
mod page_bytes;
use bullet_application::operator_sessions::{BootstrapRegistration, OperatorSessionStore};
use bullet_application::{CommandDispatchStore, ComponentCommandCompletionV1, Ledger};
use bullet_domain::{CommandPhase, Digest, RunnerId};
const AT: &str = "2026-09-10T00:00:00.000Z";
fn register(ledger: &mut SqliteLedger) -> String {
    let operator = format!("opr_{}", Digest::of(b"operator").to_hex());
    ledger
        .register_operator_bootstrap(&BootstrapRegistration {
            digest: Digest::of(b"bootstrap"),
            proposed_operator_id: operator.clone(),
            origin: "http://127.0.0.1:7420".into(),
            lifetime_seconds: 600,
        })
        .unwrap();
    operator
}
fn request(key: &str) -> CommandRequest {
    CommandRequest::new(key, "run_demo", &serde_json::json!({})).unwrap()
}
fn coding(key: &str) -> CommandRequest {
    CommandRequest::new(key,"run_coding",&serde_json::json!({"account_id":"acct-fixture","provider":"claude","model":"fixture-model","expected_revision":1,"launch_nonce":"ab".repeat(32),"quota_reservation":format!("rsv_{}","cd".repeat(32)),"quota_units":3,"allocated_run":RunnerId::from_seed("fixture-run").to_string()})).unwrap()
}
fn counts(ledger: &SqliteLedger) -> Vec<i64> {
    [
        "commands",
        "operator_command_ownership",
        "outbox",
        "events",
        "authority_nonces",
        "budget_reservations",
    ]
    .iter()
    .map(|table| {
        ledger
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    })
    .collect()
}
#[test]
fn owner_and_admission_effects_roll_back_together_at_every_boundary() {
    for boundary in 0..=4 {
        let directory = crate::test_support::private_tempdir();
        let path = directory.path().join("owner.sqlite");
        let mut ledger = SqliteLedger::open(&path).unwrap();
        let operator = register(&mut ledger);
        ledger.set_command_submission_failpoint(boundary);
        assert!(
            ledger
                .submit_operator_command(&operator, &coding("rollback"))
                .is_err(),
            "boundary {boundary}"
        );
        assert_eq!(counts(&ledger), [0, 0, 0, 0, 0, 0]);
        drop(ledger);
        let mut reopened = SqliteLedger::open(&path).unwrap();
        assert!(reopened
            .list_operator_commands(&operator, 0, 10)
            .unwrap()
            .commands
            .is_empty());
        reopened
            .submit_operator_command(&operator, &coding("rollback"))
            .unwrap();
        assert_eq!(counts(&reopened), [1, 1, 1, 1, 1, 1]);
    }
}
#[test]
fn exact_coding_retry_after_terminal_phase_and_epoch_change_has_no_new_admission() {
    let directory = crate::test_support::private_tempdir();
    let path = directory.path().join("owner.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let operator = register(&mut ledger);
    let request = coding("lost-response");
    let admitted = ledger.submit_operator_command(&operator, &request).unwrap();
    let runner = RunnerId::from_seed("fixture-runner");
    let claim = ledger
        .claim_next_command_dispatch(&runner, 1, AT)
        .unwrap()
        .unwrap();
    let receipt =
        ComponentCommandCompletionV1::new(&claim, Digest::of(b"component-evidence")).unwrap();
    let settled = ledger
        .settle_component_command_dispatch(&claim.claim_id, &runner, 1, &receipt, AT)
        .unwrap();
    assert_eq!(settled.phase, CommandPhase::Unknown);
    ledger
        .conn
        .execute(
            "UPDATE authority_revisions SET authority_epoch=authority_epoch+1 WHERE singleton=1",
            [],
        )
        .unwrap();
    let before = counts(&ledger);
    drop(ledger);
    let mut reopened = SqliteLedger::open(&path).unwrap();
    let replay = reopened
        .submit_operator_command(&operator, &request)
        .unwrap();
    assert_eq!(replay.command, settled);
    assert!(replay.as_of_sequence > admitted.as_of_sequence);
    assert_eq!(counts(&reopened), before);
    let reservation: (i64, Option<i64>, i64) = reopened
        .conn
        .query_row(
            "SELECT amount,settled_amount,unknown_liability FROM budget_reservations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        reservation,
        (3, None, 0),
        "existing retained quota state is unchanged, not settled by retry"
    );
    assert_eq!(
        reopened
            .get_operator_command(&operator, &settled.id)
            .unwrap()
            .unwrap()
            .command,
        settled
    );
    assert_eq!(
        reopened
            .list_operator_commands(&operator, 0, 10)
            .unwrap()
            .commands,
        [settled]
    );
    assert!(reopened
        .submit_operator_command(&operator, &coding("fresh-stale-authority"))
        .is_err());
    assert_eq!(counts(&reopened), before);
}
#[test]
fn history_stays_unowned_and_discovery_is_bounded_to_the_authenticated_owner() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("owner.sqlite")).unwrap();
    let operator = register(&mut ledger);
    let legacy = ledger.submit_command(&request("historical")).unwrap();
    assert!(ledger
        .get_operator_command(&operator, &legacy.id)
        .unwrap()
        .is_none());
    assert!(matches!(
        ledger.submit_operator_command(&operator, &request("historical")),
        Err(Error::OwnershipConflict)
    ));
    let mut owned = Vec::new();
    for key in ["one", "two", "three"] {
        owned.push(
            ledger
                .submit_operator_command(&operator, &request(key))
                .unwrap()
                .command,
        );
    }
    let first = ledger.list_operator_commands(&operator, 0, 2).unwrap();
    assert_eq!(first.commands, owned[..2]);
    let second = ledger
        .list_operator_commands(&operator, first.next_after.unwrap(), 2)
        .unwrap();
    assert_eq!(second.commands, owned[2..]);
    assert_eq!(second.next_after, None);
    for (after, limit) in [(0, 0), (0, 101), (MAX_SEQUENCE + 1, 1)] {
        assert!(matches!(
            ledger.list_operator_commands(&operator, after, limit),
            Err(Error::InvalidRequest)
        ));
    }
    let foreign = format!("opr_{}", Digest::of(b"another-operator").to_hex());
    assert!(matches!(
        ledger.submit_operator_command(&foreign, &request("one")),
        Err(Error::OwnershipConflict)
    ));
    assert!(ledger.get_operator_command(&foreign, &owned[0].id).is_err());
    assert!(ledger.list_operator_commands(&foreign, 0, 10).is_err());
    let changed =
        CommandRequest::new("one", "run_demo", &serde_json::json!({"changed":true})).unwrap();
    assert_eq!(
        ledger
            .submit_operator_command(&operator, &changed)
            .unwrap_err()
            .reason_code(),
        "IDEMPOTENCY_CONFLICT"
    );
    assert!(ledger
        .get_operator_command(&operator, &legacy.id)
        .unwrap()
        .is_none());
    assert_eq!(
        ledger
            .list_operator_commands(&operator, 0, 100)
            .unwrap()
            .commands,
        owned
    );
}
#[test]
fn immutable_owner_and_corrupt_subjects_fail_closed_for_read_list_and_retry() {
    for corruption in [
        "request_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        "admitted_at='2026-09-09T00:00:00Z'",
    ] {
        let directory = crate::test_support::private_tempdir();
        let mut ledger = SqliteLedger::open(directory.path().join("owner.sqlite")).unwrap();
        let operator = register(&mut ledger);
        let request = request("owned");
        let command = ledger
            .submit_operator_command(&operator, &request)
            .unwrap()
            .command;
        for sql in ["UPDATE operator_command_ownership SET admitted_at=admitted_at","DELETE FROM operator_command_ownership","INSERT OR REPLACE INTO operator_command_ownership SELECT * FROM operator_command_ownership"] { assert!(ledger.conn.execute(sql,[]).unwrap_err().to_string().contains("OPERATOR_COMMAND_OWNER_IMMUTABLE")); }
        ledger
            .conn
            .execute_batch("DROP TRIGGER operator_command_owner_no_update")
            .unwrap();
        ledger
            .conn
            .execute(
                &format!("UPDATE operator_command_ownership SET {corruption}"),
                [],
            )
            .unwrap();
        assert!(ledger.get_operator_command(&operator, &command.id).is_err());
        assert!(ledger.list_operator_commands(&operator, 0, 10).is_err());
        assert!(ledger.submit_operator_command(&operator, &request).is_err());
    }
}
