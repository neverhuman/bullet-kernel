mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{CommandRequest, Ledger};
use bullet_domain::CommandPhase;
use rusqlite::{params, Connection};

const AT: &str = "2026-01-01T00:00:00.000Z";

#[test]
fn reconciliation_commits_command_outbox_and_event_or_nothing() {
    for boundary in 0..=3 {
        let directory = support::private_tempdir();
        let path = directory.path().join("worker-crash.sqlite3");
        let request = CommandRequest::new(
            format!("worker-crash-{boundary}"),
            "run_demo",
            &serde_json::json!({}),
        )
        .expect("request");
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let pending = ledger.submit_command(&request).expect("submit");
        ledger.set_command_reconciliation_failpoint(boundary);
        assert_eq!(
            ledger
                .reconcile_offline_command(&pending.id, AT)
                .expect_err("injected rollback")
                .reason_code(),
            "STORE_FAILURE"
        );
        drop(ledger);

        let mut recovered = SqliteLedger::open(&path).expect("recover");
        let unchanged = recovered
            .get_command_by_id(&pending.id)
            .expect("lookup")
            .expect("command");
        assert_eq!(unchanged.phase, CommandPhase::Pending);
        assert!(unchanged.response.is_none());
        let row = &recovered.outbox_for_command(&pending.id).expect("outbox")[0];
        assert_eq!(row.phase, CommandPhase::Pending);
        assert!(row.acked_at.is_none());
        assert_eq!(recovered.list_events().expect("events").len(), 1);

        let settled = recovered
            .reconcile_offline_command(&pending.id, AT)
            .expect("settle");
        assert_eq!(settled.phase, CommandPhase::Unknown);
        drop(recovered);
        let mut replayed = SqliteLedger::open(&path).expect("reopen settled command");
        let replay = replayed
            .reconcile_offline_command(&pending.id, "2027-01-01T00:00:00.000Z")
            .expect("replay");
        assert_eq!(replay, settled);
        assert_eq!(replayed.list_events().expect("events").len(), 2);
        assert_eq!(
            replayed.outbox_for_command(&pending.id).expect("outbox")[0]
                .acked_at
                .as_deref(),
            Some(AT)
        );
    }
}

#[test]
fn unsupported_is_failed_and_corrupt_ingress_never_mutates() {
    let directory = support::private_tempdir();
    let path = directory.path().join("worker-refusal.sqlite3");
    let request = CommandRequest::new("worker-refusal", "not_admitted", &serde_json::json!({}))
        .expect("request");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let pending = ledger.submit_command(&request).expect("submit");
    let refused = ledger
        .reconcile_offline_command(&pending.id, AT)
        .expect("refuse");
    assert_eq!(refused.phase, CommandPhase::Failed);
    assert!(refused
        .response
        .as_deref()
        .is_some_and(|body| body.contains("UNSUPPORTED_COMMAND_KIND")));
    drop(ledger);

    let corrupt =
        CommandRequest::new("worker-corrupt", "run_demo", &serde_json::json!({})).expect("request");
    let mut ledger = SqliteLedger::open(&path).expect("reopen");
    let corrupt = ledger
        .submit_command(&corrupt)
        .expect("submit corrupt target");
    Connection::open(&path)
        .expect("raw open")
        .execute(
            "UPDATE outbox SET payload = '{}' WHERE command_id = ?1",
            params![corrupt.id.as_str()],
        )
        .expect("corrupt outbox");
    assert_eq!(
        ledger
            .reconcile_offline_command(&corrupt.id, AT)
            .expect_err("corrupt ingress")
            .reason_code(),
        "STORE_FAILURE"
    );
    let unchanged = ledger
        .get_command_by_id(&corrupt.id)
        .expect("lookup")
        .expect("command");
    assert_eq!(unchanged.phase, CommandPhase::Pending);
    assert!(unchanged.response.is_none());
}
