mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{CommandRequest, Ledger};

#[test]
fn public_command_and_dispatch_commit_or_rollback_together() {
    for boundary in 0..=2 {
        let directory = support::private_tempdir();
        let path = directory.path().join("command-ingress.sqlite3");
        let request = CommandRequest::new(
            format!("atomic-public-command-{boundary}"),
            "run_demo",
            &serde_json::json!({"requested": true}),
        )
        .expect("request");
        let mut ledger = SqliteLedger::open(&path).expect("open");
        ledger.set_command_submission_failpoint(boundary);
        assert_eq!(
            ledger
                .submit_command(&request)
                .expect_err("injected rollback")
                .reason_code(),
            "STORE_FAILURE"
        );
        drop(ledger);

        let mut recovered = SqliteLedger::open(&path).expect("recover");
        assert!(recovered
            .get_command(&request.idempotency_key)
            .expect("lookup")
            .is_none());
        assert!(recovered.outbox_all().expect("outbox").is_empty());
        assert!(recovered.list_events().expect("events").is_empty());
        let first = recovered.submit_command(&request).expect("submit");
        let replay = recovered.submit_command(&request).expect("replay");
        assert_eq!(first, replay);
        let rows = recovered
            .outbox_for_command(&first.id)
            .expect("correlated outbox");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "command_dispatch");
        let events = recovered.list_events().expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "command_submitted");
        assert_eq!(events[0].correlation_id.as_deref(), Some(first.id.as_str()));
    }
}

#[test]
fn exact_replay_refuses_missing_or_conflicting_dispatch_truth() {
    let directory = support::private_tempdir();
    let path = directory.path().join("command-corruption.sqlite3");
    let request = CommandRequest::from_json("existing", "run_demo", "{}").expect("request");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let record = ledger.record_command(&request).expect("orphan command");
    assert_eq!(
        ledger
            .submit_command(&request)
            .expect_err("missing outbox")
            .reason_code(),
        "STORE_FAILURE"
    );
    assert!(ledger
        .outbox_for_command(&record.id)
        .expect("outbox")
        .is_empty());
}
