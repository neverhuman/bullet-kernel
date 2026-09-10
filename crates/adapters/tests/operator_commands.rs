//! Independent clients recover the same durable command without local cache.
mod support;
use bullet_adapters::SqliteLedger;
use bullet_application::operator_commands::OperatorCommandStore;
use bullet_application::operator_sessions::{BootstrapRegistration, OperatorSessionStore};
use bullet_application::{CommandRequest, Ledger};
use bullet_domain::Digest;
use std::sync::{Arc, Barrier};

#[test]
fn independent_same_key_clients_commit_one_owner_and_discover_after_restart() {
    let directory = support::private_tempdir();
    let path = directory.path().join("commands.sqlite");
    let operator = format!("opr_{}", Digest::of(b"operator").to_hex());
    SqliteLedger::open(&path)
        .unwrap()
        .register_operator_bootstrap(&BootstrapRegistration {
            digest: Digest::of(b"bootstrap"),
            proposed_operator_id: operator.clone(),
            origin: "http://127.0.0.1:7420".into(),
            lifetime_seconds: 600,
        })
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles = [0, 1].map(|_| {
        let path = path.clone();
        let operator = operator.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let mut ledger = SqliteLedger::open(path).unwrap();
            let request = CommandRequest::new(
                "same-key",
                "run_demo",
                &serde_json::json!({"work":"fixture"}),
            )
            .unwrap();
            barrier.wait();
            ledger.submit_operator_command(&operator, &request).unwrap()
        })
    });
    let [one, two] = handles.map(|handle| handle.join().unwrap());
    assert_eq!(one, two);
    // Both client-local command caches are discarded before this new connection.
    let mut reopened = SqliteLedger::open(&path).unwrap();
    let page = reopened.list_operator_commands(&operator, 0, 100).unwrap();
    assert_eq!(page.commands.as_slice(), std::slice::from_ref(&one.command));
    assert_eq!(page.next_after, None);
    assert_eq!(
        reopened
            .get_operator_command(&operator, &one.command.id)
            .unwrap()
            .unwrap(),
        one
    );
    assert_eq!(reopened.outbox_all().unwrap().len(), 1);
    assert_eq!(reopened.list_events().unwrap().len(), 1);
    let conflict = CommandRequest::new(
        "same-key",
        "run_demo",
        &serde_json::json!({"work":"changed"}),
    )
    .unwrap();
    assert_eq!(
        reopened
            .submit_operator_command(&operator, &conflict)
            .unwrap_err()
            .reason_code(),
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        reopened.list_operator_commands(&operator, 0, 100).unwrap(),
        page
    );
}
