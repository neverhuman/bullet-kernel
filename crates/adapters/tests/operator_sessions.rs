//! Durable authority regression fixtures; no provider/operator enrollment.
mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::operator_sessions::{
    BootstrapRegistration, OperatorSessionError, OperatorSessionStore, SessionIssue,
};
use bullet_domain::Digest;
use std::sync::{Arc, Barrier};

const ORIGIN: &str = "http://127.0.0.1:7420";
fn registration(seed: &str) -> BootstrapRegistration {
    BootstrapRegistration {
        digest: Digest::of(seed.as_bytes()),
        proposed_operator_id: format!("opr_{}", Digest::of(seed.as_bytes()).to_hex()),
        origin: ORIGIN.into(),
        lifetime_seconds: 600,
    }
}
fn issue(bootstrap: &str, session: &str) -> SessionIssue {
    SessionIssue {
        bootstrap_digest: Digest::of(bootstrap.as_bytes()),
        session_id: format!("sid_{}", Digest::of(session.as_bytes()).to_hex()),
        bearer_digest: Digest::of(format!("bearer:{session}").as_bytes()),
        csrf_digest: Digest::of(format!("csrf:{session}").as_bytes()),
        origin: ORIGIN.into(),
        lifetime_seconds: 28_800,
    }
}

#[test]
fn restart_preserves_multiple_sessions_and_another_connection_revokes_only_one() {
    let directory = support::private_tempdir();
    let path = directory.path().join("auth.sqlite");
    let one = issue("one", "first");
    let two = issue("two", "second");
    let first = {
        let mut ledger = SqliteLedger::open(&path).unwrap();
        ledger
            .register_operator_bootstrap(&registration("one"))
            .unwrap();
        ledger.exchange_operator_bootstrap(&one).unwrap()
    };
    let mut restarted = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        restarted
            .read_operator_session(one.bearer_digest, ORIGIN)
            .unwrap(),
        first
    );
    restarted
        .register_operator_bootstrap(&registration("one"))
        .unwrap();
    assert!(matches!(
        restarted.exchange_operator_bootstrap(&one),
        Err(OperatorSessionError::BootstrapConsumed)
    ));
    restarted
        .register_operator_bootstrap(&registration("two"))
        .unwrap();
    let second = restarted.exchange_operator_bootstrap(&two).unwrap();
    assert_eq!(first.operator_id, second.operator_id);
    assert_ne!(first.session_id, second.session_id);
    let mut independent = SqliteLedger::open(&path).unwrap();
    assert!(matches!(
        independent.read_operator_session(one.bearer_digest, "http://127.0.0.1:9999"),
        Err(OperatorSessionError::SessionInvalid)
    ));
    independent
        .revoke_operator_session(one.bearer_digest, one.csrf_digest, ORIGIN)
        .unwrap();
    assert!(matches!(
        restarted.read_operator_session(one.bearer_digest, ORIGIN),
        Err(OperatorSessionError::SessionInvalid)
    ));
    assert_eq!(
        restarted
            .read_operator_session(two.bearer_digest, ORIGIN)
            .unwrap(),
        second
    );
    drop(independent);
    drop(restarted);
    let reopened = SqliteLedger::open(&path).unwrap();
    assert!(matches!(
        reopened.read_operator_session(one.bearer_digest, ORIGIN),
        Err(OperatorSessionError::SessionInvalid)
    ));
    assert_eq!(
        reopened
            .read_operator_session(two.bearer_digest, ORIGIN)
            .unwrap(),
        second
    );
}

#[test]
fn concurrent_independent_connections_consume_one_bootstrap_exactly_once() {
    let directory = support::private_tempdir();
    let path = directory.path().join("auth.sqlite");
    SqliteLedger::open(&path)
        .unwrap()
        .register_operator_bootstrap(&registration("race"))
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles = ["one", "two"].map(|name| {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let mut ledger = SqliteLedger::open(path).unwrap();
            barrier.wait();
            ledger.exchange_operator_bootstrap(&issue("race", name))
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(OperatorSessionError::BootstrapConsumed)))
            .count(),
        1
    );
    let ledger = SqliteLedger::open(&path).unwrap();
    for (name, result) in ["one", "two"].into_iter().zip(results) {
        assert_eq!(
            ledger
                .read_operator_session(issue("race", name).bearer_digest, ORIGIN)
                .is_ok(),
            result.is_ok()
        );
    }
}
