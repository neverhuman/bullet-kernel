//! Durable authority checks fail closed on corrupt or unavailable lease truth.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, ActiveLeaseSubject, LeaseService, Ledger, PlanInput};
use bullet_domain::TaskClass;
use chrono::Utc;
use rusqlite::Connection;

fn acquire(path: &std::path::Path, seed: &str) -> ActiveLeaseSubject {
    let mut ledger = SqliteLedger::open(path).expect("open");
    let now = Utc::now();
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "authority".into(),
            objective: "fail closed".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        &LeaseService::rfc3339(now),
    )
    .expect("materialize");
    let (attempt, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, seed, 15).expect("acquire");
    ActiveLeaseSubject::from_attempt(&attempt)
}

#[test]
fn corrupt_lease_row_never_authorizes() {
    let dir = support::private_tempdir();
    let path = dir.path().join("corrupt.sqlite");
    let subject = acquire(&path, "corrupt");
    Connection::open(&path)
        .expect("raw open")
        .execute(
            "UPDATE active_leases SET workspace_nonce = X'00' WHERE variant_id = ?1",
            [subject.variant_id.as_str()],
        )
        .expect("corrupt lease");
    let mut ledger = SqliteLedger::open(&path).expect("reopen");
    let error = ledger
        .check_active_lease(&subject)
        .expect_err("corrupt state must not authorize");
    assert_eq!(error.reason_code(), "STORE_FAILURE");
}

#[test]
fn unavailable_authority_table_never_authorizes() {
    let dir = support::private_tempdir();
    let path = dir.path().join("unavailable.sqlite");
    let _subject = acquire(&path, "unavailable");
    Connection::open(&path)
        .expect("raw open")
        .execute("DROP TABLE active_leases", [])
        .expect("remove authority table");
    let error = match SqliteLedger::open(&path) {
        Ok(_) => panic!("missing authority table must prevent ledger open"),
        Err(error) => error,
    };
    assert_eq!(error.reason_code(), "UNSUPPORTED_SCHEMA");
}
