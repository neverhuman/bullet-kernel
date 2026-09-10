//! Raw event fixtures for replay-window and corruption assertions.

use bullet_adapters::SqliteLedger;
use bullet_domain::Digest;
use rusqlite::{params, Connection};
use std::path::Path;

pub fn insert_events(db: &Path, count: u64) {
    drop(SqliteLedger::open(db).expect("initialize ledger"));
    let mut connection = Connection::open(db).expect("raw open");
    let transaction = connection.transaction().expect("transaction");
    for sequence in 1..=count {
        let kind = "fixture";
        let body = sequence.to_string();
        let id = Digest::of(format!("evt:{sequence}:{kind}:{body}").as_bytes()).to_hex();
        transaction
            .execute(
                "INSERT INTO events (seq, kind, body, at, event_id, sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?1)",
                params![sequence, kind, body, "2026-01-01T00:00:00.000Z", id],
            )
            .expect("fixture event");
    }
    transaction.commit().expect("commit fixtures");
}
