use super::fixtures::{fixture, source};
use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    CandidateNonceConsumption, CandidatePreparationIssuer, CandidatePreparationNonceStore,
    CandidatePreparationSigningKey, CandidatePreparationStore, LedgerCandidatePreparationIssuer,
};
use bullet_domain::Digest;
use rusqlite::params;

#[test]
fn source_grant_and_consumption_are_append_only() {
    let built = fixture("candidate-append-only");
    let directory = built._directory;
    let path = built.path;
    let attempt = built.attempt;
    let mut ledger = built.ledger;
    let source = source(&attempt, '7');
    let registered = ledger
        .register_candidate_preparation_source(&source)
        .unwrap();
    let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();
    let issued = LedgerCandidatePreparationIssuer::new(&mut ledger, &key)
        .mint(&registered.request_digest)
        .unwrap();
    assert_eq!(
        ledger
            .consume_candidate_preparation_nonce(&issued.grant.grant_nonce, attempt.id.as_str())
            .unwrap(),
        CandidateNonceConsumption::Consumed
    );
    drop(ledger);
    let raw = rusqlite::Connection::open(&path).unwrap();
    for sql in [
        "UPDATE candidate_preparation_sources SET root_change = 0",
        "DELETE FROM candidate_preparation_sources",
        "UPDATE candidate_preparation_grants SET runner_epoch = runner_epoch + 1",
        "DELETE FROM candidate_preparation_grants",
        "UPDATE candidate_preparation_nonce_consumptions SET consumed_at = 'changed'",
        "DELETE FROM candidate_preparation_nonce_consumptions",
    ] {
        assert!(raw.execute(sql, []).is_err(), "mutation admitted: {sql}");
    }
    drop(raw);
    drop(directory);
}

#[test]
fn exact_schema_eighteen_is_refused_without_byte_mutation() {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let directory = builder.tempdir().unwrap();
    let path = directory.path().join("schema-18.sqlite3");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_version (
           version INTEGER NOT NULL PRIMARY KEY,
           name TEXT NOT NULL,
           checksum TEXT NOT NULL,
           applied_at TEXT NOT NULL
         );",
    )
    .unwrap();
    for (index, (name, sql)) in MIGRATIONS_18.iter().enumerate() {
        conn.execute_batch(sql).unwrap();
        let version = i64::try_from(index + 1).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, 'prior-schema')",
            params![version, name, migration_checksum(version, name, sql)],
        )
        .unwrap();
    }
    drop(conn);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    let error = match SqliteLedger::open(&path) {
        Ok(_) => panic!("schema 18 opened"),
        Err(error) => error,
    };
    assert_eq!(error.reason_code(), "UNSUPPORTED_SCHEMA");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn authority_epoch_movement_prevents_nonce_consumption() {
    let built = fixture("candidate-authority-movement");
    let directory = built._directory;
    let path = built.path;
    let attempt = built.attempt;
    let mut ledger = built.ledger;
    let registered = ledger
        .register_candidate_preparation_source(&source(&attempt, '9'))
        .unwrap();
    let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();
    let issued = LedgerCandidatePreparationIssuer::new(&mut ledger, &key)
        .mint(&registered.request_digest)
        .unwrap();
    drop(ledger);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE authority_revisions SET authority_epoch = 2 WHERE singleton = 1",
        [],
    )
    .unwrap();
    drop(raw);
    let mut reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        reopened
            .consume_candidate_preparation_nonce(&issued.grant.grant_nonce, attempt.id.as_str())
            .unwrap(),
        CandidateNonceConsumption::Unknown
    );
    drop(reopened);
    drop(directory);
}

fn migration_checksum(version: i64, name: &str, sql: &str) -> String {
    let mut bytes = Vec::new();
    for subject in [
        b"bullet-kernel.sqlite-migration.v1".as_slice(),
        version.to_le_bytes().as_slice(),
        name.as_bytes(),
        sql.as_bytes(),
    ] {
        bytes.extend_from_slice(&u64::try_from(subject.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(subject);
    }
    Digest::of(&bytes).to_hex()
}

const MIGRATIONS_18: &[(&str, &str)] = &[
    (
        "0001_ledger.sql",
        include_str!("../../../../db/migrations/0001_ledger.sql"),
    ),
    (
        "0002_authority.sql",
        include_str!("../../../../db/migrations/0002_authority.sql"),
    ),
    (
        "0003_effects.sql",
        include_str!("../../../../db/migrations/0003_effects.sql"),
    ),
    (
        "0004_event_time.sql",
        include_str!("../../../../db/migrations/0004_event_time.sql"),
    ),
    (
        "0005_lease_ttl.sql",
        include_str!("../../../../db/migrations/0005_lease_ttl.sql"),
    ),
    (
        "0006_command_correlation.sql",
        include_str!("../../../../db/migrations/0006_command_correlation.sql"),
    ),
    (
        "0007_restore_epoch.sql",
        include_str!("../../../../db/migrations/0007_restore_epoch.sql"),
    ),
    (
        "0008_identity_contract.sql",
        include_str!("../../../../db/migrations/0008_identity_contract.sql"),
    ),
    (
        "0009_effect_receipt_identity.sql",
        include_str!("../../../../db/migrations/0009_effect_receipt_identity.sql"),
    ),
    (
        "0010_launch_grants.sql",
        include_str!("../../../../db/migrations/0010_launch_grants.sql"),
    ),
    (
        "0011_context_capsules.sql",
        include_str!("../../../../db/migrations/0011_context_capsules.sql"),
    ),
    (
        "0012_lease_transport.sql",
        include_str!("../../../../db/migrations/0012_lease_transport.sql"),
    ),
    (
        "0013_nonce_ledger.sql",
        include_str!("../../../../db/migrations/0013_nonce_ledger.sql"),
    ),
    (
        "0014_reservations.sql",
        include_str!("../../../../db/migrations/0014_reservations.sql"),
    ),
    (
        "0015_normalized_authority.sql",
        include_str!("../../../../db/migrations/0015_normalized_authority.sql"),
    ),
    (
        "0016_predecessor_constraints.sql",
        include_str!("../../../../db/migrations/0016_predecessor_constraints.sql"),
    ),
    (
        "0017_mutation_authority.sql",
        include_str!("../../../../db/migrations/0017_mutation_authority.sql"),
    ),
    (
        "0018_mutation_permit_presentation.sql",
        include_str!("../../../../db/migrations/0018_mutation_permit_presentation.sql"),
    ),
];
