//! Exact singleton markers for incompatible persisted identity boundaries.

use crate::sqlite::store;
use bullet_application::{
    LedgerError, COMMAND_DISPATCH_CLAIM_SCHEMA, EFFECT_RECOVERY_AUTHORITY_SCHEMA,
    EFFECT_RECOVERY_CLAIM_SCHEMA, EFFECT_RECOVERY_TRANSITION_SCHEMA,
};
use bullet_domain::{EFFECT_RECEIPT_IDENTITY_FORMAT_VERSION, IDENTITY_FORMAT_VERSION};
use rusqlite::{types::Value, Connection};

pub(super) fn verify(conn: &Connection) -> Result<(), LedgerError> {
    verify_marker(
        conn,
        "SELECT singleton, identity_format FROM identity_contract ORDER BY singleton",
        "identity_contract",
        IDENTITY_FORMAT_VERSION,
    )?;
    verify_marker(
        conn,
        "SELECT singleton, identity_format
         FROM effect_receipt_identity_contract ORDER BY singleton",
        "effect_receipt_identity_contract",
        EFFECT_RECEIPT_IDENTITY_FORMAT_VERSION,
    )?;
    verify_marker(
        conn,
        "SELECT singleton, identity_format
         FROM command_dispatch_claim_identity_contract ORDER BY singleton",
        "command_dispatch_claim_identity_contract",
        COMMAND_DISPATCH_CLAIM_SCHEMA,
    )?;
    verify_effect_recovery_marker(conn)
}

fn verify_marker(
    conn: &Connection,
    query: &str,
    marker: &str,
    expected_format: &str,
) -> Result<(), LedgerError> {
    let mut statement = conn.prepare(query).map_err(store)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?))
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    let expected = [(Value::Integer(1), Value::Text(expected_format.to_owned()))];
    if rows != expected {
        return Err(LedgerError::UnsupportedSchema {
            detail: format!("{marker} must contain its exact recognized singleton row"),
        });
    }
    Ok(())
}

fn verify_effect_recovery_marker(conn: &Connection) -> Result<(), LedgerError> {
    let mut statement = conn
        .prepare(
            "SELECT singleton, authority_format, claim_format, transition_format, receipt_format
             FROM effect_recovery_claim_identity_contract ORDER BY singleton",
        )
        .map_err(store)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Value>(0)?,
                row.get::<_, Value>(1)?,
                row.get::<_, Value>(2)?,
                row.get::<_, Value>(3)?,
                row.get::<_, Value>(4)?,
            ))
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    let expected = [(
        Value::Integer(1),
        Value::Text(EFFECT_RECOVERY_AUTHORITY_SCHEMA.to_owned()),
        Value::Text(EFFECT_RECOVERY_CLAIM_SCHEMA.to_owned()),
        Value::Text(EFFECT_RECOVERY_TRANSITION_SCHEMA.to_owned()),
        Value::Text("bullet.effect-recovery-receipt.v1".to_owned()),
    )];
    if rows != expected {
        return Err(LedgerError::UnsupportedSchema {
            detail: "effect_recovery_claim_identity_contract must contain its exact recognized singleton row"
                .into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{migration_checksum, CREATE_METADATA, MIGRATIONS};
    use crate::sqlite::SqliteLedger;
    use crate::test_support::{private_tempdir, sqlite_fixture};
    use bullet_application::{Ledger, LedgerError};
    use bullet_domain::{AttemptId, EffectId};
    use rusqlite::params;

    fn sidecar(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        value.into()
    }

    #[test]
    fn schema_eight_legacy_receipt_is_refused_byte_for_byte() {
        let directory = private_tempdir();
        let path = directory.path().join("schema-eight.sqlite3");
        let conn = sqlite_fixture(&path);
        conn.execute_batch(CREATE_METADATA).expect("metadata");
        for migration in &MIGRATIONS[..8] {
            conn.execute_batch(migration.sql).expect("migration");
            conn.execute(
                "INSERT INTO schema_version (version, name, checksum, applied_at)
                 VALUES (?1, ?2, ?3, 'prior-schema')",
                params![
                    migration.version,
                    migration.name,
                    migration_checksum(migration)
                ],
            )
            .expect("migration receipt");
        }
        let intent_id = EffectId::from_seed("schema-eight-intent");
        conn.execute(
            "INSERT INTO effect_intents (
               id, logical_effect_key, provider, target_identity, desired_state_hash,
               expected_old_oid, attempt_id, fence, policy_version, payload_hash,
               provider_idempotency_key, state, unknown_retries, created_at
             ) VALUES (?1, 'legacy-key', 'local-bare', 'refs/heads/legacy', ?2,
                       ?3, ?4, 1, 'policy-v1', ?5, NULL, 'PROPOSED', 0, ?6)",
            params![
                intent_id.as_str(),
                "b".repeat(40),
                "0".repeat(40),
                AttemptId::from_seed("schema-eight-attempt").to_string(),
                "a".repeat(64),
                "2026-08-25T00:00:00Z",
            ],
        )
        .expect("legacy intent");
        let legacy_receipt = format!("rcp_{}", "c".repeat(32));
        conn.execute(
            "INSERT INTO effect_receipts (
               id, effect_intent_id, observed_remote_identity, observed_state_hash,
               verification_method, verification_result, adopted_after_unknown, recorded_at
             ) VALUES (?1, ?2, 'refs/heads/legacy', NULL, 'read-back', 'ABSENT', 0, ?3)",
            params![legacy_receipt, intent_id.as_str(), "2026-08-25T00:00:01Z"],
        )
        .expect("legacy receipt");
        drop(conn);

        let bytes_before = std::fs::read(&path).expect("bytes");
        let error = match SqliteLedger::open(&path) {
            Ok(_) => panic!("schema eight opened"),
            Err(error) => error,
        };
        assert!(matches!(error, LedgerError::UnsupportedSchema { .. }));
        assert_eq!(std::fs::read(&path).expect("bytes"), bytes_before);
        assert!(!sidecar(&path, "-wal").exists());
        assert!(!sidecar(&path, "-journal").exists());
        let conn = sqlite_fixture(&path);
        let persisted: String = conn
            .query_row("SELECT id FROM effect_receipts", [], |row| row.get(0))
            .expect("persisted receipt");
        assert_eq!(persisted, legacy_receipt);
    }

    #[test]
    fn sqlite_admission_rejects_legacy_uppercase_and_wrong_prefix_receipts() {
        let directory = private_tempdir();
        let ledger =
            SqliteLedger::open(directory.path().join("current.sqlite3")).expect("current schema");
        for invalid in [
            format!("rcp_{}", "a".repeat(32)),
            format!("efr_{}", "A".repeat(64)),
            format!("efi_{}", "a".repeat(64)),
        ] {
            let error = ledger
                .conn
                .execute(
                    "INSERT INTO effect_receipts (
                       id, effect_intent_id, observed_remote_identity, observed_state_hash,
                       verification_method, verification_result, adopted_after_unknown, recorded_at
                     ) VALUES (?1, 'missing', 'remote', NULL, 'read-back', 'ABSENT', 0, 'now')",
                    params![invalid],
                )
                .expect_err("invalid receipt admitted");
            assert!(error.to_string().contains("INVALID_EFFECT_RECEIPT_ID"));
        }
        assert!(ledger
            .effect_receipts(&EffectId::from_seed("missing"))
            .expect("empty")
            .is_empty());
    }
}
