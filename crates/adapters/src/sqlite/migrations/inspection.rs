//! Typed inspection does not grant serving or migration authority.

use super::{
    identity, metadata_table_exists, read_restore_state, schema_contract_digest_for, store,
    unsupported, verify_applied_migrations, verify_foreign_key_integrity, verify_metadata_schema,
    verify_product_schema, verify_unclaimed_pragmas, RestoreState, SchemaState, MIGRATIONS,
};
use bullet_application::{LedgerError, NormalizedAuthority};
use rusqlite::Connection;

/// Validated metadata, product schema, identities, authority and restore state.
/// Only inspection constructs this value. Its digest describes the actual
/// supported catalog prefix; it is not a receipt for mutable database bytes.
#[derive(Debug)]
pub(in crate::sqlite) struct VerifiedSchema {
    schema: SchemaState,
    schema_digest: String,
    authority: NormalizedAuthority,
    restore: RestoreState,
}

impl VerifiedSchema {
    pub(in crate::sqlite) fn schema_state(&self) -> SchemaState {
        self.schema
    }

    pub(in crate::sqlite) fn schema_digest(&self) -> &str {
        &self.schema_digest
    }

    pub(in crate::sqlite) fn restore_state(&self) -> &RestoreState {
        &self.restore
    }

    pub(in crate::sqlite) fn authority(&self) -> &NormalizedAuthority {
        &self.authority
    }

    pub(in crate::sqlite) fn require_current(&self) -> Result<&NormalizedAuthority, LedgerError> {
        if let SchemaState::UpgradeRequired { from, to } = self.schema_state() {
            return Err(store(format!(
                "UPGRADE_REQUIRED: recognized schema {from} requires supervised upgrade to {to}; \
                 stop serving and retain this database for verified backup and supervised migration; \
                 this binary does not yet provide the upgrade operation"
            )));
        }
        Ok(self.authority())
    }

    pub(super) fn into_restore_state(self) -> RestoreState {
        self.restore
    }
}

/// Inspect an admitted connection with SQLite constraint checks enabled.
/// This does not change connection settings or start a read transaction. The
/// authority is observed at its SELECT; callers needing a coherent snapshot
/// across all checks must hold the appropriate transaction and custody.
pub(in crate::sqlite) fn inspect_existing(
    conn: &Connection,
    allow_pending_restore: bool,
) -> Result<VerifiedSchema, LedgerError> {
    verify_unclaimed_pragmas(conn)?;
    if !metadata_table_exists(conn)? {
        return Err(unsupported(
            "database has no checksummed schema_version authority",
        ));
    }
    verify_metadata_schema(conn)?;
    let schema = verify_applied_migrations(conn)?;
    let applied = match schema {
        SchemaState::Current => MIGRATIONS,
        SchemaState::UpgradeRequired { .. } => &MIGRATIONS[..22],
    };
    verify_product_schema(conn, applied)?;
    verify_foreign_key_integrity(conn)?;
    identity::verify(
        conn,
        applied.last().expect("verified nonempty prefix").version,
    )?;
    let authority = crate::sqlite::authority::current(conn).map_err(|error| match schema {
        SchemaState::Current => error,
        SchemaState::UpgradeRequired { .. } => unsupported(error.to_string()),
    })?;
    let restore = read_restore_state(conn)?;
    // Preserve quarantine refusal before the supported-upgrade diagnostic.
    if restore.pending_admission && !allow_pending_restore {
        return Err(store(
            "RESTORE_ADMISSION_REQUIRED: this physically restored database is quarantined; \
             no production authority-admission operation exists in V1",
        ));
    }
    if matches!(schema, SchemaState::UpgradeRequired { .. }) {
        let mut statement = conn.prepare("PRAGMA integrity_check").map_err(store)?;
        let integrity = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(store)?;
        verify_integrity_rows(&integrity)?;
    }
    Ok(VerifiedSchema {
        schema,
        schema_digest: schema_contract_digest_for(applied),
        authority,
        restore,
    })
}

pub(super) fn verify_integrity_rows(rows: &[String]) -> Result<(), LedgerError> {
    if rows != ["ok"] {
        return Err(unsupported(format!(
            "SQLite integrity check failed: {rows:?}"
        )));
    }
    Ok(())
}
