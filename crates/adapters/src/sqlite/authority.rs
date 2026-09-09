//! Singleton normalized authority row. Seeded once; never INSERT OR REPLACE.

use super::store;
use bullet_application::{LedgerError, NormalizedAuthority};
use rusqlite::{params, Connection, OptionalExtension};

pub(super) fn seed_genesis(conn: &Connection) -> Result<(), LedgerError> {
    let genesis = NormalizedAuthority::genesis();
    conn.execute(
        "INSERT INTO authority_revisions (
            singleton, graph_revision, workspace_generation, scope_digest,
            policy_generation, routing_generation, authority_epoch, freeze_generation
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            i64::try_from(genesis.graph_revision()).map_err(store)?,
            i64::try_from(genesis.workspace_generation()).map_err(store)?,
            genesis.scope_digest(),
            i64::try_from(genesis.policy_generation()).map_err(store)?,
            i64::try_from(genesis.routing_generation()).map_err(store)?,
            i64::try_from(genesis.authority_epoch()).map_err(store)?,
            i64::try_from(genesis.freeze_generation()).map_err(store)?,
        ],
    )
    .map_err(store)?;
    Ok(())
}

pub(super) fn current(conn: &Connection) -> Result<NormalizedAuthority, LedgerError> {
    let row: Option<(i64, i64, String, i64, i64, i64, i64)> = conn
        .query_row(
            "SELECT graph_revision, workspace_generation, scope_digest,
                    policy_generation, routing_generation, authority_epoch, freeze_generation
             FROM authority_revisions WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(store)?;
    let Some((
        graph_revision,
        workspace_generation,
        scope_digest,
        policy_generation,
        routing_generation,
        authority_epoch,
        freeze_generation,
    )) = row
    else {
        return Err(store("authority revision singleton is absent"));
    };
    NormalizedAuthority::new(
        u64::try_from(graph_revision).map_err(store)?,
        u64::try_from(workspace_generation).map_err(store)?,
        scope_digest,
        u64::try_from(policy_generation).map_err(store)?,
        u64::try_from(routing_generation).map_err(store)?,
        u64::try_from(authority_epoch).map_err(store)?,
        u64::try_from(freeze_generation).map_err(store)?,
    )
    .map_err(|err| store(err.to_string()))
}
