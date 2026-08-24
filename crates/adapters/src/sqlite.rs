//! SQLite WAL ledger.

use bullet_application::{CommandRecord, CommandRequest, Ledger, LedgerError, StoredGraph};
use bullet_domain::{
    Attempt, AttemptId, Candidate, CommandId, CommandPhase, Digest, DomainError, Effect, Evidence,
    Mission, MissionId, WorkPackageId,
};
use rusqlite::{params, Connection};
use std::path::Path;

const MIGRATION: &str = include_str!("../../../db/migrations/0001_ledger.sql");

/// SQLite-backed ledger.
pub struct SqliteLedger {
    conn: Connection,
}

impl SqliteLedger {
    /// Open or create a database at `path` with WAL.
    ///
    /// # Errors
    ///
    /// Returns a store error when SQLite cannot open or migrate.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = Connection::open(path.as_ref()).map_err(store)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(store)?;
        conn.execute_batch(MIGRATION).map_err(store)?;
        Ok(Self { conn })
    }
}

fn store(err: impl ToString) -> LedgerError {
    LedgerError::Store(err.to_string())
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, LedgerError> {
    serde_json::to_string(value).map_err(store)
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, LedgerError> {
    serde_json::from_str(text).map_err(store)
}

impl Ledger for SqliteLedger {
    fn record_command(&mut self, request: &CommandRequest) -> Result<CommandRecord, LedgerError> {
        let existing = self.conn.query_row(
            "SELECT id, kind, payload, payload_digest, phase FROM commands WHERE idempotency_key = ?1",
            params![request.idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        );
        match existing {
            Ok((id, kind, payload, digest, phase)) => {
                if payload != request.payload {
                    return Err(DomainError::Idempotency(request.idempotency_key.clone()).into());
                }
                Ok(CommandRecord {
                    id: CommandId::parse(&id)?,
                    idempotency_key: request.idempotency_key.clone(),
                    kind,
                    payload,
                    payload_digest: Digest::from_hex(&digest)?,
                    phase: phase_from(&phase),
                })
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let record = CommandRecord {
                    id: CommandId::from_seed(&request.idempotency_key),
                    idempotency_key: request.idempotency_key.clone(),
                    kind: request.kind.clone(),
                    payload: request.payload.clone(),
                    payload_digest: request.digest(),
                    phase: CommandPhase::Applied,
                };
                self.conn
                    .execute(
                        "INSERT INTO commands (idempotency_key, id, kind, payload, payload_digest, phase)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            record.idempotency_key,
                            record.id.to_string(),
                            record.kind,
                            record.payload,
                            record.payload_digest.to_hex(),
                            phase_name(record.phase)
                        ],
                    )
                    .map_err(store)?;
                Ok(record)
            }
            Err(err) => Err(store(err)),
        }
    }

    fn put_graph(&mut self, graph: &StoredGraph) -> Result<(), LedgerError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO graphs (mission_id, body) VALUES (?1, ?2)",
                params![graph.mission.id.to_string(), json(graph)?],
            )
            .map_err(store)?;
        Ok(())
    }

    fn get_graph(&self, mission: &MissionId) -> Result<Option<StoredGraph>, LedgerError> {
        match self.conn.query_row(
            "SELECT body FROM graphs WHERE mission_id = ?1",
            params![mission.to_string()],
            |row| row.get::<_, String>(0),
        ) {
            Ok(body) => Ok(Some(from_json(&body)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(store(err)),
        }
    }

    fn list_missions(&self) -> Result<Vec<Mission>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare("SELECT body FROM graphs")
            .map_err(store)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(store)?;
        let mut out = Vec::new();
        for row in rows {
            let graph: StoredGraph = from_json(&row.map_err(store)?)?;
            out.push(graph.mission);
        }
        Ok(out)
    }

    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO attempts (id, body) VALUES (?1, ?2)",
                params![attempt.id.to_string(), json(attempt)?],
            )
            .map_err(store)?;
        Ok(())
    }

    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError> {
        match self.conn.query_row(
            "SELECT body FROM attempts WHERE id = ?1",
            params![id.to_string()],
            |row| row.get::<_, String>(0),
        ) {
            Ok(body) => Ok(Some(from_json(&body)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(store(err)),
        }
    }

    fn active_attempt(&self, package: &WorkPackageId) -> Result<Option<Attempt>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare("SELECT body FROM attempts")
            .map_err(store)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(store)?;
        for row in rows {
            let attempt: Attempt = from_json(&row.map_err(store)?)?;
            if !attempt.state.may_mutate() {
                continue;
            }
            let mut graphs = self
                .conn
                .prepare("SELECT body FROM graphs")
                .map_err(store)?;
            let graph_rows = graphs
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(store)?;
            for graph_row in graph_rows {
                let graph: StoredGraph = from_json(&graph_row.map_err(store)?)?;
                if graph.packages.iter().any(|p| p.id == *package)
                    && graph.variants.iter().any(|v| v.id == attempt.variant_id)
                {
                    return Ok(Some(attempt));
                }
            }
        }
        Ok(None)
    }

    fn put_candidate(&mut self, candidate: &Candidate) -> Result<(), LedgerError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO candidates (id, body) VALUES (?1, ?2)",
                params![candidate.id.to_string(), json(candidate)?],
            )
            .map_err(store)?;
        Ok(())
    }

    fn put_evidence(&mut self, evidence: &Evidence) -> Result<(), LedgerError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO evidence (id, body) VALUES (?1, ?2)",
                params![evidence.id.to_string(), json(evidence)?],
            )
            .map_err(store)?;
        Ok(())
    }

    fn put_effect(&mut self, effect: &Effect) -> Result<(), LedgerError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO effects (id, body) VALUES (?1, ?2)",
                params![effect.id.to_string(), json(effect)?],
            )
            .map_err(store)?;
        Ok(())
    }

    fn append_event(&mut self, kind: &str, body: &str) -> Result<(), LedgerError> {
        self.conn
            .execute(
                "INSERT INTO events (kind, body) VALUES (?1, ?2)",
                params![kind, body],
            )
            .map_err(store)?;
        Ok(())
    }

    fn pending_outbox(&self) -> Result<Vec<CommandRecord>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT idempotency_key, id, kind, payload, payload_digest, phase
                 FROM commands WHERE phase != 'verified'",
            )
            .map_err(store)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(store)?;
        let mut out = Vec::new();
        for row in rows {
            let (key, id, kind, payload, digest, phase) = row.map_err(store)?;
            out.push(CommandRecord {
                id: CommandId::parse(&id)?,
                idempotency_key: key,
                kind,
                payload,
                payload_digest: Digest::from_hex(&digest)?,
                phase: phase_from(&phase),
            });
        }
        Ok(out)
    }
}

fn phase_name(phase: CommandPhase) -> &'static str {
    match phase {
        CommandPhase::Pending => "pending",
        CommandPhase::Applied => "applied",
        CommandPhase::Verified => "verified",
        CommandPhase::Unknown => "unknown",
    }
}

fn phase_from(name: &str) -> CommandPhase {
    match name {
        "pending" => CommandPhase::Pending,
        "verified" => CommandPhase::Verified,
        "unknown" => CommandPhase::Unknown,
        _ => CommandPhase::Applied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::run_demo;

    #[test]
    fn sqlite_demo_roundtrip() {
        let dir = std::env::temp_dir().join(format!("bullet-sqlite-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ledger.sqlite");
        let _ = std::fs::remove_file(&path);
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let receipt = run_demo(&mut ledger).expect("demo");
        assert!(receipt.stale_refused);
        let mut again = SqliteLedger::open(&path).expect("reopen");
        let second = run_demo(&mut again).expect("idempotent demo");
        assert_eq!(receipt.mission_id, second.mission_id);
    }
}
