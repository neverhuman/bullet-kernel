//! Independently observed submission records; no fabricated execution relationships.

use super::model::{row, Row};
use crate::client::models::CommandDiscoverySnapshot;

#[derive(Default)]
pub(super) struct Submissions {
    pub(super) snapshot: Option<CommandDiscoverySnapshot>,
    pub(super) error: Option<String>,
}

impl Submissions {
    pub(super) fn update(&mut self, result: Result<CommandDiscoverySnapshot, String>) {
        match result {
            Ok(snapshot)
                if self
                    .snapshot
                    .as_ref()
                    .is_some_and(|old| old.as_of_sequence > snapshot.as_of_sequence) =>
            {
                self.error = Some("FARMD_COMMANDS_REGRESSED: previous submissions retained".into());
            }
            Ok(snapshot) => {
                self.snapshot = Some(snapshot);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    pub(super) fn observation(&self) -> &'static str {
        match (self.snapshot.is_some(), self.error.is_some()) {
            (true, false) => "OBSERVED",
            (true, true) => "STALE",
            (false, true) => "UNAVAILABLE",
            (false, false) => "CONNECTING",
        }
    }

    pub(super) fn status(&self) -> String {
        self.snapshot
            .as_ref()
            .map(|s| {
                format!(
                    "submissions snapshot {} · {}{}",
                    s.as_of_sequence,
                    s.observed_at,
                    if s.data.next_after.is_some() {
                        " · more submissions available"
                    } else {
                        ""
                    }
                )
            })
            .unwrap_or_else(|| "submissions snapshot UNKNOWN".into())
    }

    pub(super) fn rows(&self) -> Vec<Row> {
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        snapshot.data.commands.iter().map(|command| row(
            command, &command.id, format!("[{}] {} submission", command.status, command.kind),
            format!("id             {}\nkind           {}\nstatus         {}\npayload_digest {}\nas_of_sequence {}\nobserved_at    {}\nsource         {}\nExecution relationships require their own durable records.",
                command.id, command.kind, command.status, command.payload_digest,
                snapshot.as_of_sequence, snapshot.observed_at, snapshot.source),
        )).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_observation_rejects_regression_and_preserves_exact_digests() {
        let body = serde_json::json!({"data":{"commands":[{
            "id":format!("cmd_{}", "a".repeat(64)), "kind":"run_coding", "status":"PENDING",
            "payload_digest":"b".repeat(64), "result":null}], "next_after":null},
            "as_of_sequence":7,"observed_at":"2026-09-11T00:00:00Z","source":"bullet-kernel/sqlite-ledger"});
        let snapshot: CommandDiscoverySnapshot = crate::client::decode(&body).unwrap();
        let mut submissions = Submissions::default();
        submissions.update(Ok(snapshot.clone()));
        let rows = submissions.rows();
        assert!(rows[0].raw.contains(&"a".repeat(64)));
        assert!(rows[0].raw.contains(&"b".repeat(64)));
        assert!(rows[0].human.contains("as_of_sequence 7"));
        let mut older = snapshot;
        older.as_of_sequence = 6;
        submissions.update(Ok(older));
        assert_eq!(submissions.observation(), "STALE");
        assert_eq!(submissions.snapshot.as_ref().unwrap().as_of_sequence, 7);
        submissions.update(Err("FARMD_COMMANDS_REFUSED: HTTP 500".into()));
        assert_eq!(submissions.rows()[0].id, rows[0].id);
    }
}
