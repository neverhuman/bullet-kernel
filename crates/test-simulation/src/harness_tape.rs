//! Recorded provider event tapes. Required CI never talks to a live model.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// One JSONL tape of normalized harness events.
#[derive(Debug, Clone)]
pub struct HarnessTape {
    /// Fixture file name.
    pub name: String,
    /// Events in order.
    pub events: Vec<Value>,
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/harness")
}

/// Load a JSONL tape from `tests/fixtures/harness/<name>.jsonl`.
///
/// # Errors
///
/// Returns a store-style string when the file is missing or a line is not JSON.
pub fn load_tape(name: &str) -> Result<HarnessTape, String> {
    let path = fixture_dir().join(format!("{name}.jsonl"));
    let text = fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    let mut events = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|err| format!("{}:{}: {err}", path.display(), idx + 1))?;
        events.push(value);
    }
    Ok(HarnessTape {
        name: name.to_string(),
        events,
    })
}

/// False completion is never an authoritative PASS.
#[must_use]
pub fn tape_claims_authoritative_done(tape: &HarnessTape) -> bool {
    tape.events.iter().any(|event| {
        event.get("kind").and_then(Value::as_str) == Some("false_completion")
            && event.get("authoritative").and_then(Value::as_bool) == Some(true)
    })
}
