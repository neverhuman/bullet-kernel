//! Generated-model consumer. Never promote malformed data to an empty projection.

mod coherence;

#[path = "../../../contracts/generated/api.rs"]
pub(crate) mod models;

use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

static VALIDATORS: OnceLock<Mutex<BTreeMap<&'static str, jsonschema::Validator>>> = OnceLock::new();

pub(crate) fn decode<T: models::ApiModel>(value: &Value) -> Result<T, String> {
    let mut validators = VALIDATORS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "FARMD_SCHEMA_UNAVAILABLE")?;
    if !validators.contains_key(T::SCHEMA_NAME) {
        let mut schema: Value =
            serde_json::from_str(include_str!("../../../contracts/generated/api.schema.json"))
                .map_err(|_| "FARMD_SCHEMA_INVALID")?;
        schema["$ref"] = Value::String(format!("#/$defs/{}", T::SCHEMA_NAME));
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|_| "FARMD_SCHEMA_INVALID")?;
        validators.insert(T::SCHEMA_NAME, validator);
    }
    if !validators[T::SCHEMA_NAME].is_valid(value) {
        return Err(format!("FARMD_MODEL_INVALID: {}", T::SCHEMA_NAME));
    }
    serde_json::from_value(value.clone())
        .map_err(|_| format!("FARMD_MODEL_INVALID: {}", T::SCHEMA_NAME))
}

pub(crate) fn snapshot_response(
    response: crate::coding::http::HttpResponse,
) -> Result<models::OperatorSnapshot, String> {
    if response.status != 200 {
        return Err(format!("FARMD_SNAPSHOT_REFUSED: HTTP {}", response.status));
    }
    let snapshot: models::OperatorSnapshot = decode(&response.body)?;
    if response.sequence != Some(snapshot.as_of_sequence)
        || snapshot.source != "bullet-kernel/sqlite-ledger"
        || snapshot.data.audit.latest_sequence != snapshot.as_of_sequence
    {
        return Err("FARMD_SNAPSHOT_INCOMPATIBLE".into());
    }
    coherence::validate(&snapshot.data)?;
    Ok(snapshot)
}

#[cfg(unix)]
pub(crate) fn operator_snapshot(
    credentials: &crate::auth::store::Credentials,
) -> Result<models::OperatorSnapshot, String> {
    snapshot_response(crate::coding::http::request(
        &credentials.farmd,
        "GET",
        "/api/v1/operator-snapshot",
        &[
            ("Cookie", &credentials.cookie),
            ("Origin", &credentials.origin),
        ],
        None,
    )?)
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct CodingCommand {
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) kind: String,
    pub(crate) blockers: Vec<String>,
}

#[cfg(unix)]
pub(crate) fn coding_commands(
    credentials: &crate::auth::store::Credentials,
    after: u64,
) -> Result<(Vec<CodingCommand>, Option<u64>), String> {
    let response = crate::coding::http::request_query(
        &credentials.farmd,
        "GET",
        "/api/v1/commands",
        &[("after", &after.to_string()), ("limit", "50")],
        &[
            ("Cookie", &credentials.cookie),
            ("Origin", &credentials.origin),
        ],
        None,
    )?;
    if response.status != 200 {
        return Err(format!("FARMD_COMMANDS_REFUSED: HTTP {}", response.status));
    }
    let commands = response.body["data"]["commands"]
        .as_array()
        .ok_or("FARMD_COMMANDS_INVALID")?;
    let next_after = response.body["data"]["next_after"].as_u64();
    Ok((
        commands
            .iter()
            .filter(|command| command["kind"] == "run_coding")
            .filter_map(|command| {
                Some(CodingCommand {
                    id: command["id"].as_str()?.to_owned(),
                    status: command["status"].as_str()?.to_owned(),
                    kind: command["kind"].as_str()?.to_owned(),
                    blockers: command["blockers"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|blocker| {
                            blocker["code"]
                                .as_str()
                                .or_else(|| blocker.as_str())
                                .map(str::to_owned)
                        })
                        .collect(),
                })
            })
            .collect(),
        next_after,
    ))
}

/// Same required names as `coding harness-check`; does not spawn a provider.
pub(crate) fn harness_outcome() -> &'static str {
    const REQUIRED: &[&str] = &[
        "BULLET_HARNESS_HOME",
        "BULLET_HARNESS_WORK_PACKAGE_ID",
        "BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST",
        "BULLET_HARNESS_CANDIDATE_VERIFICATION_KEY",
        "BULLET_HARNESS_WORKSPACE_ROOT",
        "BULLET_HARNESS_SOURCE_REPO",
        "BULLET_HARNESS_BASE_SHA",
        "BULLET_HARNESS_PRESERVATION",
        "BULLET_HARNESS_OBJECTIVE",
        "BULLET_HARNESS_GATE_ID",
        "BULLET_HARNESS_SCOPE",
        "BULLET_HARNESS_IDEMPOTENCY_KEY",
        "BULLET_HARNESS_LEASE_SOCKET",
        "BULLET_HARNESS_FARMD_UID",
        "BULLET_HARNESS_SOCKET_GID",
        "BULLET_HARNESS_LEASE_RECOVERY",
        "BULLET_HARNESS_EXECUTABLE",
    ];
    if REQUIRED.iter().all(|name| {
        std::env::var(name)
            .ok()
            .is_some_and(|value| !value.is_empty())
    }) {
        "BOUND"
    } else {
        "UNBOUND"
    }
}

/// Escape terminal controls and directional overrides without changing ordinary Unicode.
pub(crate) fn terminal_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn generated_bootstrap_model_rejects_missing_extra_and_malformed_secrets() {
        let valid = json!({"status":"AUTHENTICATED", "csrf_token":format!("csrf_{}", "a".repeat(64)), "expires_in_seconds": 28800});
        assert!(decode::<models::BootstrapResponse>(&valid).is_ok());
        for changed in [
            json!({}),
            json!({"status":"AUTHENTICATED","csrf_token":"bad","expires_in_seconds":1}),
            json!({"status":"AUTHENTICATED","csrf_token":format!("csrf_{}", "a".repeat(64)),"expires_in_seconds":1,"unexpected":true}),
        ] {
            assert!(decode::<models::BootstrapResponse>(&changed).is_err());
        }
        assert!(decode::<models::CommandStatus>(&valid).is_err());
    }
    #[test]
    fn terminal_controls_and_directional_overrides_are_visible_text() {
        let value = terminal_text("title\x1b]52;clipboard\x07\r\n\u{202e}合法");
        assert!(!value.chars().any(char::is_control));
        assert!(value.contains("\\u{1b}"));
        assert!(value.contains("合法"));
    }
}
