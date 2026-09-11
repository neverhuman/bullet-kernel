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
pub(crate) fn authenticated_get(
    credentials: &crate::auth::store::Credentials,
    path: &str,
    query: &[(&str, &str)],
) -> Result<crate::coding::http::HttpResponse, String> {
    let owner = crate::auth::session::status(credentials)?;
    crate::coding::http::request_query(
        &credentials.farmd,
        "GET",
        path,
        query,
        &[
            ("Cookie", &credentials.cookie),
            ("Origin", &credentials.origin),
            ("x-bullet-expected-session", &owner.session_id),
        ],
        None,
    )
}

#[cfg(unix)]
pub(crate) fn operator_snapshot(
    credentials: &crate::auth::store::Credentials,
) -> Result<models::OperatorSnapshot, String> {
    snapshot_response(authenticated_get(
        credentials,
        "/api/v1/operator-snapshot",
        &[],
    )?)
}

#[cfg(unix)]
pub(crate) fn coding_commands(
    credentials: &crate::auth::store::Credentials,
) -> Result<models::CommandDiscoverySnapshot, String> {
    command_response(authenticated_get(credentials, "/api/v1/commands", &[])?)
}

#[cfg(all(test, unix))]
mod session_binding_tests;

pub(crate) fn command_response(
    response: crate::coding::http::HttpResponse,
) -> Result<models::CommandDiscoverySnapshot, String> {
    if response.status != 200 {
        return Err(format!("FARMD_COMMANDS_REFUSED: HTTP {}", response.status));
    }
    let snapshot: models::CommandDiscoverySnapshot = decode(&response.body)?;
    let mut ids = std::collections::BTreeSet::new();
    if response.sequence != Some(snapshot.as_of_sequence)
        || snapshot.source != "bullet-kernel/sqlite-ledger"
        || snapshot.data.commands.len() > 100
        || snapshot
            .data
            .commands
            .iter()
            .any(|command| !ids.insert(&command.id))
    {
        return Err("FARMD_COMMANDS_INCOMPATIBLE".into());
    }
    Ok(snapshot)
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
