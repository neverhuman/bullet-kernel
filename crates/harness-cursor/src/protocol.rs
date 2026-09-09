//! Cursor ACP lexical validation and transcript binding helpers.

use crate::parse::{CursorAcpOutcome, CursorAcpTranscript, Phase};
use bullet_harness_core::{AgentEvent, AgentEventKind, HarnessError, NativeMeta};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::Path;

const AUTH_METHOD_LIMIT: usize = 8;

impl CursorAcpTranscript {
    /// Return a terminal result only after exact response validation.
    pub fn outcome(&self) -> Result<&CursorAcpOutcome, HarnessError> {
        if self.phase != Phase::Terminal {
            return Err(protocol("transcript has no terminal outcome"));
        }
        self.outcome
            .as_ref()
            .ok_or_else(|| protocol("terminal outcome missing"))
    }

    pub(super) fn binding_meta(&self, request_id: Option<u64>) -> Map<String, Value> {
        let mut meta = Map::from_iter([
            ("protocol".into(), json!("patch-proposal-v1")),
            ("subjectDigest".into(), json!(self.subject_digest)),
            (
                "runtimeVersion".into(),
                json!(self.expected_runtime_version),
            ),
            ("readOnly".into(), json!(true)),
        ]);
        if let Some(cwd) = &self.cwd {
            meta.insert("cwd".into(), json!(cwd));
        }
        if let Some(session_id) = &self.native_session_id {
            meta.insert("sessionId".into(), json!(session_id));
        }
        if let Some(request_id) = request_id {
            meta.insert("requestId".into(), json!(request_id));
        }
        meta
    }

    pub(super) fn validate_binding_meta<'a>(
        &self,
        value: &'a Value,
        request_id: Option<u64>,
        proposal_field: Option<&str>,
    ) -> Result<Option<&'a Value>, HarnessError> {
        let wrapper = object(value, "_meta")?;
        exact_fields(wrapper, &["bullet.farm"], &["bullet.farm"])?;
        let actual = object(wrapper.get("bullet.farm").expect("required"), "bullet.farm")?;
        let expected = self.binding_meta(request_id);
        for (key, value) in &expected {
            if actual.get(key) != Some(value) {
                return Err(protocol(format!("bullet.farm {key} binding mismatch")));
            }
        }
        let allowed: Vec<&str> = expected
            .keys()
            .map(String::as_str)
            .chain(proposal_field)
            .collect();
        exact_fields(actual, &allowed, &allowed)?;
        Ok(proposal_field.and_then(|field| actual.get(field)))
    }

    pub(super) fn session_id(&self) -> Result<&str, HarnessError> {
        self.native_session_id
            .as_deref()
            .ok_or_else(|| protocol("native session id is not established"))
    }

    pub(super) fn require_phase(
        &self,
        expected: Phase,
        operation: &str,
    ) -> Result<(), HarnessError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(protocol(format!(
                "{operation} invalid in phase {:?}",
                self.phase
            )))
        }
    }

    pub(super) fn event(
        &mut self,
        kind: AgentEventKind,
        payload: Value,
        native: &str,
    ) -> AgentEvent {
        self.event_serial += 1;
        self.normalizer.accept(
            kind,
            payload,
            &NativeMeta {
                event_id: Some(format!("{native}:{}", self.event_serial)),
                sequence: None,
            },
        )
    }

    pub(super) fn fail<T>(&mut self, reason: impl Into<String>) -> Result<T, HarnessError> {
        self.phase = Phase::Poisoned;
        Err(protocol(reason))
    }
}

pub(super) fn validate_capabilities(value: &Value) -> Result<(), HarnessError> {
    let capabilities = object(value, "agentCapabilities")?;
    exact_fields(
        capabilities,
        &[
            "loadSession",
            "promptCapabilities",
            "mcpCapabilities",
            "sessionCapabilities",
            "auth",
            "_meta",
        ],
        &["_meta"],
    )?;
    if capabilities
        .get("loadSession")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(protocol("loadSession capability must be boolean"));
    }
    validate_boolean_capability(
        capabilities.get("promptCapabilities"),
        "promptCapabilities",
        &["image", "audio", "embeddedContext"],
    )?;
    validate_boolean_capability(
        capabilities.get("mcpCapabilities"),
        "mcpCapabilities",
        &["http", "sse"],
    )?;
    validate_object_capability(
        capabilities.get("sessionCapabilities"),
        "sessionCapabilities",
        &["list", "resume", "close", "fork", "additionalDirectories"],
    )?;
    validate_object_capability(capabilities.get("auth"), "auth", &["logout"])?;
    let wrapper = object(
        capabilities.get("_meta").expect("required"),
        "capability _meta",
    )?;
    exact_fields(wrapper, &["bullet.farm"], &["bullet.farm"])?;
    let extension = object(
        wrapper.get("bullet.farm").expect("required"),
        "bullet capability",
    )?;
    exact_fields(
        extension,
        &["patchProposal", "readOnly"],
        &["patchProposal", "readOnly"],
    )?;
    if extension.get("patchProposal").and_then(Value::as_str) != Some("v1")
        || extension.get("readOnly").and_then(Value::as_bool) != Some(true)
    {
        return Err(protocol(
            "typed read-only proposal extension not advertised",
        ));
    }
    Ok(())
}

fn validate_boolean_capability(
    value: Option<&Value>,
    name: &str,
    fields: &[&str],
) -> Result<(), HarnessError> {
    let Some(value) = value else { return Ok(()) };
    let object = object(value, name)?;
    exact_fields(object, fields, &[])?;
    if object.values().any(|value| !value.is_boolean()) {
        return Err(protocol(format!("{name} values must be boolean")));
    }
    Ok(())
}

fn validate_object_capability(
    value: Option<&Value>,
    name: &str,
    fields: &[&str],
) -> Result<(), HarnessError> {
    let Some(value) = value else { return Ok(()) };
    let object = object(value, name)?;
    exact_fields(object, fields, &[])?;
    if object.values().any(|value| !value.is_object()) {
        return Err(protocol(format!("{name} values must be objects")));
    }
    Ok(())
}

pub(super) fn validate_agent_info(
    value: &Value,
    expected_version: &str,
) -> Result<(), HarnessError> {
    let info = object(value, "agentInfo")?;
    exact_fields(info, &["name", "title", "version"], &["name", "version"])?;
    bounded_string(info.get("name"), "agent name", 128)?;
    if bounded_string(info.get("version"), "agent version", 128)? != expected_version {
        return Err(protocol("Cursor runtime version binding mismatch"));
    }
    if let Some(title) = info.get("title") {
        bounded_string(Some(title), "agent title", 128)?;
    }
    Ok(())
}

pub(super) fn validate_auth_methods(value: &Value) -> Result<(), HarnessError> {
    let methods = value
        .as_array()
        .ok_or_else(|| protocol("authMethods must be an array"))?;
    if methods.is_empty() || methods.len() > AUTH_METHOD_LIMIT {
        return Err(protocol("authMethods count outside admitted bounds"));
    }
    let mut ids = BTreeSet::new();
    for method in methods {
        let method = object(method, "auth method")?;
        exact_fields(method, &["id", "name", "description"], &["id", "name"])?;
        let id = bounded_string(method.get("id"), "auth method id", 128)?;
        bounded_string(method.get("name"), "auth method name", 128)?;
        if let Some(description) = method.get("description") {
            bounded_string(Some(description), "auth description", 512)?;
        }
        if !ids.insert(id) {
            return Err(protocol("duplicate auth method id"));
        }
    }
    if !ids.contains("cursor_login") {
        return Err(protocol("cursor_login auth method not advertised"));
    }
    Ok(())
}

pub(super) fn exact_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), HarnessError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !object.contains_key(*key))
    {
        return Err(protocol("unknown or missing protocol field"));
    }
    Ok(())
}

pub(super) fn object<'a>(
    value: &'a Value,
    name: &str,
) -> Result<&'a Map<String, Value>, HarnessError> {
    value
        .as_object()
        .ok_or_else(|| protocol(format!("{name} must be an object")))
}

pub(super) fn bounded_string<'a>(
    value: Option<&'a Value>,
    name: &str,
    limit: usize,
) -> Result<&'a str, HarnessError> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= limit && !text.contains('\0'))
        .ok_or_else(|| protocol(format!("{name} must be a nonempty bounded string")))
}

pub(super) fn valid_token(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

pub(super) fn valid_subject_digest(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

pub(super) fn valid_cwd(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.contains('\0')
        && Path::new(value).is_absolute()
}

pub(super) fn valid_native_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(super) fn protocol(reason: impl Into<String>) -> HarnessError {
    HarnessError::Protocol {
        provider: "cursor".to_string(),
        reason: reason.into(),
    }
}
