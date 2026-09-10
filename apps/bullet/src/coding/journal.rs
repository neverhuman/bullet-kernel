//! Durable request identity precedes all submission network effects.

use super::{credentials::Session, SubmitRequest};
use bullet_application::CommandRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    farmd: String,
    origin: String,
    envelope: Value,
}

#[cfg(unix)]
pub(super) fn prepare(
    session: &Session,
    input: &SubmitRequest<'_>,
) -> Result<(Value, CommandRequest), String> {
    use crate::auth::store::CredentialStore;
    let key = match input.idempotency_key {
        Some(key) => key.to_owned(),
        None => format!("cli_{}", super::random_hex(16)?),
    };
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err("COMMAND_KEY_INVALID: require 1..=256 non-control UTF-8 bytes".into());
    }
    let id = bullet_domain::CommandId::from_seed(&key);
    let store = CredentialStore::open(&session.directory)?;
    let envelope = match store.load_command(&id)? {
        Some(value) => {
            let recorded: Journal =
                serde_json::from_value(value).map_err(|_| "COMMAND_JOURNAL_CORRUPT")?;
            validate_retry(&recorded, session, input, &key)?;
            recorded.envelope
        }
        None => {
            let mut proposed = super::run_coding_envelope(
                input.account,
                input.provider,
                input.model,
                input.expected_revision,
            )?;
            proposed["idempotency_key"] = Value::String(key.clone());
            CommandRequest::new(&key, "run_coding", &proposed["payload"])
                .map_err(|_| "COMMAND_REQUEST_INVALID")?;
            let record = Journal {
                schema_version: 1,
                farmd: session.farmd.clone(),
                origin: session.origin.clone(),
                envelope: proposed.clone(),
            };
            store.record_command(
                &id,
                &serde_json::to_value(record).map_err(|_| "COMMAND_JOURNAL_ENCODING_FAILED")?,
            )?;
            proposed
        }
    };
    let request = CommandRequest::new(&key, "run_coding", &envelope["payload"])
        .map_err(|_| "COMMAND_JOURNAL_CORRUPT")?;
    Ok((envelope, request))
}

#[cfg(not(unix))]
pub(super) fn prepare(
    _session: &Session,
    _input: &SubmitRequest<'_>,
) -> Result<(Value, CommandRequest), String> {
    Err("AUTH_PRIVATE_STORE_UNSUPPORTED".into())
}

#[cfg(unix)]
fn validate_retry(
    record: &Journal,
    session: &Session,
    input: &SubmitRequest<'_>,
    key: &str,
) -> Result<(), String> {
    let _: crate::client::models::CommandEnvelope =
        crate::client::decode(&record.envelope).map_err(|_| "COMMAND_JOURNAL_CORRUPT")?;
    if record.schema_version != 1
        || record.farmd != session.farmd
        || record.origin != session.origin
        || record.envelope["idempotency_key"] != key
        || record.envelope["kind"] != "run_coding"
        || record.envelope["payload"]["account_id"] != input.account.trim()
        || record.envelope["payload"]["provider"] != input.provider
        || record.envelope["payload"]["model"] != input.model.trim()
        || record.envelope["payload"]["expected_revision"] != input.expected_revision
    {
        return Err(
            "IDEMPOTENCY_CONFLICT: this key already binds another request or endpoint".into(),
        );
    }
    Ok(())
}

pub(super) fn correlate(request: &CommandRequest, response: &Value) -> Result<(), String> {
    if response["id"] != request.id().as_str()
        || response["kind"] != request.kind
        || response["payload_digest"] != request.digest().to_hex()
    {
        return Err("FARMD_COMMAND_SUBJECT_MISMATCH: preserve the original journal and reconcile its command id".into());
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn reconciliation_request(
    session: &Session,
    id: &str,
) -> Result<Option<CommandRequest>, String> {
    let id = bullet_domain::CommandId::parse(id).map_err(|_| "COMMAND_ID_INVALID")?;
    let store = crate::auth::store::CredentialStore::open(&session.directory)?;
    let Some(value) = store.load_command(&id)? else {
        return Ok(None);
    };
    let record: Journal = serde_json::from_value(value).map_err(|_| "COMMAND_JOURNAL_CORRUPT")?;
    let envelope: crate::client::models::CommandEnvelope =
        crate::client::decode(&record.envelope).map_err(|_| "COMMAND_JOURNAL_CORRUPT")?;
    if record.schema_version != 1
        || record.farmd != session.farmd
        || record.origin != session.origin
    {
        return Err("COMMAND_JOURNAL_ENDPOINT_MISMATCH".into());
    }
    let request = CommandRequest::new(envelope.idempotency_key, envelope.kind, &envelope.payload)
        .map_err(|_| "COMMAND_JOURNAL_CORRUPT")?;
    if request.id() != id {
        return Err("COMMAND_JOURNAL_SUBJECT_MISMATCH".into());
    }
    Ok(Some(request))
}

#[cfg(not(unix))]
pub(super) fn reconciliation_request(
    _session: &Session,
    _id: &str,
) -> Result<Option<CommandRequest>, String> {
    Err("AUTH_PRIVATE_STORE_UNSUPPORTED".into())
}

#[cfg(all(test, unix))]
mod tests;
