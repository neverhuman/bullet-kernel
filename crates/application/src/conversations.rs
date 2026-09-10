//! Human conversation intent; saving a message does not execute an agent turn.

use bullet_domain::{CommandId, Digest, DomainError};
use serde::{Deserialize, Serialize};

mod reads;
mod records;
mod refusal;
#[cfg(test)]
mod tests;

pub use reads::{
    ConversationIndex, ConversationMessage, ConversationPage, ConversationRole, ConversationStore,
    ConversationSummary,
};
pub use records::{ConversationMessageReceipt, HeadTurnReference, HEAD_TURN_OUTBOX_KIND};
pub use refusal::ConversationRefusal;

/// Mutation ingress for an operator-authored message.
pub const CONVERSATION_MESSAGE_KIND: &str = "conversation_message";
/// Closed conversation-message submission version.
pub const CONVERSATION_MESSAGE_SCHEMA: &str = "bullet.conversation-message.v1";
/// Limit on original UTF-8 content, before JSON escaping.
pub const MAX_MESSAGE_BYTES: usize = 32_768;
/// Exact integers shared by Rust and browser consumers.
pub const MAX_MESSAGE_SEQUENCE: u64 = 9_007_199_254_740_991;

/// Last observed message, checked atomically before appending to an existing thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationCursor {
    /// Server-owned thread identity.
    pub conversation_id: String,
    /// Exact last observed message identity.
    pub message_id: String,
    /// Its server-assigned position, including both human and assistant messages.
    pub sequence: u64,
}

impl ConversationCursor {
    /// Validate selectors; ownership and current position require a store transaction.
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_subject(&self.conversation_id, "cnv_")?;
        validate_subject(&self.message_id, "msg_")?;
        if !(1..=MAX_MESSAGE_SEQUENCE).contains(&self.sequence) {
            return Err(invalid("cursor sequence is outside the supported range"));
        }
        Ok(())
    }
}

/// Only a human message can enter through the public command API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessagePayload {
    /// Exact supported schema discriminator.
    pub schema_version: String,
    /// Null starts a thread; a cursor appends against the exact observed head.
    #[serde(deserialize_with = "required_cursor")]
    pub cursor: Option<ConversationCursor>,
    /// Original human content, preserved without trimming or rewriting.
    pub content: String,
}

impl ConversationMessagePayload {
    /// Decode the closed shape, refusing duplicate fields and unknown authority.
    pub fn parse(payload: &str) -> Result<Self, DomainError> {
        let value: Self = serde_json::from_str(payload).map_err(invalid)?;
        value.validate()?;
        Ok(value)
    }

    /// Validate byte and scalar limits without claiming the message was persisted.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != CONVERSATION_MESSAGE_SCHEMA {
            return Err(invalid("unsupported conversation message schema"));
        }
        validate_content(&self.content)?;
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }

    /// Stable field order with the complete original content and causal cursor.
    pub fn canonical_json(&self) -> Result<String, DomainError> {
        self.validate()?;
        serde_json::to_string(self).map_err(invalid)
    }
}

/// Validate complete message bytes, shared by persisted human and assistant turns.
pub fn validate_content(content: &str) -> Result<(), DomainError> {
    if content.trim().is_empty()
        || content.len() > MAX_MESSAGE_BYTES
        || content
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(invalid(
            "content must contain 1..=32768 UTF-8 bytes with only LF/TAB controls",
        ));
    }
    Ok(())
}

/// New thread identities are isolated to the authenticated operator and command.
pub fn conversation_id(operator: &str, command: &CommandId) -> Result<String, DomainError> {
    validate_subject(operator, "opr_")?;
    let seed = format!("bullet.conversation.v1\0{operator}\0{command}");
    Ok(format!("cnv_{}", Digest::of(seed.as_bytes()).to_hex()))
}

/// One exact command can create at most one human message identity.
#[must_use]
pub fn message_id(command: &CommandId) -> String {
    let seed = format!("bullet.conversation-message.v1\0{command}");
    format!("msg_{}", Digest::of(seed.as_bytes()).to_hex())
}

/// Complete selectors are validated before any database or client lookup.
pub fn validate_subject(subject: &str, prefix: &str) -> Result<(), DomainError> {
    crate::coding_tasks::validate_coding_subject(subject, prefix)
}

fn invalid(error: impl std::fmt::Display) -> DomainError {
    DomainError::Encoding(format!("CONVERSATION_MESSAGE_INVALID: {error}"))
}

fn required_cursor<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> Result<Option<ConversationCursor>, D::Error> {
    Option::<ConversationCursor>::deserialize(value)
}
