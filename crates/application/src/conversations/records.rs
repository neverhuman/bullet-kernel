use super::{invalid, message_id, ConversationCursor, ConversationMessagePayload};
use crate::CommandRequest;
use bullet_domain::{Digest, DomainError};
use serde::{Deserialize, Serialize};

/// A separate consumer owns head turns; coding Runners must not claim these rows.
pub const HEAD_TURN_OUTBOX_KIND: &str = "conversation_head_turn";

/// Acknowledges only that the human message and its turn request were saved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageReceipt {
    /// Exact local persistence receipt version.
    pub schema_version: String,
    /// Newly committed message position, not necessarily the current thread tip.
    pub cursor: ConversationCursor,
    /// Digest of complete original message content; no content enters audit streams.
    pub content_digest: String,
    /// Durable requested head turn, carrying no provider execution authority.
    pub head_turn_id: String,
}

impl ConversationMessageReceipt {
    /// Derive a receipt for a validated command at its transaction-assigned position.
    pub fn for_request(
        request: &CommandRequest,
        conversation_id: &str,
        sequence: u64,
    ) -> Result<Self, DomainError> {
        request.validate()?;
        if request.kind != super::CONVERSATION_MESSAGE_KIND {
            return Err(invalid(
                "saved-message receipt requires a conversation command",
            ));
        }
        let payload = ConversationMessagePayload::parse(&request.payload)?;
        let message_id = message_id(&request.id());
        let seed = format!("bullet.conversation-head-turn.v1\0{message_id}");
        let cursor = ConversationCursor {
            conversation_id: conversation_id.into(),
            message_id,
            sequence,
        };
        cursor.validate()?;
        Ok(Self {
            schema_version: "bullet.conversation-message-receipt.v1".into(),
            cursor,
            content_digest: Digest::of(payload.content.as_bytes()).to_hex(),
            head_turn_id: format!("hdt_{}", Digest::of(seed.as_bytes()).to_hex()),
        })
    }
}

/// Reference-only durable queue payload; private content stays in message storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadTurnReference {
    /// Exact queue reference version.
    pub schema_version: String,
    /// Command whose original bytes were accepted.
    pub command_id: String,
    /// Digest of those exact command bytes, independent of struct field ordering.
    pub request_digest: String,
    /// Immutable causal input boundary for this requested turn.
    pub message: ConversationMessageReceipt,
}

impl HeadTurnReference {
    /// Bind the original command digest and complete causal message reference.
    pub fn for_request(
        request: &CommandRequest,
        receipt: &ConversationMessageReceipt,
    ) -> Result<Self, DomainError> {
        let expected = ConversationMessageReceipt::for_request(
            request,
            &receipt.cursor.conversation_id,
            receipt.cursor.sequence,
        )?;
        if &expected != receipt {
            return Err(invalid(
                "head turn reference does not match its accepted message",
            ));
        }
        Ok(Self {
            schema_version: "bullet.conversation-head-reference.v1".into(),
            command_id: request.id().to_string(),
            request_digest: request.digest().to_hex(),
            message: receipt.clone(),
        })
    }
}
