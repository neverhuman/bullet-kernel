//! Typed admission refusals expose no foreign conversation contents.

/// A valid human-message request conflicts with durable conversation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConversationRefusal {
    /// The selected thread is absent or belongs to another operator.
    NotFound,
    /// Another message was committed after the client's observed head.
    CursorConflict,
    /// The thread cannot represent another exact browser-safe sequence.
    SequenceExhausted,
    /// Public human content arrived without an authenticated operator.
    OperatorIngressRequired,
}

impl ConversationRefusal {
    /// Stable machine-readable reason independent of diagnostic wording.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::NotFound => "CONVERSATION_NOT_FOUND",
            Self::CursorConflict => "CONVERSATION_CURSOR_CONFLICT",
            Self::SequenceExhausted => "CONVERSATION_SEQUENCE_EXHAUSTED",
            Self::OperatorIngressRequired => "CONVERSATION_OPERATOR_INGRESS_REQUIRED",
        }
    }

    /// Concrete recovery action; an unchanged fresh request cannot fix these refusals.
    #[must_use]
    pub const fn repair(self) -> &'static str {
        match self {
            Self::NotFound => {
                "Open a conversation from this operator's history, or start a new one."
            }
            Self::CursorConflict => {
                "Refresh this conversation, then submit against its current last message."
            }
            Self::SequenceExhausted => {
                "Start a new conversation; this thread's history remains available."
            }
            Self::OperatorIngressRequired => {
                "Authenticate and submit through POST /api/v1/commands."
            }
        }
    }
}

impl std::fmt::Display for ConversationRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ConversationRefusal {}
