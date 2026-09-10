use super::ConversationCursor;
use crate::operator_commands::OperatorCommandError;

/// Authorship is established by distinct human ingress and native head outcome ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationRole {
    /// Authenticated operator message.
    User,
    /// Validated native head response; a queue request alone cannot establish it.
    Assistant,
}

/// One complete immutable message; clients never reconstruct it from local history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationMessage {
    /// Exact position of this message in its thread.
    pub cursor: ConversationCursor,
    /// Prior message in the same durable history.
    pub parent_message_id: Option<String>,
    /// Validated author class.
    pub role: ConversationRole,
    /// Complete original content, without trimming or a generated summary.
    pub content: String,
    /// Digest of those exact UTF-8 bytes.
    pub content_digest: String,
    /// Original human command, absent for an assistant response.
    pub command_id: Option<String>,
    /// Requested turn for a human message, or observed cause of an assistant reply.
    pub head_turn_id: String,
    /// Original store timestamp.
    pub accepted_at: String,
}

/// One read transaction's complete-message page and current thread head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationPage {
    /// Exact current head, independent of page position.
    pub cursor: ConversationCursor,
    /// Complete messages in increasing message-sequence order.
    pub messages: Vec<ConversationMessage>,
    /// Exclusive message-sequence cursor for the next page, when more remain.
    pub next_after: Option<u64>,
    /// Current head scheduling blocker; saving a human message is not a reply.
    pub head_blocker: String,
    /// Global audit watermark covered by this same snapshot.
    pub as_of_sequence: u64,
    /// Store observation timestamp.
    pub observed_at: String,
}

/// A stable thread entry, ordered by its immutable creation event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationSummary {
    /// Current last message in the thread.
    pub cursor: ConversationCursor,
    /// Short excerpt of the original human message, for thread navigation only.
    pub preview: String,
    /// Original thread creation timestamp.
    pub created_at: String,
    /// Current last-message timestamp.
    pub last_activity_at: String,
}

/// Owner-scoped thread discovery after client cache loss.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationIndex {
    /// Validated threads in immutable creation order.
    pub conversations: Vec<ConversationSummary>,
    /// Exclusive creation-event cursor for the next page.
    pub next_after: Option<u64>,
    /// Global audit watermark covered by this same read transaction.
    pub as_of_sequence: u64,
    /// Store observation timestamp.
    pub observed_at: String,
}

/// Conversation projections share the authenticated command owner's durable store.
pub trait ConversationStore {
    /// Read complete messages from one owned thread; foreign/absent threads are absent.
    fn get_operator_conversation(
        &self,
        operator: &str,
        conversation: &str,
        after: u64,
        limit: u32,
    ) -> Result<Option<ConversationPage>, OperatorCommandError>;

    /// Discover owned threads using a stable creation cursor, bounded to 100 entries.
    fn list_operator_conversations(
        &self,
        operator: &str,
        after: u64,
        limit: u32,
    ) -> Result<ConversationIndex, OperatorCommandError>;
}
