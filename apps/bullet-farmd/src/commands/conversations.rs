//! Authenticated conversation projections from one durable ledger snapshot.
use super::{discovery::query, operator_error};
use crate::{api::SharedState, errors::ApiError};
use axum::{
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use bullet_application::conversations::{self as app, ConversationRole, ConversationStore};

#[path = "../../../../contracts/generated/api.rs"]
mod wire;

fn cursor(value: app::ConversationCursor) -> wire::ConversationCursor {
    wire::ConversationCursor {
        conversation_id: value.conversation_id,
        message_id: value.message_id,
        sequence: value.sequence,
    }
}

fn message(value: app::ConversationMessage) -> wire::ConversationMessage {
    wire::ConversationMessage {
        cursor: cursor(value.cursor),
        parent_message_id: value.parent_message_id,
        role: match value.role {
            ConversationRole::User => "user",
            ConversationRole::Assistant => "assistant",
        }
        .into(),
        content: value.content,
        content_digest: value.content_digest,
        command_id: value.command_id,
        head_turn_id: value.head_turn_id,
        accepted_at: value.accepted_at,
    }
}

fn response<T: serde::Serialize>(body: T, sequence: u64) -> Result<Response, ApiError> {
    if sequence > 9_007_199_254_740_991 {
        return Err(ApiError::UnsafeInteger(
            "ConversationSnapshot.as_of_sequence",
        ));
    }
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        "x-bullet-as-of-sequence",
        HeaderValue::from_str(&sequence.to_string())
            .map_err(|error| ApiError::Internal(error.to_string()))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(crate) async fn get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let operator = state
        .auth
        .lock()
        .await
        .authorize_session(&headers)?
        .operator_id;
    let (after, limit) = query(raw.as_deref())?;
    let page = state
        .ledger
        .lock()
        .await
        .get_operator_conversation(&operator, &id, after, limit)
        .map_err(operator_error)?
        .ok_or_else(|| ApiError::NotFound("conversation".into()))?;
    let sequence = page.as_of_sequence;
    response(
        wire::ConversationSnapshot {
            data: wire::ConversationView {
                cursor: cursor(page.cursor),
                messages: page.messages.into_iter().map(message).collect(),
                next_after: page.next_after,
                head_blocker: page.head_blocker,
            },
            as_of_sequence: sequence,
            observed_at: page.observed_at,
            source: "bullet-kernel/sqlite-ledger".into(),
        },
        sequence,
    )
}

pub(crate) async fn list(
    State(state): State<SharedState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let operator = state
        .auth
        .lock()
        .await
        .authorize_session(&headers)?
        .operator_id;
    let (after, limit) = query(raw.as_deref())?;
    let page = state
        .ledger
        .lock()
        .await
        .list_operator_conversations(&operator, after, limit)
        .map_err(operator_error)?;
    let sequence = page.as_of_sequence;
    response(
        wire::ConversationIndexSnapshot {
            data: wire::ConversationIndexView {
                conversations: page
                    .conversations
                    .into_iter()
                    .map(|value| wire::ConversationSummary {
                        cursor: cursor(value.cursor),
                        preview: value.preview,
                        created_at: value.created_at,
                        last_activity_at: value.last_activity_at,
                    })
                    .collect(),
                next_after: page.next_after,
            },
            as_of_sequence: sequence,
            observed_at: page.observed_at,
            source: "bullet-kernel/sqlite-ledger".into(),
        },
        sequence,
    )
}
