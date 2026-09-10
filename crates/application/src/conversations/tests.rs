use super::*;

fn payload() -> ConversationMessagePayload {
    ConversationMessagePayload {
        schema_version: CONVERSATION_MESSAGE_SCHEMA.into(),
        cursor: None,
        content: "  Improve the Rust API.\n\tKeep the existing behavior.  ".into(),
    }
}

#[test]
fn message_shape_refuses_forged_roles_authority_duplicates_and_missing_cursor() {
    let original = payload();
    let encoded = original.canonical_json().unwrap();
    assert_eq!(
        ConversationMessagePayload::parse(&encoded).unwrap(),
        original
    );
    for field in [
        "role",
        "operator_id",
        "model",
        "account_id",
        "assistant_reply",
        "run_id",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = serde_json::json!("forged");
        assert!(
            ConversationMessagePayload::parse(&value.to_string()).is_err(),
            "{field}"
        );
    }
    let mut value = serde_json::to_value(&original).unwrap();
    value.as_object_mut().unwrap().remove("cursor");
    assert!(ConversationMessagePayload::parse(&value.to_string()).is_err());
    let duplicate = encoded.replacen('{', "{\"content\":\"substituted\",", 1);
    assert!(ConversationMessagePayload::parse(&duplicate).is_err());
    let mut unsupported = original;
    unsupported.schema_version = "bullet.conversation-message.v2".into();
    assert!(unsupported.validate().is_err());
}

#[test]
fn message_byte_limits_preserve_original_text_and_bound_json_expansion() {
    let mut value = payload();
    for content in [
        "x".repeat(MAX_MESSAGE_BYTES),
        "🦀".repeat(MAX_MESSAGE_BYTES / 4),
    ] {
        value.content = content.clone();
        let encoded = value.canonical_json().unwrap();
        assert_eq!(
            ConversationMessagePayload::parse(&encoded).unwrap().content,
            content
        );
        value.content.push('x');
        assert!(value.validate().is_err());
    }
    value.content = format!("x{}", "\t".repeat(MAX_MESSAGE_BYTES - 1));
    assert!(value.canonical_json().unwrap().len() < 2 * MAX_MESSAGE_BYTES + 128);
    for content in [
        "",
        " \n\t",
        "\u{2003}",
        "hello\u{1b}[2J",
        "hello\0",
        "a\rb",
        "a\u{85}b",
    ] {
        value.content = content.into();
        assert!(value.validate().is_err(), "{content:?}");
    }
}

#[test]
fn conversation_cursor_and_server_ids_preserve_exact_causal_subjects() {
    let command = CommandId::from_seed("conversation-message-test");
    let operator = format!("opr_{}", Digest::of(b"operator").to_hex());
    let thread = conversation_id(&operator, &command).unwrap();
    let message = message_id(&command);
    let mut cursor = ConversationCursor {
        conversation_id: thread.clone(),
        message_id: message.clone(),
        sequence: 1,
    };
    cursor.validate().unwrap();
    assert_eq!(conversation_id(&operator, &command).unwrap(), thread);
    assert_eq!(message_id(&command), message);
    let other_operator = format!("opr_{}", Digest::of(b"other-operator").to_hex());
    assert_ne!(conversation_id(&other_operator, &command).unwrap(), thread);
    assert_ne!(message_id(&CommandId::from_seed("other-command")), message);
    assert!(conversation_id("opr_short", &command).is_err());
    for sequence in [0, MAX_MESSAGE_SEQUENCE + 1, u64::MAX] {
        cursor.sequence = sequence;
        assert!(cursor.validate().is_err());
    }
    cursor.sequence = MAX_MESSAGE_SEQUENCE;
    cursor.validate().unwrap();
    let mut value = payload();
    value.cursor = Some(cursor.clone());
    assert_eq!(
        ConversationMessagePayload::parse(&value.canonical_json().unwrap()).unwrap(),
        value
    );
    cursor.message_id = thread;
    assert!(cursor.validate().is_err());
    cursor.message_id = message;
    cursor.conversation_id.push('0');
    assert!(cursor.validate().is_err());
}

#[test]
fn saved_receipt_binds_original_command_bytes_without_copying_human_content() {
    use crate::CommandRequest;
    let content = "private human text";
    let payload = ConversationMessagePayload {
        content: content.into(),
        ..payload()
    };
    let original = CommandRequest::new(
        "original-order",
        CONVERSATION_MESSAGE_KIND,
        &serde_json::to_value(&payload).unwrap(),
    )
    .unwrap();
    assert_ne!(original.payload, payload.canonical_json().unwrap());
    let owner = format!("opr_{}", Digest::of(b"receipt-owner").to_hex());
    let thread = conversation_id(&owner, &original.id()).unwrap();
    let receipt = ConversationMessageReceipt::for_request(&original, &thread, 1).unwrap();
    let reference = HeadTurnReference::for_request(&original, &receipt).unwrap();
    assert_eq!(reference.request_digest, original.digest().to_hex());
    assert_eq!(
        receipt.content_digest,
        Digest::of(content.as_bytes()).to_hex()
    );
    assert!(!serde_json::to_string(&reference).unwrap().contains(content));
    let mut corrupt = receipt;
    corrupt.head_turn_id = format!("hdt_{}", Digest::of(b"substitution").to_hex());
    assert!(HeadTurnReference::for_request(&original, &corrupt).is_err());
}

#[test]
fn conversation_refusals_keep_typed_identity_through_durable_error_encoding() {
    use crate::{graph_delta::GraphDeltaFailure, LedgerError};
    for reason in [
        ConversationRefusal::NotFound,
        ConversationRefusal::CursorConflict,
        ConversationRefusal::SequenceExhausted,
        ConversationRefusal::OperatorIngressRequired,
    ] {
        let original = LedgerError::from(reason);
        let encoded = serde_json::to_string(&GraphDeltaFailure::from_error(&original)).unwrap();
        let restored: GraphDeltaFailure = serde_json::from_str(&encoded).unwrap();
        assert!(
            matches!(restored.into_error(), LedgerError::Conversation(value) if value == reason)
        );
        assert_eq!(original.reason_code(), reason.reason_code());
        assert!(!reason.repair().is_empty());
    }
}
