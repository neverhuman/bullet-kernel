//! Agreement between authored schema, generated consumers and durable message types.
use crate::client::{decode, models};
use bullet_application::{
    conversations::{
        ConversationMessagePayload, ConversationMessageReceipt, CONVERSATION_MESSAGE_SCHEMA,
    },
    CommandRequest,
};
use serde_json::{json, Value};

#[test]
fn conversation_payload_and_receipt_match_generated_models_and_closed_runtime_roots() {
    let payload = ConversationMessagePayload {
        schema_version: CONVERSATION_MESSAGE_SCHEMA.into(),
        cursor: None,
        content: "Full goal 🦀\n".into(),
    };
    let value = serde_json::to_value(&payload).unwrap();
    let decoded = decode::<models::ConversationMessagePayload>(&value).unwrap();
    assert_eq!(decoded.content, payload.content);
    assert!(decoded.cursor.is_none());
    let request = CommandRequest::new("contract-message", "conversation_message", &value).unwrap();
    let operator = format!("opr_{}", "1".repeat(64));
    let thread =
        bullet_application::conversations::conversation_id(&operator, &request.id()).unwrap();
    let receipt = ConversationMessageReceipt::for_request(&request, &thread, 1).unwrap();
    let value = serde_json::to_value(&receipt).unwrap();
    let decoded = decode::<models::ConversationMessageReceipt>(&value).unwrap();
    assert_eq!(decoded.cursor.conversation_id, thread);
    assert_eq!(decoded.content_digest, receipt.content_digest);
    let source: serde_yaml::Value = serde_yaml::from_str(
        &std::fs::read_to_string(super::repo_root().join("contracts/openapi.yaml")).unwrap(),
    )
    .unwrap();
    let runtime =
        super::runtime_schema(source["components"]["schemas"].as_mapping().unwrap()).unwrap();
    for name in [
        "ConversationMessagePayload",
        "ConversationMessageReceipt",
        "ConversationView",
        "ConversationIndexView",
    ] {
        assert_eq!(runtime["$defs"][name]["additionalProperties"], false);
    }
    let mut malformed = serde_json::to_value(&payload).unwrap();
    malformed.as_object_mut().unwrap().remove("cursor");
    assert!(decode::<models::ConversationMessagePayload>(&malformed).is_err());
    malformed["cursor"] = Value::Null;
    malformed["role"] = json!("assistant");
    assert!(decode::<models::ConversationMessagePayload>(&malformed).is_err());
    let mut malformed = value;
    malformed["cursor"]["sequence"] = json!(9_007_199_254_740_992u64);
    assert!(decode::<models::ConversationMessageReceipt>(&malformed).is_err());
}

#[test]
fn conversation_snapshot_decoder_rejects_malformed_author_identity_and_watermarks() {
    let cursor = json!({"conversation_id":format!("cnv_{}", "a".repeat(64)),
        "message_id":format!("msg_{}", "b".repeat(64)),"sequence":1});
    let value = json!({"data":{"cursor":cursor,"messages":[{
        "cursor":cursor,"parent_message_id":null,"role":"user","content":"goal",
        "content_digest":"c".repeat(64),"command_id":format!("cmd_{}", "d".repeat(64)),
        "head_turn_id":format!("hdt_{}", "e".repeat(64)),"accepted_at":"2026-09-10T00:00:00.000Z"
    }],"next_after":null,"head_blocker":"HEAD_RUNTIME_BINDING_REQUIRED"},
        "as_of_sequence":2,"observed_at":"2026-09-10T00:00:00.001Z","source":"bullet-kernel/sqlite-ledger"});
    assert!(decode::<models::ConversationSnapshot>(&value).is_ok());
    for (pointer, replacement) in [
        ("/data/messages/0/role", json!("tool")),
        ("/data/messages/0/head_turn_id", json!("caller-choice")),
        ("/data/cursor/sequence", json!(0)),
        ("/as_of_sequence", json!(9_007_199_254_740_992u64)),
        ("/observed_at", json!("not-a-time")),
        ("/source", json!("local-cache")),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            decode::<models::ConversationSnapshot>(&bad).is_err(),
            "{pointer}"
        );
    }
}
