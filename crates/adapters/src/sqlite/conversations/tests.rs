use crate::sqlite::SqliteLedger;
use bullet_application::conversations::{
    ConversationCursor, ConversationMessagePayload, ConversationMessageReceipt,
    CONVERSATION_MESSAGE_KIND, CONVERSATION_MESSAGE_SCHEMA,
};
use bullet_application::operator_commands::OperatorCommandStore;
use bullet_application::operator_sessions::{BootstrapRegistration, OperatorSessionStore};
use bullet_application::{CommandDispatchStore, CommandRecord, CommandRequest, Ledger};
use bullet_domain::{CommandPhase, Digest, RunnerId};

mod corruption;
mod reads;

fn register(ledger: &mut SqliteLedger) -> String {
    let operator = format!(
        "opr_{}",
        Digest::of(b"conversation-fixture-operator").to_hex()
    );
    ledger
        .register_operator_bootstrap(&BootstrapRegistration {
            digest: Digest::of(b"conversation-fixture-bootstrap"),
            proposed_operator_id: operator.clone(),
            origin: "http://127.0.0.1:7420".into(),
            lifetime_seconds: 600,
        })
        .unwrap();
    operator
}

fn request(key: &str, cursor: Option<ConversationCursor>, content: &str) -> CommandRequest {
    let payload = ConversationMessagePayload {
        schema_version: CONVERSATION_MESSAGE_SCHEMA.into(),
        cursor,
        content: content.into(),
    };
    // Match public JSON map ordering, not the internal Rust struct's field order.
    CommandRequest::new(
        key,
        CONVERSATION_MESSAGE_KIND,
        &serde_json::to_value(payload).unwrap(),
    )
    .unwrap()
}

fn receipt(record: &CommandRecord) -> ConversationMessageReceipt {
    assert_eq!(record.phase, CommandPhase::Applied);
    serde_json::from_str(record.response.as_deref().unwrap()).unwrap()
}

fn counts(ledger: &SqliteLedger) -> Vec<i64> {
    [
        "commands",
        "operator_command_ownership",
        "outbox",
        "events",
        "conversations",
        "conversation_messages",
        "conversation_head_requests",
        "command_dispatch_claims",
        "budget_reservations",
    ]
    .iter()
    .map(|table| {
        ledger
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    })
    .collect()
}

#[test]
fn message_owner_history_and_head_queue_roll_back_at_every_transaction_boundary() {
    for append in [false, true] {
        for boundary in 0..=8 {
            let directory = crate::test_support::private_tempdir();
            let path = directory.path().join("conversation.sqlite");
            let mut ledger = SqliteLedger::open(&path).unwrap();
            let owner = register(&mut ledger);
            let cursor = append.then(|| {
                let command = ledger
                    .submit_operator_command(&owner, &request("first", None, "Initial goal"))
                    .unwrap()
                    .command;
                receipt(&command).cursor
            });
            let requested = request(
                "boundary-message",
                cursor,
                "Keep this entire message.\n🦀 Rust.",
            );
            let before = counts(&ledger);
            ledger.set_command_submission_failpoint(boundary);
            let error = ledger
                .submit_operator_command(&owner, &requested)
                .unwrap_err();
            assert!(error.to_string().contains("STORE"), "{boundary}: {error}");
            assert_eq!(
                counts(&ledger),
                before,
                "append={append} boundary={boundary}"
            );
            drop(ledger);
            let mut reopened = SqliteLedger::open(&path).unwrap();
            assert_eq!(counts(&reopened), before);
            assert!(reopened
                .get_operator_command(&owner, &requested.id())
                .unwrap()
                .is_none());
            let command = reopened
                .submit_operator_command(&owner, &requested)
                .unwrap()
                .command;
            let saved = receipt(&command);
            assert_eq!(saved.cursor.sequence, if append { 2 } else { 1 });
            assert_eq!(counts(&reopened)[7..], [0, 0]);
        }
    }
}

#[test]
fn settled_retry_after_concurrent_append_and_empty_cache_reopen_preserves_messages() {
    let directory = crate::test_support::private_tempdir();
    let path = directory.path().join("conversation.sqlite");
    let mut first_client = SqliteLedger::open(&path).unwrap();
    let owner = register(&mut first_client);
    let original = request(
        "lost-response",
        None,
        "Make the CLI pleasant.\nKeep my exact text.",
    );
    let saved = first_client
        .submit_operator_command(&owner, &original)
        .unwrap();
    let mut second_client = SqliteLedger::open(&path).unwrap();
    let cursor = receipt(&saved.command).cursor;
    let followup = request("followup", Some(cursor.clone()), "How is it going?");
    let second = second_client
        .submit_operator_command(&owner, &followup)
        .unwrap();
    let before = counts(&second_client);
    let stale = request("stale-client", Some(cursor), "Another concurrent message");
    let error = first_client
        .submit_operator_command(&owner, &stale)
        .unwrap_err();
    assert_eq!(error.reason_code(), "CONVERSATION_CURSOR_CONFLICT");
    assert_eq!(counts(&first_client), before);
    let replay = first_client
        .submit_operator_command(&owner, &original)
        .unwrap();
    assert_eq!(replay.command, saved.command);
    assert_eq!(replay.as_of_sequence, second.as_of_sequence);
    assert_eq!(counts(&first_client), before);
    drop(first_client);
    drop(second_client);
    let mut reopened = SqliteLedger::open(&path).unwrap();
    let discovered = reopened.list_operator_commands(&owner, 0, 100).unwrap();
    assert_eq!(discovered.commands, [saved.command.clone(), second.command]);
    assert_eq!(
        reopened
            .submit_operator_command(&owner, &original)
            .unwrap()
            .command,
        saved.command
    );
    assert_eq!(counts(&reopened), before);
    let changed = request("lost-response", None, "Substituted goal");
    assert!(reopened.submit_operator_command(&owner, &changed).is_err());
    assert_eq!(counts(&reopened), before);
}

#[test]
fn conversation_content_stays_private_and_never_acquires_runner_authority() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("conversation.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let secret_text = "private conversation fixture content never belongs in generic streams";
    let requested = request("private-message", None, secret_text);
    assert_eq!(
        ledger.submit_command(&requested).unwrap_err().reason_code(),
        "CONVERSATION_OPERATOR_INGRESS_REQUIRED"
    );
    assert_eq!(counts(&ledger), [0; 9]);
    let saved = ledger.submit_operator_command(&owner, &requested).unwrap();
    let outbox = ledger.outbox_all().unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].kind, "conversation_head_turn");
    assert!(!outbox[0].payload.contains(secret_text));
    assert!(!saved
        .command
        .response
        .as_ref()
        .unwrap()
        .contains(secret_text));
    assert!(ledger
        .list_events()
        .unwrap()
        .iter()
        .all(|event| !event.body.contains(secret_text)));
    let runner = RunnerId::from_seed("unrelated-coding-worker");
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-10T00:00:00.000Z")
        .unwrap()
        .is_none());
    // Corrupt queue classification cannot turn a conversation into Runner work.
    ledger
        .conn
        .execute("UPDATE outbox SET kind='command_dispatch'", [])
        .unwrap();
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-10T00:00:00.000Z")
        .unwrap()
        .is_none());
    assert!(ledger
        .get_operator_command(&owner, &requested.id())
        .is_err());
    assert_eq!(counts(&ledger)[7..], [0, 0]);
}

#[test]
fn absent_threads_and_unadmitted_operators_do_not_disclose_history() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("conversation.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let saved = ledger
        .submit_operator_command(&owner, &request("owned", None, "Owner-only history"))
        .unwrap();
    let mut cursor = receipt(&saved.command).cursor;
    cursor.conversation_id = format!("cnv_{}", Digest::of(b"foreign-or-absent").to_hex());
    let before = counts(&ledger);
    let error = ledger
        .submit_operator_command(&owner, &request("absent", Some(cursor), "Append"))
        .unwrap_err();
    assert_eq!(error.reason_code(), "CONVERSATION_NOT_FOUND");
    let foreign = format!("opr_{}", Digest::of(b"unadmitted-operator").to_hex());
    assert!(ledger
        .get_operator_command(&foreign, &saved.command.id)
        .is_err());
    assert!(ledger.list_operator_commands(&foreign, 0, 100).is_err());
    assert_eq!(counts(&ledger), before);
}
