use super::*;
use bullet_application::conversations::ConversationStore;
use rusqlite::params;

#[test]
fn complete_history_pages_cross_batch_boundary_and_refresh_after_another_client_appends() {
    let directory = crate::test_support::private_tempdir();
    let path = directory.path().join("history.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let owner = register(&mut ledger);
    let mut cursor = None;
    let mut content = Vec::new();
    for position in 0..101 {
        let body = format!("Message {position}\nComplete UTF-8 🦀 content.");
        let requested = request(&format!("history-{position}"), cursor, &body);
        let saved = ledger.submit_operator_command(&owner, &requested).unwrap();
        cursor = Some(receipt(&saved.command).cursor);
        content.push(body);
    }
    let cursor = cursor.unwrap();
    let first = ledger
        .get_operator_conversation(&owner, &cursor.conversation_id, 0, 100)
        .unwrap()
        .unwrap();
    assert_eq!(first.cursor, cursor);
    assert_eq!(first.messages.len(), 100);
    assert_eq!(first.next_after, Some(100));
    assert_eq!(first.head_blocker, "HEAD_RUNTIME_BINDING_REQUIRED");
    assert_eq!(
        first.as_of_sequence,
        ledger.latest_event_sequence().unwrap()
    );
    assert_eq!(
        first
            .messages
            .iter()
            .map(|message| message.content.clone())
            .collect::<Vec<_>>(),
        content[..100]
    );
    let mut other_client = SqliteLedger::open(&path).unwrap();
    let body = "Arrived between ordinary page reads";
    other_client
        .submit_operator_command(
            &owner,
            &request("concurrent-page", Some(cursor.clone()), body),
        )
        .unwrap();
    let second = ledger
        .get_operator_conversation(&owner, &cursor.conversation_id, 100, 100)
        .unwrap()
        .unwrap();
    assert_eq!(second.cursor.sequence, 102);
    assert_eq!(
        second
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>(),
        [content[100].as_str(), body]
    );
    assert_eq!(second.next_after, None);
    assert!(second.as_of_sequence > first.as_of_sequence);
    let empty = ledger
        .get_operator_conversation(&owner, &cursor.conversation_id, 102, 100)
        .unwrap()
        .unwrap();
    assert!(empty.messages.is_empty());
    assert_eq!(empty.cursor, second.cursor);
    drop(other_client);
    drop(ledger);
    let reopened = SqliteLedger::open(&path).unwrap();
    let index = reopened
        .list_operator_conversations(&owner, 0, 100)
        .unwrap();
    assert_eq!(index.conversations.len(), 1);
    assert_eq!(index.conversations[0].cursor, second.cursor);
    assert_eq!(index.conversations[0].preview, "Message 0");
}

#[test]
fn thread_index_keeps_creation_cursor_when_older_threads_receive_new_messages() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("index.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let first = ledger
        .submit_operator_command(&owner, &request("first-thread", None, "First goal"))
        .unwrap();
    let second = ledger
        .submit_operator_command(&owner, &request("second-thread", None, "Second goal"))
        .unwrap();
    let first_page = ledger.list_operator_conversations(&owner, 0, 1).unwrap();
    let after = first_page.next_after.unwrap();
    ledger
        .submit_operator_command(
            &owner,
            &request(
                "first-update",
                Some(receipt(&first.command).cursor.clone()),
                "Progress",
            ),
        )
        .unwrap();
    let second_page = ledger
        .list_operator_conversations(&owner, after, 1)
        .unwrap();
    assert_eq!(
        second_page.conversations[0].cursor,
        receipt(&second.command).cursor
    );
    assert_eq!(second_page.next_after, None);
    let refreshed = ledger.list_operator_conversations(&owner, 0, 1).unwrap();
    assert_eq!(refreshed.next_after, Some(after));
    assert_eq!(refreshed.conversations[0].cursor.sequence, 2);
    assert!(matches!(
        ledger.list_operator_conversations(&owner, refreshed.as_of_sequence + 1, 1),
        Err(bullet_application::operator_commands::OperatorCommandError::InvalidRequest)
    ));
    let thread = &refreshed.conversations[0].cursor.conversation_id;
    for (after, limit) in [(0, 0), (0, 101), (9_007_199_254_740_992, 1), (3, 1)] {
        assert!(ledger
            .get_operator_conversation(&owner, thread, after, limit)
            .is_err());
    }
    let absent = format!("cnv_{}", Digest::of(b"absent-thread").to_hex());
    assert!(ledger
        .get_operator_conversation(&owner, &absent, 0, 10)
        .unwrap()
        .is_none());
    let other = format!("opr_{}", Digest::of(b"other-operator").to_hex());
    assert!(ledger
        .get_operator_conversation(&other, thread, 0, 10)
        .is_err());
    assert!(ledger.list_operator_conversations(&other, 0, 10).is_err());
}

#[test]
fn assistant_fixture_without_native_outcome_is_never_projected_as_a_real_reply() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("assistant.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let saved = ledger
        .submit_operator_command(&owner, &request("head-request", None, "Hello"))
        .unwrap();
    let saved = receipt(&saved.command);
    ledger
        .append_event("head_test_fixture", "not native outcome evidence")
        .unwrap();
    let event = ledger.latest_event_sequence().unwrap();
    let fake_id = format!("msg_{}", Digest::of(b"fake-assistant-fixture").to_hex());
    ledger.conn.execute("INSERT INTO conversation_messages (message_id,conversation_id,sequence,
        parent_message_id,role,content,content_digest,command_id,head_turn_id,accepted_sequence,accepted_at)
        VALUES (?1,?2,2,?3,'assistant','fixture reply',?4,NULL,?5,?6,'2026-09-10T00:00:00.000Z')",
        params![fake_id,saved.cursor.conversation_id,saved.cursor.message_id,Digest::of(b"fixture reply").to_hex(),saved.head_turn_id,event]).unwrap();
    let before = counts(&ledger);
    assert!(ledger
        .get_operator_conversation(&owner, &saved.cursor.conversation_id, 0, 10)
        .is_err());
    assert!(ledger.list_operator_conversations(&owner, 0, 10).is_err());
    let cursor = ConversationCursor {
        conversation_id: saved.cursor.conversation_id,
        message_id: fake_id,
        sequence: 2,
    };
    assert!(ledger
        .submit_operator_command(&owner, &request("after-fake", Some(cursor), "More"))
        .is_err());
    assert_eq!(counts(&ledger), before);
}
