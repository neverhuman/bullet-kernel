use super::*;

#[test]
fn changed_message_owner_cause_queue_and_audit_truth_refuse_get_list_and_retry() {
    for statement in [
        "UPDATE conversation_messages SET content='rewritten'",
        "UPDATE conversation_messages SET content_digest=lower(hex(zeroblob(32)))",
        "UPDATE conversation_messages SET accepted_sequence=accepted_sequence+1",
        "UPDATE conversations SET created_at='2026-09-11T00:00:00.000Z'",
        "UPDATE conversation_head_requests SET requested_at='2026-09-11T00:00:00.000Z'",
        "UPDATE conversation_head_requests SET input_sequence=2",
        "DELETE FROM conversation_head_requests",
        "UPDATE outbox SET payload='{}'",
        "UPDATE outbox SET phase='applied',delivered_at='2026-09-10T00:00:00.000Z'",
        "UPDATE commands SET phase='verified'",
        "UPDATE commands SET response_json='{}'",
        "UPDATE events SET body='{}' WHERE kind='command_reconciled'",
        "UPDATE operator_command_ownership SET admitted_at='2026-09-11T00:00:00.000Z'",
    ] {
        let directory = crate::test_support::private_tempdir();
        let mut ledger = SqliteLedger::open(directory.path().join("corrupt.sqlite")).unwrap();
        let owner = register(&mut ledger);
        let requested = request("corrupt-binding", None, "Preserve this message");
        ledger.submit_operator_command(&owner, &requested).unwrap();
        // Simulate corrupted durable bytes below immutable SQL protections.
        ledger
            .conn
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
            DROP TRIGGER conversation_message_no_update;
            DROP TRIGGER conversation_no_update;
            DROP TRIGGER conversation_head_no_update;
            DROP TRIGGER conversation_head_no_delete;
            DROP TRIGGER operator_command_owner_no_update;",
            )
            .unwrap();
        ledger.conn.execute_batch(statement).unwrap();
        let before = counts(&ledger);
        assert!(
            ledger
                .get_operator_command(&owner, &requested.id())
                .is_err(),
            "get: {statement}"
        );
        assert!(
            ledger.list_operator_commands(&owner, 0, 100).is_err(),
            "list: {statement}"
        );
        assert!(
            ledger.submit_operator_command(&owner, &requested).is_err(),
            "retry: {statement}"
        );
        assert_eq!(counts(&ledger), before, "{statement}");
    }
}

#[test]
fn corrupt_prior_history_refuses_later_get_retry_and_fresh_append_without_new_rows() {
    for statement in [
        "UPDATE conversation_messages SET content='rewritten predecessor' WHERE command_id=?1",
        "UPDATE commands SET payload_digest=lower(hex(zeroblob(32))) WHERE id=?1",
        "UPDATE operator_command_ownership SET request_digest=lower(hex(zeroblob(32))) WHERE command_id=?1",
        "UPDATE conversation_head_requests SET requested_at='2026-09-11T00:00:00.000Z' WHERE command_id=?1",
    ] {
        let directory = crate::test_support::private_tempdir();
        let mut ledger = SqliteLedger::open(directory.path().join("prior.sqlite")).unwrap();
        let owner = register(&mut ledger);
        let first = request("prior", None, "Original goal");
        let first_saved = ledger.submit_operator_command(&owner, &first).unwrap();
        let second = request("later", Some(receipt(&first_saved.command).cursor), "Progress question");
        let second_saved = ledger.submit_operator_command(&owner, &second).unwrap();
        let third = request("fresh", Some(receipt(&second_saved.command).cursor), "Next message");
        ledger.conn.execute_batch("DROP TRIGGER conversation_message_no_update;
            DROP TRIGGER operator_command_owner_no_update;
            DROP TRIGGER conversation_head_no_update;").unwrap();
        ledger.conn.execute(statement, [first.id().as_str()]).unwrap();
        let before = counts(&ledger);
        assert!(ledger.get_operator_command(&owner, &second.id()).is_err(), "get: {statement}");
        assert!(ledger.list_operator_commands(&owner, 0, 100).is_err(), "list: {statement}");
        assert!(ledger.submit_operator_command(&owner, &second).is_err(), "retry: {statement}");
        assert!(ledger.submit_operator_command(&owner, &third).is_err(), "append: {statement}");
        assert_eq!(counts(&ledger), before, "{statement}");
    }
}
