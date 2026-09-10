//! Explicit maximum-result projection fixtures, not native execution evidence.
use super::*;
fn wire_page(page: &OperatorCommandPage) -> serde_json::Value {
    let commands:Vec<_>=page.commands.iter().map(|record|serde_json::json!({"id":record.id,"status":"UNKNOWN","kind":record.kind,"payload_digest":record.payload_digest.to_hex(),"result":serde_json::from_str::<serde_json::Value>(record.response.as_ref().unwrap()).unwrap()})).collect();
    serde_json::json!({"data":{"commands":commands,"next_after":page.next_after},"as_of_sequence":page.as_of_sequence,"observed_at":AT,"source":"bullet-kernel/sqlite-ledger"})
}
#[test]
fn large_results_stop_at_byte_budget_and_continue_without_missing_commands() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("large.sqlite")).unwrap();
    let operator = register(&mut ledger);
    let mut expected = Vec::new();
    // Escapes are retained as real JSON syntax; byte accounting serializes the
    // parsed value exactly as the HTTP status serializer does.
    let large =
        serde_json::to_string(&serde_json::json!({"component_fixture":"\n\t\"\\".repeat(120_000)}))
            .unwrap();
    assert!(large.len() < 1024 * 1024);
    assert!(large.len() > 900_000);
    for index in 0..9 {
        let command = ledger
            .submit_operator_command(&operator, &request(&format!("large-{index}")))
            .unwrap()
            .command;
        let runner = RunnerId::from_seed(&format!("fixture-{index}"));
        let claim = ledger
            .claim_next_command_dispatch(&runner, 1, AT)
            .unwrap()
            .unwrap();
        let receipt =
            ComponentCommandCompletionV1::new(&claim, Digest::of(b"component-fixture")).unwrap();
        ledger
            .settle_component_command_dispatch(&claim.claim_id, &runner, 1, &receipt, AT)
            .unwrap();
        // Substitute a large but valid, exactly correlated projection result.
        // This fixture exercises transport sizing, not completion semantics.
        ledger
            .conn
            .execute(
                "UPDATE commands SET response_json=?1 WHERE id=?2",
                params![large, command.id.as_str()],
            )
            .unwrap();
        ledger
            .conn
            .execute(
                "UPDATE events SET body=?1 WHERE kind='command_reconciled' AND correlation_id=?2",
                params![large, command.id.as_str()],
            )
            .unwrap();
        expected.push(command.id);
    }
    let first = ledger.list_operator_commands(&operator, 0, 100).unwrap();
    assert!(!first.commands.is_empty());
    assert!(first.commands.len() < 9);
    assert!(serde_json::to_vec(&wire_page(&first)).unwrap().len() < MAX_PAGE_BYTES);
    let next = first.next_after.expect("byte cutoff carries a cursor");
    let second = ledger.list_operator_commands(&operator, next, 100).unwrap();
    assert_eq!(second.next_after, None);
    assert!(serde_json::to_vec(&wire_page(&second)).unwrap().len() < MAX_PAGE_BYTES);
    let actual: Vec<_> = first
        .commands
        .into_iter()
        .chain(second.commands)
        .map(|record| record.id)
        .collect();
    assert_eq!(actual, expected);
}
