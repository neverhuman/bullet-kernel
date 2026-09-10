//! Corruption is injected only into isolated regression databases.
use super::*;

#[test]
fn missing_or_substituted_accepted_coding_bindings_never_replay_or_project() {
    for mutation in ["DELETE FROM authority_nonces", "UPDATE authority_nonces SET consumed_at=NULL",
        "UPDATE authority_nonces SET request_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        "DELETE FROM budget_reservations", "UPDATE budget_reservations SET amount=4"] {
        let directory=crate::test_support::private_tempdir();let mut ledger=SqliteLedger::open(directory.path().join("corrupt.sqlite")).unwrap();let operator=register(&mut ledger);let request=coding("owned");let record=ledger.submit_operator_command(&operator,&request).unwrap().command;
        ledger.conn.execute(mutation,[]).unwrap();let before=counts(&ledger);
        assert!(ledger.submit_command(&request).is_err(),"legacy replay: {mutation}");
        assert!(ledger.submit_operator_command(&operator,&request).is_err(),"owner replay: {mutation}");
        assert!(ledger.get_operator_command(&operator,&record.id).is_err(),"owner get: {mutation}");
        assert!(ledger.list_operator_commands(&operator,0,10).is_err(),"owner list: {mutation}");
        assert_eq!(counts(&ledger),before,"failed checks must not recreate acceptance rows");
    }
}

#[test]
fn bounded_event_projection_still_rejects_a_fourth_correlated_required_event() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("events.sqlite")).unwrap();
    let operator = register(&mut ledger);
    let request = request("owned");
    let command = ledger
        .submit_operator_command(&operator, &request)
        .unwrap()
        .command;
    let runner = RunnerId::from_seed("fixture-runner");
    let claim = ledger
        .claim_next_command_dispatch(&runner, 1, AT)
        .unwrap()
        .unwrap();
    let receipt = ComponentCommandCompletionV1::new(&claim, Digest::of(b"component")).unwrap();
    ledger
        .settle_component_command_dispatch(&claim.claim_id, &runner, 1, &receipt, AT)
        .unwrap();
    assert_eq!(
        events::command_projection_events(&ledger.conn, &command.id)
            .unwrap()
            .len(),
        3
    );
    for _ in 0..20 {
        events::insert_event(
            &ledger.conn,
            "command_submitted",
            command.id.as_str(),
            Some(command.id.as_str()),
            Some(command.id.as_str()),
            None,
        )
        .unwrap();
    }
    assert_eq!(
        events::command_projection_events(&ledger.conn, &command.id)
            .unwrap()
            .len(),
        4
    );
    assert!(ledger.get_operator_command(&operator, &command.id).is_err());
    assert!(ledger.list_operator_commands(&operator, 0, 10).is_err());
    assert!(ledger.submit_operator_command(&operator, &request).is_err());
}

#[test]
fn owner_reads_stay_coherent_during_independent_dispatch_and_settlement() {
    let directory = crate::test_support::private_tempdir();
    let path = directory.path().join("concurrent.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let operator = register(&mut ledger);
    let record = ledger
        .submit_operator_command(&operator, &request("concurrent"))
        .unwrap()
        .command;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writer_barrier = barrier.clone();
    let writer = std::thread::spawn(move || {
        let mut connection = SqliteLedger::open(path).unwrap();
        let runner = RunnerId::from_seed("concurrent-fixture");
        writer_barrier.wait();
        let claim = connection
            .claim_next_command_dispatch(&runner, 1, AT)
            .unwrap()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let receipt = ComponentCommandCompletionV1::new(&claim, Digest::of(b"component")).unwrap();
        connection
            .settle_component_command_dispatch(&claim.claim_id, &runner, 1, &receipt, AT)
            .unwrap();
    });
    barrier.wait();
    for _ in 0..100 {
        let snapshot = ledger
            .get_operator_command(&operator, &record.id)
            .unwrap()
            .unwrap();
        assert!(matches!(
            (snapshot.command.phase, snapshot.as_of_sequence),
            (CommandPhase::Pending, 1 | 2) | (CommandPhase::Unknown, 3)
        ));
        let page = ledger.list_operator_commands(&operator, 0, 10).unwrap();
        assert_eq!(page.commands.len(), 1);
        assert!(matches!(
            (page.commands[0].phase, page.as_of_sequence),
            (CommandPhase::Pending, 1 | 2) | (CommandPhase::Unknown, 3)
        ));
    }
    writer.join().unwrap();
    assert_eq!(
        ledger
            .get_operator_command(&operator, &record.id)
            .unwrap()
            .unwrap()
            .command
            .phase,
        CommandPhase::Unknown
    );
}
