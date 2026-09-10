//! Deliberately damaged component fixture databases; product triggers stay intact.
use super::*;

#[test]
fn missing_run_binding_never_converts_task_intent_into_a_legacy_dispatch_claim() {
    let dir = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(dir.path().join("corrupt.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let task = request("corrupt-run", &payload());
    ledger.submit_operator_command(&owner, &task).unwrap();
    ledger
        .conn
        .execute_batch("DROP TRIGGER coding_run_no_delete; DELETE FROM coding_runs;")
        .unwrap();
    let before = counts(&ledger);
    let outbox = ledger.outbox_all().unwrap();
    let runner = RunnerId::from_seed("corrupt-task-runner");
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-10T05:00:00.000Z")
        .is_err());
    assert_eq!(counts(&ledger), before);
    assert_eq!(ledger.outbox_all().unwrap(), outbox);
    assert!(ledger
        .command_dispatch_claim_for_command(&task.id())
        .unwrap()
        .is_none());
    assert!(ledger.get_operator_coding(&owner, &task.id()).is_err());
    assert!(ledger.list_operator_commands(&owner, 0, 100).is_err());
    assert!(ledger.submit_operator_command(&owner, &task).is_err());
    assert_eq!(counts(&ledger), before);
}

#[test]
fn dangling_extra_dependency_is_not_hidden_from_read_list_or_retry() {
    let dir = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(dir.path().join("corrupt.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let task = payload();
    let request = request("orphan-edge", &task);
    ledger.submit_operator_command(&owner, &request).unwrap();
    ledger
        .conn
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    ledger
        .conn
        .execute(
            "INSERT INTO coding_task_dependencies(revision_id,dependency_id) VALUES(?1,?2)",
            rusqlite::params![
                task.task.revision_id(&owner).unwrap(),
                format!("ctr_{}", "ef".repeat(32))
            ],
        )
        .unwrap();
    ledger
        .conn
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    let before = counts(&ledger);
    assert!(ledger.get_operator_coding(&owner, &request.id()).is_err());
    assert!(ledger.get_operator_command(&owner, &request.id()).is_err());
    assert!(ledger.list_operator_commands(&owner, 0, 100).is_err());
    assert!(ledger.submit_operator_command(&owner, &request).is_err());
    assert_eq!(counts(&ledger), before);
}

#[test]
fn persisted_task_claim_is_refused_before_readback_or_reclaim() {
    let dir = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(dir.path().join("corrupt.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let task = request("forged-claim", &payload());
    ledger.submit_operator_command(&owner, &task).unwrap();
    let runner = RunnerId::from_seed("forged-runner");
    let seq = ledger.outbox_all().unwrap()[0].seq;
    let seed = format!(
        "bullet.command-dispatch-claim.v1\0{}\0{seq}\0{}\0{}\0{epoch}\0{epoch}\0{zero}\0{zero}",
        task.id(),
        task.digest().to_hex(),
        runner,
        epoch = 1,
        zero = 0
    );
    let claim_id = format!("dcl_{}", Digest::of(seed.as_bytes()).to_hex());
    ledger.conn.execute("INSERT INTO command_dispatch_claims(claim_id,command_id,outbox_sequence,request_digest,runner_id,runner_epoch,authority_epoch,freeze_generation,restore_epoch,disposition,completion_digest,claimed_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,1,0,0,'CLAIMED',NULL,?6,?6)",
        rusqlite::params![claim_id, task.id().as_str(),seq,task.digest().to_hex(),runner.as_str(),"2026-09-10T05:00:00.000Z"]).unwrap();
    let before = counts(&ledger);
    for result in [
        ledger.readback_command_dispatch(&runner, 1),
        ledger.command_dispatch_claim_for_command(&task.id()),
        ledger.claim_next_command_dispatch(&runner, 1, "2026-09-10T05:00:01.000Z"),
    ] {
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("task intent cannot carry legacy dispatch authority"));
    }
    assert_eq!(counts(&ledger), before);
}
