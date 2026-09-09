mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{
    CommandDispatchDisposition, CommandDispatchStore, CommandRequest, ComponentCommandCompletionV1,
    Ledger,
};
use bullet_domain::{CommandPhase, Digest, RunnerId};
use rusqlite::Connection;

const AT: &str = "2026-08-27T13:00:00.000Z";

fn submit(ledger: &mut SqliteLedger, key: &str, kind: &str) -> bullet_application::CommandRecord {
    ledger
        .submit_command(&CommandRequest::new(key, kind, &serde_json::json!({})).unwrap())
        .unwrap()
}

fn completion(claim: &bullet_application::CommandDispatchClaim) -> ComponentCommandCompletionV1 {
    ComponentCommandCompletionV1::new(claim, Digest::of(b"retained component receipt"))
        .expect("completion")
}

#[test]
fn claim_is_atomic_exclusive_and_exact_request_bound() {
    let directory = support::private_tempdir();
    let path = directory.path().join("dispatch.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let first = submit(&mut ledger, "dispatch-first", "run_demo");
    let second = submit(&mut ledger, "dispatch-second", "run_demo");
    let one = RunnerId::from_seed("dispatch-runner-one");
    let two = RunnerId::from_seed("dispatch-runner-two");

    let claimed = ledger
        .claim_next_command_dispatch(&one, 7, AT)
        .unwrap()
        .expect("first claim");
    assert_eq!(claimed.command_id, first.id);
    assert_eq!(claimed.request.id(), first.id);
    assert_eq!(claimed.request_digest, claimed.request.digest());
    assert_eq!(claimed.runner_id, one);
    assert_eq!(claimed.runner_epoch, 7);
    assert_eq!(claimed.disposition, CommandDispatchDisposition::Claimed);
    assert_eq!(
        ledger
            .claim_next_command_dispatch(&one, 7, "2027-01-01T00:00:00.000Z")
            .unwrap(),
        Some(claimed.clone())
    );

    let next = ledger
        .claim_next_command_dispatch(&two, 9, AT)
        .unwrap()
        .expect("second claim");
    assert_eq!(next.command_id, second.id);
    assert_ne!(next.claim_id, claimed.claim_id);
    let outbox = ledger.outbox_for_command(&first.id).unwrap();
    assert_eq!(outbox[0].phase, CommandPhase::Applied);
    assert_eq!(outbox[0].delivered_at.as_deref(), Some(AT));
    assert_eq!(
        ledger
            .list_events()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "command_dispatch_claimed")
            .count(),
        2
    );
}

#[test]
fn lost_claim_response_reads_back_after_restart() {
    let directory = support::private_tempdir();
    let path = directory.path().join("readback.sqlite3");
    let runner = RunnerId::from_seed("dispatch-readback-runner");
    let claim = {
        let mut ledger = SqliteLedger::open(&path).unwrap();
        submit(&mut ledger, "dispatch-readback", "run_demo");
        ledger
            .claim_next_command_dispatch(&runner, 3, AT)
            .unwrap()
            .unwrap()
    };
    let reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        reopened.readback_command_dispatch(&runner, 3).unwrap(),
        Some(claim)
    );
}

#[test]
fn foreign_runner_epoch_cannot_steal_claim() {
    let directory = support::private_tempdir();
    let path = directory.path().join("owned.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let command = submit(&mut ledger, "dispatch-owned", "run_demo");
    let runner = RunnerId::from_seed("dispatch-owned-runner");
    let claim = ledger
        .claim_next_command_dispatch(&runner, 1, AT)
        .unwrap()
        .unwrap();

    assert!(ledger
        .readback_command_dispatch(&runner, 2)
        .unwrap()
        .is_none());
    assert!(ledger
        .claim_next_command_dispatch(&RunnerId::from_seed("foreign-runner"), 1, AT)
        .unwrap()
        .is_none());
    assert_eq!(
        ledger
            .command_dispatch_claim_for_command(&command.id)
            .unwrap(),
        Some(claim)
    );
}

#[test]
fn authority_or_restore_movement_invalidates_before_execution() {
    let directory = support::private_tempdir();
    let path = directory.path().join("stale.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let command = submit(&mut ledger, "dispatch-stale", "run_demo");
    let runner = RunnerId::from_seed("dispatch-stale-runner");
    ledger
        .claim_next_command_dispatch(&runner, 1, AT)
        .unwrap()
        .unwrap();
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE authority_revisions
             SET authority_epoch = authority_epoch + 1,
                 freeze_generation = freeze_generation + 1
             WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(ledger);

    let mut reopened = SqliteLedger::open(&path).unwrap();
    let invalidated = reopened
        .command_dispatch_claim_for_command(&command.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        invalidated.disposition,
        CommandDispatchDisposition::Invalidated
    );
    assert!(reopened
        .readback_command_dispatch(&runner, 1)
        .unwrap()
        .is_none());
    assert!(reopened
        .claim_next_command_dispatch(&RunnerId::from_seed("successor-runner"), 1, AT)
        .unwrap()
        .is_none());
}

#[test]
fn component_settlement_is_atomic_replay_safe_and_never_green() {
    let directory = support::private_tempdir();
    let path = directory.path().join("settle.sqlite3");
    let runner = RunnerId::from_seed("dispatch-settle-runner");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let command = submit(&mut ledger, "dispatch-settle", "run_demo");
    let claim = ledger
        .claim_next_command_dispatch(&runner, 4, AT)
        .unwrap()
        .unwrap();
    let completion = completion(&claim);
    let settled = ledger
        .settle_component_command_dispatch(&claim.claim_id, &runner, 4, &completion, AT)
        .unwrap();
    assert_eq!(settled.phase, CommandPhase::Unknown);
    let response = settled.response.as_deref().unwrap();
    assert!(response.contains("COMPONENT_PROOF_NOT_TRANSACTION_ELIGIBLE"));
    assert!(response.contains("\"transaction_gate_eligible\":false"));
    assert!(!response.contains("VERIFIED"));
    assert_eq!(
        ledger
            .settle_component_command_dispatch(
                &claim.claim_id,
                &runner,
                4,
                &completion,
                "2028-01-01T00:00:00.000Z",
            )
            .unwrap(),
        settled
    );
    let outbox = &ledger.outbox_for_command(&command.id).unwrap()[0];
    assert_eq!(outbox.phase, CommandPhase::Unknown);
    assert_eq!(outbox.acked_at.as_deref(), Some(AT));
    assert_eq!(
        ledger
            .list_events()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "command_reconciled")
            .count(),
        1
    );
}

#[test]
fn settlement_refuses_tampered_or_off_command_receipt() {
    let directory = support::private_tempdir();
    let path = directory.path().join("tamper.sqlite3");
    let runner = RunnerId::from_seed("dispatch-tamper-runner");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let command = submit(&mut ledger, "dispatch-tamper", "run_demo");
    let claim = ledger
        .claim_next_command_dispatch(&runner, 2, AT)
        .unwrap()
        .unwrap();
    let mut tampered = completion(&claim);
    tampered.transaction_gate_eligible = true;
    let error = ledger
        .settle_component_command_dispatch(&claim.claim_id, &runner, 2, &tampered, AT)
        .expect_err("painted eligibility");
    assert_eq!(error.reason_code(), "COMMAND_COMPLETION_INVALID");
    let mut off_command = completion(&claim);
    off_command.command_id = bullet_domain::CommandId::from_seed("other-command");
    assert_eq!(
        ledger
            .settle_component_command_dispatch(&claim.claim_id, &runner, 2, &off_command, AT,)
            .expect_err("off command")
            .reason_code(),
        "COMMAND_DISPATCH_SUBJECT_MISMATCH"
    );
    let unchanged = ledger.get_command_by_id(&command.id).unwrap().unwrap();
    assert_eq!(unchanged.phase, CommandPhase::Pending);
    assert!(unchanged.response.is_none());
}

#[test]
fn every_claim_and_settlement_boundary_rolls_back_all_correlated_truth() {
    for boundary in 0..=2 {
        let directory = support::private_tempdir();
        let path = directory.path().join(format!("claim-{boundary}.sqlite3"));
        let runner = RunnerId::from_seed(&format!("claim-boundary-{boundary}"));
        let mut ledger = SqliteLedger::open(&path).unwrap();
        let command = submit(&mut ledger, "claim-boundary", "run_demo");
        ledger.set_command_dispatch_claim_failpoint(boundary);
        assert_eq!(
            ledger
                .claim_next_command_dispatch(&runner, 1, AT)
                .expect_err("claim rollback")
                .reason_code(),
            "STORE_FAILURE"
        );
        assert!(ledger
            .command_dispatch_claim_for_command(&command.id)
            .unwrap()
            .is_none());
        assert_eq!(
            ledger.outbox_for_command(&command.id).unwrap()[0].phase,
            CommandPhase::Pending
        );
        assert_eq!(ledger.list_events().unwrap().len(), 1);
    }

    for boundary in 0..=2 {
        let directory = support::private_tempdir();
        let path = directory.path().join(format!("settle-{boundary}.sqlite3"));
        let runner = RunnerId::from_seed(&format!("settle-boundary-{boundary}"));
        let mut ledger = SqliteLedger::open(&path).unwrap();
        let command = submit(&mut ledger, "settle-boundary", "run_demo");
        let claim = ledger
            .claim_next_command_dispatch(&runner, 1, AT)
            .unwrap()
            .unwrap();
        ledger.set_command_dispatch_settlement_failpoint(boundary);
        assert_eq!(
            ledger
                .settle_component_command_dispatch(
                    &claim.claim_id,
                    &runner,
                    1,
                    &completion(&claim),
                    AT,
                )
                .expect_err("settlement rollback")
                .reason_code(),
            "STORE_FAILURE"
        );
        assert_eq!(
            ledger
                .get_command_by_id(&command.id)
                .unwrap()
                .unwrap()
                .phase,
            CommandPhase::Pending
        );
        assert_eq!(
            ledger
                .command_dispatch_claim_for_command(&command.id)
                .unwrap()
                .unwrap()
                .disposition,
            CommandDispatchDisposition::Claimed
        );
        assert_eq!(
            ledger.outbox_for_command(&command.id).unwrap()[0].phase,
            CommandPhase::Applied
        );
        assert_eq!(ledger.list_events().unwrap().len(), 2);
    }
}

#[test]
fn unsupported_kind_is_kernel_failed_without_worker_execution() {
    let directory = support::private_tempdir();
    let path = directory.path().join("unsupported.sqlite3");
    let runner = RunnerId::from_seed("dispatch-unsupported-runner");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let command = submit(&mut ledger, "dispatch-unsupported", "not_admitted");
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, AT)
        .unwrap()
        .is_none());
    let failed = ledger.get_command_by_id(&command.id).unwrap().unwrap();
    assert_eq!(failed.phase, CommandPhase::Failed);
    assert!(failed
        .response
        .as_deref()
        .is_some_and(|value| value.contains("UNSUPPORTED_COMMAND_KIND")));
    let claim = ledger
        .command_dispatch_claim_for_command(&command.id)
        .unwrap()
        .unwrap();
    assert_eq!(claim.disposition, CommandDispatchDisposition::Failed);
    assert_eq!(
        ledger.outbox_for_command(&command.id).unwrap()[0].phase,
        CommandPhase::Failed
    );
}
