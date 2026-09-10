//! Component failures around acknowledged termination, terminal release and cleanup.

use super::finalization_client::{FailingJournal, ObservedClient};
use super::*;
use crate::RunnerError;

#[derive(Clone, Copy)]
enum Fault {
    CleanupRefused,
    CleanupResponseLost,
    ReleaseResponseLost,
    TerminationRefused,
    NegativeTerminationAck,
    Journal(&'static str, bool),
}

async fn exercise(
    fault: Fault,
    expected_stage: &'static str,
    expected_releases: usize,
    expected_cleanup: usize,
) {
    let (_temp, ledger, inner, grant, config, mut workspace, mut info, _) =
        cloned_attempt("finalization-boundary").await;
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );
    match fault {
        Fault::CleanupRefused => workspace.fail_cleanup(false),
        Fault::CleanupResponseLost => workspace.fail_cleanup(true),
        Fault::TerminationRefused => adapter.fail_terminate("termination unconfirmed"),
        Fault::NegativeTerminationAck => adapter.refuse_termination_ack(),
        _ => {}
    }
    let client = Arc::new(ObservedClient {
        inner,
        adapter: adapter.clone(),
        releases: Mutex::new(Vec::new()),
        lose_release_response: matches!(fault, Fault::ReleaseResponseLost),
    });
    let (fail_stage, fail_recovery) = match fault {
        Fault::Journal(stage, recovery) => (stage, recovery),
        _ => ("none", false),
    };
    let journal = Arc::new(FailingJournal {
        memory: MemoryJournal::new(),
        fail_stage,
        fail_recovery,
    });
    let error = run_cloned_attempt(
        client.clone(),
        adapter.clone(),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &grant,
        &config,
        &mut workspace,
        &mut info,
    )
    .await
    .expect_err("the unresolved boundary must refuse success");
    assert_eq!(error.reason_code(), "FINALIZATION_UNRESOLVED");
    let RunnerError::FinalizationUnresolved {
        stage,
        attempt_id,
        candidate_id,
        receipt_digest,
        destination,
        primary,
        recovery_journal_error,
    } = &error
    else {
        panic!("missing recovery subject: {error}")
    };
    assert_eq!(*stage, expected_stage);
    assert_eq!(attempt_id.as_ref(), grant.attempt.id.as_str());
    assert!(candidate_id.starts_with("can_"));
    assert_eq!(receipt_digest.len(), 64);
    assert_eq!(destination.as_ref(), config.workspace_root.join("retained"));
    assert!(destination.join("generation/repo/PONG.txt").is_file());
    assert_eq!(recovery_journal_error.is_some(), fail_recovery);
    if fail_recovery {
        assert!(error
            .to_string()
            .contains("injected durable journal failure: finalization_unresolved"));
    }
    match fault {
        Fault::CleanupResponseLost => {
            assert!(primary.to_string().contains("response lost after deletion"))
        }
        Fault::ReleaseResponseLost => assert_eq!(primary.reason_code(), "RELEASE_OUTCOME_UNKNOWN"),
        Fault::NegativeTerminationAck => assert!(primary.to_string().contains("not acknowledged")),
        Fault::Journal(stage, _) => assert!(primary.to_string().contains(stage)),
        _ => {}
    }
    assert!(
        !format!("{error:?}").contains("TEST_ONLY_PRESERVE:"),
        "bearer token in error"
    );
    let releases = client.releases.lock().expect("release trace");
    assert_eq!(
        releases.len(),
        expected_releases,
        "terminal release repeated"
    );
    assert!(releases
        .iter()
        .all(|call| call.outcome == AttemptState::Succeeded && !call.requeue));
    assert_eq!(workspace.cleanup_calls(), expected_cleanup);
    let removed = matches!(
        fault,
        Fault::CleanupResponseLost | Fault::Journal("workspace_cleaned", _)
    );
    assert_eq!(
        info.repo_dir.exists(),
        !removed,
        "fixture must distinguish pre/post deletion failures"
    );
    let state = ledger.lock().expect("ledger");
    let attempt = state
        .get_attempt(&grant.attempt.id)
        .expect("attempt")
        .expect("present");
    assert_eq!(
        attempt.state,
        if expected_releases == 0 {
            AttemptState::Preparing
        } else {
            AttemptState::Succeeded
        }
    );
    assert_eq!(
        state
            .get_lease(&attempt.variant_id)
            .expect("lease")
            .is_some(),
        expected_releases == 0
    );
    assert!(
        state.ready_rows().expect("ready").is_empty(),
        "unresolved attempt was requeued"
    );
    let entries = journal.memory.entries();
    assert!(!entries
        .iter()
        .any(|(_, detail)| detail.contains("TEST_ONLY_PRESERVE:")));
    if !fail_recovery {
        let (_, detail) = entries
            .iter()
            .find(|(stage, _)| stage == "finalization_unresolved")
            .expect("durable recovery event");
        let value: serde_json::Value = serde_json::from_str(detail).expect("recovery JSON");
        assert_eq!(value["candidate_id"], candidate_id.as_ref());
        assert_eq!(value["receipt_digest"], receipt_digest.as_ref());
        assert_eq!(value["stage"], expected_stage);
    }
}

#[tokio::test]
async fn cleanup_refusal_never_issues_a_second_release_or_requeues() {
    exercise(Fault::CleanupRefused, "workspace_cleanup", 1, 1).await;
}

#[tokio::test]
async fn deleted_workspace_with_lost_cleanup_response_is_unresolved_not_known_orphan() {
    exercise(Fault::CleanupResponseLost, "workspace_cleanup", 1, 1).await;
}

#[tokio::test]
async fn committed_release_response_loss_never_attempts_cleanup_or_requeue() {
    exercise(Fault::ReleaseResponseLost, "release", 1, 0).await;
}

#[tokio::test]
async fn refused_or_negative_termination_never_releases_or_cleans() {
    exercise(Fault::TerminationRefused, "provider_termination", 0, 0).await;
    exercise(Fault::NegativeTerminationAck, "provider_termination", 0, 0).await;
}

#[tokio::test]
async fn required_finalization_journal_failures_retain_candidate_and_original_failure() {
    for (journal_stage, error_stage, releases, cleanup) in [
        ("candidate_preserved", "preservation_journal", 0, 0),
        ("terminated", "termination_journal", 0, 0),
        ("released", "release_journal", 1, 0),
        ("workspace_cleaned", "cleanup_journal", 1, 1),
    ] {
        exercise(
            Fault::Journal(journal_stage, false),
            error_stage,
            releases,
            cleanup,
        )
        .await;
        exercise(
            Fault::Journal(journal_stage, true),
            error_stage,
            releases,
            cleanup,
        )
        .await;
    }
}
