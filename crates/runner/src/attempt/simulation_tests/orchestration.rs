//! Test-only Runner orchestration after a simulated private clone.

use super::harness::ScriptedSim;
use super::{build_origin, candidate::TestCandidateClient, proposal, seeded_ledger, SimWorkspace};
use crate::journal::JournalSink;
use crate::{HeartbeatConfig, LeaseClient, MemoryJournal, MonotonicClock};
use bullet_application::{Ledger, MemoryLedger};
use bullet_domain::{AttemptId, AttemptState, RunnerId, WorkPackageId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::{run_cloned_attempt, AttemptConfig};

mod finalization;
mod finalization_client;
mod fixtures;
use fixtures::*;

#[tokio::test]
async fn failed_native_process_preserves_proposal_without_apply_or_success() {
    for (exit, timed_out) in [(Some(1), false), (None, false), (Some(0), true)] {
        let (_temp, ledger, client, grant, config, mut workspace, mut info, journal) =
            cloned_attempt("failed-native-with-proposal").await;
        let adapter = Arc::new(ScriptedSim::new());
        adapter.native_outcome(exit, timed_out);
        adapter.override_proposal(
            0,
            proposal(serde_json::json!([
                {"path":"PONG.txt", "op":"create", "contents":"PONG\n"}
            ])),
        );
        let error = run_cloned_attempt(
            client,
            adapter.clone(),
            journal.clone(),
            Arc::new(MonotonicClock::new()),
            &grant,
            &config,
            &mut workspace,
            &mut info,
        )
        .await
        .expect_err("failed native process cannot produce a successful Attempt");
        assert_eq!(error.reason_code(), "NO_PROPOSAL", "{error}");
        assert!(!journal.stages().contains(&"patch_applied".into()));
        assert!(!journal.stages().contains(&"candidate_prepared".into()));
        assert!(!info.repo_dir.join("PONG.txt").exists());
        let artifacts = std::fs::read_dir(&info.runtime_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("failed-turn-")
            })
            .collect::<Vec<_>>();
        assert_eq!(artifacts.len(), 1);
        let artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifacts[0]).unwrap()).unwrap();
        assert_eq!(artifact["exit_code"], serde_json::json!(exit));
        assert_eq!(artifact["timed_out"], timed_out);
        assert_eq!(
            artifact["close"][1]["proposal"]["operations"][0]["path"],
            "PONG.txt"
        );
        assert!(adapter.was_terminated());
        assert_failed_and_requeued(&ledger, &grant.attempt.id, journal.as_ref());
    }
}

#[tokio::test]
async fn provider_start_failure_aborts_heartbeat_and_releases_lease() {
    let (_temp, ledger, client, grant, config, mut workspace, mut info, journal) =
        cloned_attempt("provider-start-failure").await;
    let adapter = Arc::new(ScriptedSim::new());
    adapter.fail_start("injected start refusal");

    let error = run_cloned_attempt(
        client,
        adapter.clone(),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &grant,
        &config,
        &mut workspace,
        &mut info,
    )
    .await
    .expect_err("start failure must fail the attempt");

    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    assert!(!adapter.was_terminated(), "no session existed to terminate");
    assert!(journal
        .stages()
        .contains(&"session_start_refused".to_string()));
    assert_failed_and_requeued(&ledger, &grant.attempt.id, journal.as_ref());
}

#[tokio::test]
async fn running_transition_failure_terminates_provider_and_releases_lease() {
    let (_temp, ledger, client, grant, config, mut workspace, mut info, journal) =
        cloned_attempt("running-transition-failure").await;
    let adapter = Arc::new(ScriptedSim::new());
    let failing = Arc::new(FailAdvanceClient {
        inner: client,
        releases: AtomicUsize::new(0),
    });

    let error = run_cloned_attempt(
        failing.clone(),
        adapter.clone(),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &grant,
        &config,
        &mut workspace,
        &mut info,
    )
    .await
    .expect_err("advance failure must fail the attempt");

    assert_eq!(error.reason_code(), "LEASE_REFUSED");
    assert!(adapter.was_terminated());
    assert_eq!(failing.releases.load(Ordering::SeqCst), 1);
    assert_failed_and_requeued(&ledger, &grant.attempt.id, journal.as_ref());
}

#[tokio::test]
async fn preservation_failure_requeues_and_never_succeeds() {
    let (_temp, ledger, client, grant, config, mut workspace, mut info, journal) =
        cloned_attempt("preservation-failure").await;
    workspace.fail_preserve("injected preservation refusal");
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );

    let error = run_cloned_attempt(
        client,
        adapter,
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &grant,
        &config,
        &mut workspace,
        &mut info,
    )
    .await
    .expect_err("preservation refusal must fail the Attempt");

    assert_eq!(error.reason_code(), "IO_FAILED");
    let stages = journal.stages();
    assert!(stages.contains(&"candidate_prepared".to_string()));
    assert!(!stages.contains(&"candidate_preserved".to_string()));
    assert!(!stages.contains(&"workspace_cleaned".to_string()));
    assert_failed_and_requeued(&ledger, &grant.attempt.id, journal.as_ref());
}

fn assert_salvaged_without_apply(fixture: &FrozenFixture) {
    let stages = fixture.journal.stages();
    assert!(stages.contains(&"frozen".to_string()), "{stages:?}");
    assert!(
        stages.contains(&"salvage_checkpoint".to_string()),
        "{stages:?}"
    );
    assert!(stages.contains(&"terminated".to_string()), "{stages:?}");
    assert!(!stages.contains(&"patch_applied".to_string()), "{stages:?}");
    assert!(!stages.contains(&"released".to_string()), "{stages:?}");
    let frozen_at = stages
        .iter()
        .position(|stage| stage == "frozen")
        .expect("frozen stage");
    let salvage_at = stages
        .iter()
        .position(|stage| stage == "salvage_checkpoint")
        .expect("salvage stage");
    let terminated_at = stages
        .iter()
        .position(|stage| stage == "terminated")
        .expect("termination stage");
    assert!(frozen_at < salvage_at && salvage_at < terminated_at);
    assert!(fixture.adapter.was_terminated());
    assert_eq!(fixture.adapter.prompts().len(), 1);
    assert!(!fixture.repo_dir.join("PONG.txt").exists());
    assert!(
        stages.contains(&"salvage_preserved".to_string()),
        "{stages:?}"
    );

    let checkpoint = std::fs::read_to_string(fixture.runtime_dir.join("checkpoint.json"))
        .expect("preserved test checkpoint");
    assert!(checkpoint.contains("TEST_ONLY_SIMULATOR"));
    assert!(checkpoint.contains(fixture.attempt_id.as_str()));
    let salvage = fixture
        .farm_root
        .join("salvage")
        .join(fixture.attempt_id.as_str())
        .join("preservation.json");
    assert!(
        salvage.is_file(),
        "freeze must preserve bytes outside the live workspace"
    );

    let ledger = fixture.ledger.lock().expect("ledger");
    let attempt = ledger
        .get_attempt(&fixture.attempt_id)
        .expect("attempt read")
        .expect("attempt row");
    assert_eq!(attempt.state, AttemptState::Crashed);
    assert!(ledger
        .get_lease(&attempt.variant_id)
        .expect("lease read")
        .is_none());
    assert_eq!(ledger.ready_rows().expect("ready rows").len(), 1);
}

#[tokio::test]
async fn stale_heartbeat_after_clone_salvages_terminates_and_never_applies() {
    let fixture = freeze_after_clone("post-clone-stale").await;
    assert_salvaged_without_apply(&fixture);
}

#[tokio::test]
async fn successor_uses_fence_two_while_salvaged_workspace_stays_inert() {
    let fixture = freeze_after_clone("post-clone-successor").await;
    assert_salvaged_without_apply(&fixture);

    let grant = fixture
        .client
        .acquire(&request(fixture.package.clone(), "post-clone-successor-2"))
        .await
        .expect("successor lease");
    assert_eq!(grant.attempt.fence, 2);
    let config = fixture.client.admit_config(config(
        fixture.origin.clone(),
        fixture.base_sha.clone(),
        fixture.farm_root.clone(),
    ));
    let mut workspace = SimWorkspace::new(grant.authority_token.clone());
    let mut info = workspace
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await
        .expect("successor test clone");
    assert_ne!(info.repo_dir, fixture.repo_dir);
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );
    let successor_journal = Arc::new(MemoryJournal::new());
    let outcome = run_cloned_attempt(
        fixture.client.clone(),
        adapter,
        successor_journal.clone(),
        Arc::new(MonotonicClock::new()),
        &grant,
        &config,
        &mut workspace,
        &mut info,
    )
    .await
    .expect("successor completes in test simulator");
    assert_eq!(outcome.fence, 2);
    assert_eq!(outcome.candidate.prepared_at, "TEST_ONLY_SIMULATOR");
    assert!(!info.repo_dir.exists());
    assert!(outcome
        .preservation
        .receipt
        .destination
        .join("generation/repo/PONG.txt")
        .is_file());
    assert!(!fixture.repo_dir.join("PONG.txt").exists());
    assert!(fixture.runtime_dir.join("checkpoint.json").is_file());
    let successor_stages = successor_journal.stages();
    assert!(successor_stages.contains(&"candidate_prepared".to_string()));
    assert!(successor_stages.contains(&"candidate_preserved".to_string()));
    assert!(successor_stages.contains(&"workspace_cleaned".to_string()));
    assert!(successor_stages.contains(&"released".to_string()));
    let released_at = successor_stages
        .iter()
        .position(|stage| stage == "released")
        .expect("released");
    let cleaned_at = successor_stages
        .iter()
        .position(|stage| stage == "workspace_cleaned")
        .expect("cleaned");
    assert!(
        released_at < cleaned_at,
        "Candidate finalization must persist before workspace cleanup: {successor_stages:?}"
    );
    let terminated_at = successor_stages
        .iter()
        .position(|stage| stage == "terminated")
        .expect("terminated");
    assert!(
        terminated_at < released_at,
        "provider termination must precede terminal release"
    );
    assert_eq!(
        successor_stages.last().map(String::as_str),
        Some("workspace_cleaned")
    );

    let ledger = fixture.ledger.lock().expect("ledger");
    let first = ledger
        .get_attempt(&fixture.attempt_id)
        .expect("first read")
        .expect("first attempt");
    let second = ledger
        .get_attempt(&outcome.attempt_id)
        .expect("second read")
        .expect("second attempt");
    assert_eq!(first.state, AttemptState::Crashed);
    assert_eq!(second.state, AttemptState::Succeeded);
    assert_eq!((first.fence, second.fence), (1, 2));
    assert!(ledger.ready_rows().expect("ready rows").is_empty());
}
