//! Live smoke lane: opt-in, spends real quota. Gated on the `live` feature,
//! `#[ignore]`, and BULLET_LIVE_PROVIDERS containing `codex`.
#![cfg(feature = "live")]

use bullet_harness_codex::CodexAdapter;
use bullet_harness_core::{
    conformance, synthetic_uuid, AgentEventKind, AgentSessionId, ExpectedProfile, HarnessAdapter,
    PatchProposal, ProfileRef, StartSession, Turn,
};
use futures::StreamExt;
use std::time::Duration;

fn enabled() -> bool {
    std::env::var("BULLET_LIVE_PROVIDERS").is_ok_and(|v| v.split(',').any(|p| p.trim() == "codex"))
}

fn setup_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let _ = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status();
    std::fs::write(
        dir.path().join("README.md"),
        "# throwaway live smoke repo\n",
    )
    .expect("seed");
    dir
}

#[tokio::test]
#[ignore]
async fn live_smoke_codex() {
    if !enabled() {
        eprintln!("live_smoke_codex: skipped (BULLET_LIVE_PROVIDERS)");
        return;
    }
    let adapter = CodexAdapter::new();
    let profile = ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("live-codex"),
        expected: ExpectedProfile {
            email: None,
            account_id_prefix: Some("016926d0".to_string()),
        },
    };
    let probe = conformance::check_probe_identity(&adapter, &profile)
        .await
        .expect("probe identity");
    let dir = setup_repo();
    let handle = adapter
        .start(StartSession {
            session_id: AgentSessionId::new(synthetic_uuid("live-codex")),
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join(".bullet-artifacts"),
            model: None,
            structured_schema: Some(
                serde_json::from_str(bullet_harness_core::proposal::schema_source())
                    .expect("schema"),
            ),
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(180),
        })
        .await
        .expect("start");
    let started = std::time::Instant::now();
    let turn = adapter
        .send(
            &handle,
            Turn {
                prompt:
                    "Respond with a PatchProposal that creates the file PONG.txt with contents \
                         PONG. Set intent_summary, one change (path PONG.txt, op create, contents \
                         'PONG\\n'), gate_ids exactly [\"repo.gate.v1\"], claims, uncertainties, \
                         and done=true."
                        .to_string(),
            },
        )
        .await
        .expect("send");
    let wall = started.elapsed();
    assert!(!turn.timed_out, "turn timed out");
    let events: Vec<_> = adapter.events(&handle).collect().await;
    conformance::check_event_hygiene(&events).expect("hygiene");
    conformance::check_usage_honesty(&events).expect("usage honesty");
    let completed = events
        .iter()
        .find(|e| e.kind == AgentEventKind::TurnCompleted)
        .unwrap_or_else(|| {
            for e in &events {
                eprintln!("EVENT {} {}", e.kind.as_str(), e.payload);
            }
            panic!("no turn.completed event; exit={:?}", turn.exit_code);
        });
    let proposal =
        PatchProposal::from_value(&completed.payload["proposal"]).expect("proposal parses");
    assert!(
        proposal.changes.iter().any(|c| c.path.contains("PONG")),
        "changes: {:?}",
        proposal.changes
    );
    let usage = events
        .iter()
        .find(|e| e.kind == AgentEventKind::UsageReported)
        .map(|e| e.payload.to_string());
    let native = events
        .iter()
        .rev()
        .find_map(|e| e.native_session_id.clone());
    eprintln!(
        "RECEIPT provider=codex version={} session={} usage={} wall_s={} exit={:?}",
        probe.version,
        native.unwrap_or_default(),
        usage.unwrap_or_default(),
        wall.as_secs(),
        turn.exit_code
    );
}
