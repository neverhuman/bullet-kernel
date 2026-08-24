//! Live smoke lane: opt-in, spends real quota. Gated on the `live` feature,
//! `#[ignore]`, and BULLET_LIVE_PROVIDERS containing `cursor`.
#![cfg(feature = "live")]

use bullet_harness_core::{
    conformance, synthetic_uuid, AgentEventKind, AgentSessionId, ExpectedProfile, HarnessAdapter,
    PatchProposal, ProfileRef, StartSession, Turn,
};
use bullet_harness_cursor::CursorAdapter;
use futures::StreamExt;
use std::time::Duration;

fn enabled() -> bool {
    std::env::var("BULLET_LIVE_PROVIDERS").is_ok_and(|v| v.split(',').any(|p| p.trim() == "cursor"))
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
async fn live_smoke_cursor() {
    if !enabled() {
        eprintln!("live_smoke_cursor: skipped (BULLET_LIVE_PROVIDERS)");
        return;
    }
    let adapter = CursorAdapter::new();
    let profile = ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("live-cursor"),
        expected: ExpectedProfile {
            email: Some("ben@veox.ai".to_string()),
            account_id_prefix: None,
        },
    };
    let probe = conformance::check_probe_identity(&adapter, &profile)
        .await
        .expect("probe identity");
    let dir = setup_repo();
    let handle = adapter
        .start(StartSession {
            session_id: AgentSessionId::new(synthetic_uuid("live-cursor")),
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join(".bullet-artifacts"),
            model: None,
            structured_schema: None,
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(180),
        })
        .await
        .expect("start");
    let schema = bullet_harness_core::proposal::schema_source();
    let prompt = format!(
        "Do not create or modify any files. Output ONLY one JSON object, with no prose and no \
         code fences, that validates against this JSON Schema:\n{schema}\nThe object must \
         describe creating the file PONG.txt with contents 'PONG\\n' (one change, op create), \
         with done=true."
    );
    let started = std::time::Instant::now();
    let turn = adapter.send(&handle, Turn { prompt }).await.expect("send");
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
    let native = handle.native_session_id.clone().or_else(|| {
        events
            .iter()
            .rev()
            .find_map(|e| e.native_session_id.clone())
    });
    eprintln!(
        "RECEIPT provider=cursor version={} session={} usage=none_reported wall_s={} exit={:?}",
        probe.version,
        native.unwrap_or_default(),
        wall.as_secs(),
        turn.exit_code
    );
}
