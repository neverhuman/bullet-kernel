//! Live smoke lane: opt-in, spends real quota. Gated on the `live` feature,
//! `#[ignore]`, and BULLET_LIVE_PROVIDERS containing `agy`. Text-only: the
//! assertion is a clean exit and honest text handling, never a proposal.
#![cfg(feature = "live")]

use bullet_domain::Observation;
use bullet_harness_antigravity::AntigravityAdapter;
use bullet_harness_core::{
    conformance, synthetic_uuid, AgentEventKind, AgentSessionId, ExpectedProfile, HarnessAdapter,
    ProfileRef, StartSession, Turn,
};
use futures::StreamExt;
use std::time::Duration;

fn enabled() -> bool {
    std::env::var("BULLET_LIVE_PROVIDERS").is_ok_and(|v| v.split(',').any(|p| p.trim() == "agy"))
}

#[tokio::test]
#[ignore]
async fn live_smoke_agy() {
    if !enabled() {
        eprintln!("live_smoke_agy: skipped (BULLET_LIVE_PROVIDERS)");
        return;
    }
    let adapter = AntigravityAdapter::new();
    let profile = ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("live-agy"),
        expected: ExpectedProfile::default(),
    };
    let probe = adapter.probe(&profile).await.expect("probe");
    assert!(!probe.version.trim().is_empty());
    assert!(
        matches!(probe.profile, Observation::Unknown { .. }),
        "agy has no identity surface; anything else is a surprise"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("README.md"), "# throwaway\n").expect("seed");
    let handle = adapter
        .start(StartSession {
            session_id: AgentSessionId::new(synthetic_uuid("live-agy")),
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join(".bullet-artifacts"),
            model: None,
            structured_schema: None,
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
                prompt: "Print a unified diff that creates a file PONG.txt containing the single \
                         line PONG. Put the diff inside a ```diff fenced code block. Do not run \
                         any commands."
                    .to_string(),
            },
        )
        .await
        .expect("send");
    let wall = started.elapsed();
    let events: Vec<_> = adapter.events(&handle).collect().await;
    conformance::check_event_hygiene(&events).expect("hygiene");
    let closed = events.iter().find(|e| {
        matches!(
            e.kind,
            AgentEventKind::TurnCompleted | AgentEventKind::TurnFailed
        )
    });
    let closed = closed.expect("typed turn.completed or turn.failed");
    let diff_found = closed.payload["diff"].is_string();
    if closed.kind == AgentEventKind::TurnCompleted {
        assert!(
            closed.payload["proposal"].is_null(),
            "text-only, never a proposal"
        );
        assert!(closed.payload["text"]
            .as_str()
            .is_some_and(|t| !t.is_empty()));
    }
    eprintln!(
        "RECEIPT provider=agy version={} session=none usage=none_reported wall_s={} exit={:?} outcome={} diff_extracted={}",
        probe.version,
        wall.as_secs(),
        turn.exit_code,
        closed.kind.as_str(),
        diff_found
    );
}
