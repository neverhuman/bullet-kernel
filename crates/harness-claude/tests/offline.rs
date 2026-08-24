//! Offline conformance: no provider process is spawned by these tests.

use bullet_harness_claude::ClaudeAdapter;
use bullet_harness_core::{
    conformance, AgentSessionId, ArgvBuilder, HarnessAdapter, SessionHandle, StartSession, Turn,
};
use futures::StreamExt;
use std::time::Duration;

#[tokio::test]
async fn offline_conformance_suite() {
    let adapter = ClaudeAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
}

#[test]
fn worktree_and_tmux_flags_are_denied_for_this_binary() {
    for token in [
        "-w",
        "--worktree",
        "--worktree=x",
        "--tmux",
        "--tmux=classic",
    ] {
        let err = ArgvBuilder::new("claude", "/tmp")
            .arg(token)
            .build()
            .expect_err(token);
        assert_eq!(err.reason_code(), "WORKTREE_FLAG_DENIED");
    }
}

#[tokio::test]
async fn unknown_session_is_typed_and_stream_is_empty() {
    let adapter = ClaudeAdapter::new();
    let handle = SessionHandle {
        session_id: AgentSessionId::new("missing"),
        provider: "claude".to_string(),
        native_session_id: None,
    };
    let err = adapter
        .send(
            &handle,
            Turn {
                prompt: "x".to_string(),
            },
        )
        .await
        .expect_err("unknown session");
    assert_eq!(err.reason_code(), "SESSION_UNKNOWN");
    let events: Vec<_> = adapter.events(&handle).collect().await;
    assert!(events.is_empty());
}

#[tokio::test]
async fn model_selection_is_refused_typed() {
    let adapter = ClaudeAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let err = adapter
        .start(StartSession {
            session_id: AgentSessionId::new(bullet_harness_core::synthetic_uuid("t")),
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join("a"),
            model: Some("claude-opus-4".to_string()),
            structured_schema: None,
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(5),
        })
        .await
        .expect_err("model unsupported");
    assert_eq!(err.reason_code(), "CAPABILITY_UNSUPPORTED");
}
