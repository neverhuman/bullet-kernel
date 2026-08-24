//! Offline conformance: no provider process is spawned by these tests.

use bullet_harness_antigravity::{turn_argv, AntigravityAdapter};
use bullet_harness_core::{
    conformance, AgentSessionId, ArgvBuilder, HarnessAdapter, SessionHandle, StartSession, Turn,
};
use futures::StreamExt;
use std::time::Duration;

#[tokio::test]
async fn offline_conformance_suite() {
    let adapter = AntigravityAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
}

#[test]
fn live_agy_argv_puts_prompt_last() {
    let args = turn_argv("pong", "180s");
    assert_eq!(
        args,
        [
            "--sandbox",
            "--mode",
            "plan",
            "--print-timeout",
            "180s",
            "-p=pong",
        ]
    );
    assert!(
        args[0] != "-p",
        "1.1.19 treats the token after -p as the prompt"
    );
}

#[test]
fn worktree_flags_are_denied_for_this_binary() {
    for token in ["-w", "--worktree", "--tmux"] {
        let err = ArgvBuilder::new("agy", "/tmp")
            .arg(token)
            .build()
            .expect_err(token);
        assert_eq!(err.reason_code(), "WORKTREE_FLAG_DENIED");
    }
}

#[tokio::test]
async fn unknown_session_is_typed_and_stream_is_empty() {
    let adapter = AntigravityAdapter::new();
    let handle = SessionHandle {
        session_id: AgentSessionId::new("missing"),
        provider: "agy".to_string(),
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
async fn structured_schema_and_model_are_refused_typed() {
    let adapter = AntigravityAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let base = StartSession {
        session_id: AgentSessionId::new(bullet_harness_core::synthetic_uuid("t")),
        workdir: dir.path().to_path_buf(),
        artifact_dir: dir.path().join("a"),
        model: None,
        structured_schema: None,
        max_budget_usd: None,
        wall_timeout: Duration::from_secs(5),
    };
    let mut with_schema = base.clone();
    with_schema.structured_schema = Some(serde_json::json!({ "type": "object" }));
    let err = adapter
        .start(with_schema)
        .await
        .expect_err("schema unsupported");
    assert_eq!(err.reason_code(), "CAPABILITY_UNSUPPORTED");
    let mut with_model = base;
    with_model.model = Some("gemini-3".to_string());
    let err = adapter
        .start(with_model)
        .await
        .expect_err("model unsupported");
    assert_eq!(err.reason_code(), "CAPABILITY_UNSUPPORTED");
}
