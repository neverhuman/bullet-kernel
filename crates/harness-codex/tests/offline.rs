//! Offline conformance: no provider process is spawned by these tests.

use bullet_harness_codex::CodexAdapter;
use bullet_harness_core::{
    conformance, AgentSessionId, ArgvBuilder, HarnessAdapter, SessionHandle, StartSession, Turn,
};
use futures::StreamExt;
use std::time::Duration;

#[tokio::test]
async fn offline_conformance_suite() {
    let adapter = CodexAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
}

#[test]
fn worktree_and_tmux_flags_are_denied_for_this_binary() {
    for token in ["-w", "--worktree", "--worktree-base=main", "--tmux"] {
        let err = ArgvBuilder::new("codex", "/tmp")
            .arg("exec")
            .arg(token)
            .build()
            .expect_err(token);
        assert_eq!(err.reason_code(), "WORKTREE_FLAG_DENIED");
    }
}

#[tokio::test]
async fn unknown_session_is_typed_and_stream_is_empty() {
    let adapter = CodexAdapter::new();
    let handle = SessionHandle {
        session_id: AgentSessionId::new("missing"),
        provider: "codex".to_string(),
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
async fn model_selection_is_refused_typed_and_schema_file_is_written() {
    let adapter = CodexAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let request = StartSession {
        session_id: AgentSessionId::new(bullet_harness_core::synthetic_uuid("t")),
        workdir: dir.path().to_path_buf(),
        artifact_dir: dir.path().join("a"),
        model: Some("sol".to_string()),
        structured_schema: None,
        max_budget_usd: None,
        wall_timeout: Duration::from_secs(5),
    };
    let err = adapter.start(request).await.expect_err("model unsupported");
    assert_eq!(err.reason_code(), "CAPABILITY_UNSUPPORTED");

    let session_id = AgentSessionId::new(bullet_harness_core::synthetic_uuid("t2"));
    let schema: serde_json::Value =
        serde_json::from_str(bullet_harness_core::proposal::schema_source()).expect("schema");
    adapter
        .start(StartSession {
            session_id: session_id.clone(),
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join("a"),
            model: None,
            structured_schema: Some(schema),
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(5),
        })
        .await
        .expect("start registers without spawning");
    let schema_file = dir
        .path()
        .join("a")
        .join(format!("{session_id}.schema.json"));
    let written = std::fs::read_to_string(schema_file).expect("schema file written");
    assert!(written.contains("PatchProposal"));
}
