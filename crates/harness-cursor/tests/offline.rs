//! Offline conformance: no provider process is spawned by these tests.
//! (`start` mints a chat id via the real CLI, so it is not called here.)

use bullet_harness_core::{
    conformance, AgentSessionId, ArgvBuilder, HarnessAdapter, SessionHandle, Turn,
};
use bullet_harness_cursor::CursorAdapter;
use futures::StreamExt;

#[tokio::test]
async fn offline_conformance_suite() {
    let adapter = CursorAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
}

#[test]
fn worktree_flags_are_denied_for_this_binary() {
    for token in [
        "-w",
        "--worktree",
        "--worktree=side",
        "--worktree-base",
        "--worktree-base=main",
    ] {
        let err = ArgvBuilder::new("cursor-agent", "/tmp")
            .arg(token)
            .build()
            .expect_err(token);
        assert_eq!(err.reason_code(), "WORKTREE_FLAG_DENIED");
    }
}

#[tokio::test]
async fn unknown_session_is_typed_and_stream_is_empty() {
    let adapter = CursorAdapter::new();
    let handle = SessionHandle {
        session_id: AgentSessionId::new("missing"),
        provider: "cursor".to_string(),
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
