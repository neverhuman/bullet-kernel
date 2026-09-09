//! Enabling `live` must not restore Cursor process or credential access.
#![cfg(feature = "live")]

use bullet_harness_core::{
    AgentSessionId, ExpectedProfile, HarnessAdapter, ProfileRef, StartSession,
};
use bullet_harness_cursor::CursorAdapter;
use std::time::Duration;

#[tokio::test]
async fn live_feature_fails_closed_and_creates_zero_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let adapter = CursorAdapter::new();
    let profile = ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("cursor-live-blocked"),
        expected: ExpectedProfile::default(),
    };
    let probe = adapter.probe(&profile).await.expect_err("probe blocked");
    assert_eq!(probe.reason_code(), "PROVIDER_ADMISSION_BLOCKED");

    let artifacts = root.path().join("artifacts");
    let start = adapter
        .start(StartSession {
            session_id: AgentSessionId::new("cursor-live-blocked"),
            workdir: root.path().to_path_buf(),
            artifact_dir: artifacts.clone(),
            model: None,
            structured_schema: None,
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(1),
        })
        .await
        .expect_err("dispatch blocked");
    assert_eq!(start.reason_code(), "PROVIDER_ADMISSION_BLOCKED");
    assert!(!artifacts.exists());
    assert_eq!(root.path().read_dir().expect("read tempdir").count(), 0);
}
