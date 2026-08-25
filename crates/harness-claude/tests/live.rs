//! Enabling `live` must never restore ambient Claude execution.
#![cfg(feature = "live")]

use bullet_harness_claude::ClaudeAdapter;
use bullet_harness_core::{AgentSessionId, HarnessAdapter, StartSession};
use std::time::Duration;

#[tokio::test]
async fn live_feature_still_fails_closed_without_authority() {
    let directory = tempfile::tempdir().expect("tempdir");
    let artifact_dir = directory.path().join("artifacts");
    let error = ClaudeAdapter::new()
        .start(StartSession {
            session_id: AgentSessionId::new("live-remains-blocked"),
            workdir: directory.path().to_path_buf(),
            artifact_dir: artifact_dir.clone(),
            model: None,
            structured_schema: None,
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(1),
        })
        .await
        .expect_err("live dispatch must remain blocked");
    assert_eq!(error.reason_code(), "PROVIDER_ADMISSION_BLOCKED");
    assert!(!artifact_dir.exists());
}
