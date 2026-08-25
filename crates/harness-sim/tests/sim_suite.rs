//! The simulator runs the full shared conformance suite plus one assertion
//! block per s33.2 condition. This is the default CI lane: no live provider.

use bullet_harness_core::conformance;
use bullet_harness_core::{
    synthetic_uuid, AgentEventKind, AgentSessionId, ExpectedProfile, HarnessAdapter,
    PermissionDecision, ProfileRef, ResumeSession, SessionHandle, StartSession, Turn,
};
use bullet_harness_sim::scenario::SimCondition;
use bullet_harness_sim::SimAdapter;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;

fn profile() -> ProfileRef {
    ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("sim-tests"),
        expected: ExpectedProfile {
            email: Some("sim@bullet.farm".to_string()),
            account_id_prefix: None,
        },
    }
}

fn start_request(dir: &tempfile::TempDir) -> StartSession {
    StartSession {
        session_id: AgentSessionId::new(synthetic_uuid("sim-test")),
        workdir: dir.path().to_path_buf(),
        artifact_dir: dir.path().join("artifacts"),
        model: Some("sim-economy".to_string()),
        structured_schema: None,
        max_budget_usd: None,
        wall_timeout: Duration::from_secs(10),
    }
}

async fn run_condition(
    condition: SimCondition,
) -> (
    SimAdapter,
    SessionHandle,
    Vec<bullet_harness_core::AgentEvent>,
) {
    let adapter = SimAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = adapter.start(start_request(&dir)).await.expect("start");
    let prompt = format!("run condition:{}", condition.as_str());
    let _ = adapter.send(&handle, Turn { prompt }).await;
    let events = adapter.events(&handle).collect::<Vec<_>>().await;
    (adapter, handle, events)
}

fn kinds(events: &[bullet_harness_core::AgentEvent]) -> Vec<AgentEventKind> {
    events.iter().map(|e| e.kind).collect()
}

fn anomaly_codes(events: &[bullet_harness_core::AgentEvent]) -> Vec<String> {
    events
        .iter()
        .filter(|e| e.kind == AgentEventKind::ProtocolError)
        .filter_map(|e| e.payload["reason_code"].as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn offline_suite_passes() {
    let adapter = SimAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
}

#[tokio::test]
async fn probe_identity_verifies_and_fails_closed() {
    let adapter = SimAdapter::new();
    let result = conformance::check_probe_identity(&adapter, &profile())
        .await
        .expect("probe identity");
    assert_eq!(result.version, bullet_harness_sim::SIM_VERSION);
}

#[tokio::test]
async fn simple_turn_yields_a_patch_proposal() {
    let adapter = SimAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let (handle, proposal) = conformance::run_simple_turn(
        &adapter,
        start_request(&dir),
        Turn {
            prompt: "create PONG.txt".to_string(),
        },
        true,
    )
    .await
    .expect("simple turn");
    let proposal = proposal.expect("structured proposal");
    assert_eq!(proposal.operations[0].path, "PONG.txt");
    assert!(proposal.done);
    let events = adapter.events(&handle).collect::<Vec<_>>().await;
    let raw = events
        .iter()
        .find_map(|e| e.raw_artifact.clone())
        .expect("raw artifact recorded");
    let text = std::fs::read_to_string(raw.as_str()).expect("raw transcript readable");
    assert!(text.contains("turn.completed"));
}

#[tokio::test]
async fn interrupt_terminates_a_long_turn_bounded() {
    let adapter: Arc<dyn HarnessAdapter> = Arc::new(SimAdapter::new());
    let dir = tempfile::tempdir().expect("tempdir");
    conformance::check_interrupt_bounded(
        adapter,
        start_request(&dir),
        Turn {
            prompt: "condition:long_turn".to_string(),
        },
        Duration::from_secs(2),
    )
    .await
    .expect("bounded interrupt");
}

#[tokio::test]
async fn streaming_and_tool_call_conditions() {
    let (_, _, events) = run_condition(SimCondition::Streaming).await;
    conformance::check_event_hygiene(&events).expect("hygiene");
    conformance::check_usage_honesty(&events).expect("usage");
    assert!(kinds(&events).contains(&AgentEventKind::ThinkingDelta));
    assert!(
        kinds(&events)
            .iter()
            .filter(|k| **k == AgentEventKind::TurnDelta)
            .count()
            >= 2
    );

    let (_, _, events) = run_condition(SimCondition::ToolCall).await;
    for kind in [
        AgentEventKind::ToolRequested,
        AgentEventKind::ToolStarted,
        AgentEventKind::ToolCompleted,
        AgentEventKind::TurnCompleted,
    ] {
        assert!(kinds(&events).contains(&kind), "{kind:?}");
    }
}

#[tokio::test]
async fn permission_prompt_waits_then_completes_on_decision() {
    let (adapter, handle, events) = run_condition(SimCondition::PermissionPrompt).await;
    assert!(kinds(&events).contains(&AgentEventKind::PermissionRequested));
    assert!(!kinds(&events).contains(&AgentEventKind::TurnCompleted));
    adapter
        .respond_permission(
            &handle,
            PermissionDecision {
                allow: true,
                scope: None,
            },
        )
        .await
        .expect("permission decision");
    let events = adapter.events(&handle).collect::<Vec<_>>().await;
    assert!(kinds(&events).contains(&AgentEventKind::TurnCompleted));
}

#[tokio::test]
async fn usage_context_and_quota_conditions() {
    let (_, _, events) = run_condition(SimCondition::UsageEvents).await;
    assert!(
        kinds(&events)
            .iter()
            .filter(|k| **k == AgentEventKind::UsageReported)
            .count()
            >= 2
    );
    conformance::check_usage_honesty(&events).expect("usage honesty");

    let (_, _, events) = run_condition(SimCondition::ContextReport).await;
    assert!(kinds(&events).contains(&AgentEventKind::ContextReported));

    let (_, _, events) = run_condition(SimCondition::QuotaReset).await;
    let quota: Vec<_> = events
        .iter()
        .filter(|e| e.kind == AgentEventKind::QuotaReported)
        .collect();
    assert_eq!(quota.len(), 2);
    assert_eq!(quota[1].payload["reset"], true);
}

#[tokio::test]
async fn auth_expiry_and_http_errors_are_typed() {
    let adapter = SimAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = adapter.start(start_request(&dir)).await.expect("start");
    let err = adapter
        .send(
            &handle,
            Turn {
                prompt: "condition:auth_expiry".to_string(),
            },
        )
        .await
        .expect_err("auth expiry is an error");
    assert_eq!(err.reason_code(), "AUTH_REQUIRED");
    let events = adapter.events(&handle).collect::<Vec<_>>().await;
    assert!(kinds(&events).contains(&AgentEventKind::AuthRequired));

    let (_, _, events) = run_condition(SimCondition::HttpErrors).await;
    for kind in [
        AgentEventKind::AuthRequired,
        AgentEventKind::RateLimited,
        AgentEventKind::TurnFailed,
    ] {
        assert!(kinds(&events).contains(&kind), "{kind:?}");
    }
}

#[tokio::test]
async fn event_anomalies_become_protocol_errors_without_corruption() {
    let (_, _, events) = run_condition(SimCondition::EventAnomalies).await;
    conformance::check_event_hygiene(&events).expect("hygiene survives anomalies");
    let codes = anomaly_codes(&events);
    for code in ["DUPLICATE_EVENT", "OUT_OF_ORDER_EVENT", "MALFORMED_EVENT"] {
        assert!(codes.iter().any(|c| c == code), "{code}: {codes:?}");
    }

    let (_, _, events) = run_condition(SimCondition::DelayedStaleEvent).await;
    assert!(anomaly_codes(&events).iter().any(|c| c == "STALE_EVENT"));
}

#[tokio::test]
async fn refusal_false_completion_and_crash_never_yield_proposals() {
    let (_, _, events) = run_condition(SimCondition::Refusal).await;
    let completed = events
        .iter()
        .find(|e| e.kind == AgentEventKind::TurnCompleted)
        .expect("completed");
    assert!(completed.payload["proposal"].is_null());
    assert_eq!(completed.payload["refusal"], "policy refusal");

    let (_, _, events) = run_condition(SimCondition::FalseCompletion).await;
    let completed = events
        .iter()
        .find(|e| e.kind == AgentEventKind::TurnCompleted)
        .expect("completed");
    assert!(
        completed.payload["proposal"].is_null(),
        "false done is not a proposal"
    );

    let adapter = SimAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = adapter.start(start_request(&dir)).await.expect("start");
    let err = adapter
        .send(
            &handle,
            Turn {
                prompt: "condition:process_crash".to_string(),
            },
        )
        .await
        .expect_err("crash is an error");
    assert_eq!(err.reason_code(), "PROVIDER_FAILURE");
}

#[tokio::test]
async fn context_limit_terminal_dialog_and_version_drift() {
    let (_, _, events) = run_condition(SimCondition::ContextLimit).await;
    assert!(kinds(&events).contains(&AgentEventKind::ContextReported));
    assert!(kinds(&events).contains(&AgentEventKind::TurnFailed));

    let (_, _, events) = run_condition(SimCondition::TerminalOnlyDialog).await;
    let request = events
        .iter()
        .find(|e| e.kind == AgentEventKind::PermissionRequested)
        .expect("dialog");
    assert_eq!(request.payload["channel"], "terminal_only");

    let (adapter, _, events) = run_condition(SimCondition::VersionDrift).await;
    let started: Vec<_> = events
        .iter()
        .filter(|e| e.kind == AgentEventKind::SessionStarted)
        .collect();
    let drifted = started
        .iter()
        .filter_map(|e| e.payload["binary_version"].as_str())
        .any(|v| v != bullet_harness_sim::SIM_VERSION);
    assert!(drifted, "drifted version must be observable");
    let descriptor_version = match adapter.descriptor().version {
        bullet_domain::Observation::Value { value } => value,
        other => panic!("descriptor version must be observed: {other:?}"),
    };
    assert_eq!(descriptor_version, bullet_harness_sim::SIM_VERSION);
}

#[tokio::test]
async fn resume_succeeds_natively_and_fails_typed_for_unknown_ids() {
    let adapter = SimAdapter::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let request = start_request(&dir);
    let session_id = request.session_id.clone();
    let handle = adapter.start(request).await.expect("start");
    let native = handle.native_session_id.clone().expect("native id");
    let resumed = adapter
        .resume(ResumeSession {
            session_id: session_id.clone(),
            native_session_id: native,
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join("artifacts"),
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(10),
        })
        .await
        .expect("native resume");
    assert_eq!(resumed.session_id, session_id);

    let err = adapter
        .resume(ResumeSession {
            session_id: AgentSessionId::new(synthetic_uuid("resume-fail")),
            native_session_id: "missing".to_string(),
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join("artifacts"),
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(10),
        })
        .await
        .expect_err("condition:resume_failure");
    assert_eq!(err.reason_code(), "SESSION_UNKNOWN");
}

#[tokio::test]
async fn all_18_conditions_are_named_and_selectable() {
    assert_eq!(SimCondition::ALL.len(), 18);
    for condition in SimCondition::ALL {
        let prompt = format!("x condition:{} y", condition.as_str());
        assert_eq!(SimCondition::from_prompt(&prompt), condition);
    }
    assert_eq!(SimCondition::from_prompt("plain"), SimCondition::Streaming);
}
