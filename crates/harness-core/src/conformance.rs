//! Shared conformance suite (spec s42, s33.2), generic over
//! `&dyn HarnessAdapter`. Adapter crates call these from their tests; the
//! simulator runs the full set; live lanes run the turn checks against real
//! CLIs. Failures are strings so one report can aggregate several checks.

use crate::adapter::{HarnessAdapter, ResumeSession, SessionHandle, StartSession, Turn};
use crate::argv::{denied_token, filter_env};
use crate::capability::{Capability, CapabilityState};
use crate::error::HarnessError;
use crate::event::{AgentEvent, AgentEventKind};
use crate::ids::{synthetic_uuid, AgentSessionId};
use crate::probe::{ExpectedProfile, ProbeResult, ProfileRef};
use crate::proposal::PatchProposal;
use bullet_domain::Observation;
use futures::StreamExt;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Descriptor sanity: complete 24-entry matrix, named provider and binary.
///
/// # Errors
///
/// A description of the first violated invariant.
pub fn check_descriptor(adapter: &dyn HarnessAdapter) -> Result<(), String> {
    let d = adapter.descriptor();
    if d.provider.trim().is_empty() {
        return Err("descriptor.provider is empty".to_string());
    }
    if d.binary.trim().is_empty() {
        return Err("descriptor.binary is empty".to_string());
    }
    if !d.capabilities.is_complete() {
        return Err("capability matrix does not cover all 24 capabilities".to_string());
    }
    for (cap, state) in d.capabilities.iter() {
        if state == CapabilityState::Unknown {
            return Err(format!(
                "descriptor declares {} as Unknown; declare it or leave it Unsupported",
                cap.as_str()
            ));
        }
    }
    Ok(())
}

fn dummy_handle(provider: &str) -> SessionHandle {
    SessionHandle {
        session_id: AgentSessionId::new(synthetic_uuid("conformance")),
        provider: provider.to_string(),
        native_session_id: None,
    }
}

fn require_unsupported(
    result: Result<(), HarnessError>,
    capability: Capability,
    method: &str,
) -> Result<(), String> {
    match result {
        Err(HarnessError::Unsupported { .. }) => Ok(()),
        Err(other) => Err(format!(
            "{method}: capability {} is Unsupported but the error was {} instead of UNSUPPORTED",
            capability.as_str(),
            other.reason_code()
        )),
        Ok(()) => Err(format!(
            "{method}: capability {} is Unsupported but the call succeeded",
            capability.as_str()
        )),
    }
}

/// Every capability the descriptor marks Unsupported must yield a typed
/// `UNSUPPORTED` error from its method, never a panic or a success.
///
/// # Errors
///
/// A description of the first dishonest method.
pub async fn check_unsupported_methods(adapter: &dyn HarnessAdapter) -> Result<(), String> {
    let d = adapter.descriptor();
    let handle = dummy_handle(&d.provider);
    let profile = ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("conformance"),
        expected: ExpectedProfile::default(),
    };
    let gated: [(Capability, &str); 8] = [
        (Capability::AuthChallenge, "begin_login"),
        (Capability::ModelSelection, "list_models"),
        (Capability::QuotaSource, "observe_quota"),
        (Capability::MidTurnSteering, "steer"),
        (Capability::PlanModeControl, "approve_local_plan"),
        (Capability::ToolApprovals, "respond_permission"),
        (Capability::NativeCompaction, "compact"),
        (Capability::SessionExport, "checkpoint"),
    ];
    for (capability, method) in gated {
        if d.capabilities.state(capability) != CapabilityState::Unsupported {
            continue;
        }
        let result: Result<(), HarnessError> = match method {
            "begin_login" => adapter.begin_login(&profile).await.map(|_| ()),
            "list_models" => adapter.list_models(&profile).await.map(|_| ()),
            "observe_quota" => adapter.observe_quota(&profile).await.map(|_| ()),
            "steer" => adapter
                .steer(
                    &handle,
                    crate::adapter::SteeringMessage { text: "x".into() },
                )
                .await
                .map(|_| ()),
            "approve_local_plan" => adapter
                .approve_local_plan(
                    &handle,
                    crate::adapter::PlanDecision {
                        approved: true,
                        note: None,
                    },
                )
                .await
                .map(|_| ()),
            "respond_permission" => adapter
                .respond_permission(
                    &handle,
                    crate::adapter::PermissionDecision {
                        allow: false,
                        scope: None,
                    },
                )
                .await
                .map(|_| ()),
            "compact" => adapter
                .compact(&handle, crate::adapter::CompactRequest::default())
                .await
                .map(|_| ()),
            "checkpoint" => adapter.checkpoint(&handle).await.map(|_| ()),
            _ => Ok(()),
        };
        require_unsupported(result, capability, method)?;
    }
    if d.capabilities.state(Capability::NativeResume) == CapabilityState::Unsupported {
        let resume = adapter
            .resume(ResumeSession {
                session_id: AgentSessionId::new(synthetic_uuid("conformance")),
                native_session_id: "missing".to_string(),
                workdir: std::env::temp_dir(),
                artifact_dir: std::env::temp_dir(),
                max_budget_usd: None,
                wall_timeout: Duration::from_secs(5),
            })
            .await
            .map(|_| ());
        require_unsupported(resume, Capability::NativeResume, "resume")?;
    }
    Ok(())
}

/// The builder-level guardrails every adapter relies on: worktree/tmux argv
/// tokens are denied and only non-authority locale/display hints may be
/// inherited by a child environment.
///
/// # Errors
///
/// A description of the first hole.
pub fn check_argv_guardrails() -> Result<(), String> {
    for token in [
        "-w",
        "--worktree",
        "--worktree=x",
        "--worktree-base",
        "--tmux",
        "--tmux=classic",
    ] {
        if denied_token(token).is_none() {
            return Err(format!("token {token} is not denied"));
        }
    }
    for token in ["-p", "--verbose", "-o", "--workspace", "--sandbox"] {
        if denied_token(token).is_some() {
            return Err(format!("legitimate token {token} is denied"));
        }
    }
    let kept = filter_env(vec![
        ("HOME".to_string(), "/h".to_string()),
        ("PATH".to_string(), "/bin".to_string()),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
        ("GH_TOKEN".to_string(), "x".to_string()),
        ("GITHUB_TOKEN".to_string(), "x".to_string()),
        ("SSH_AUTH_SOCK".to_string(), "x".to_string()),
        ("GIT_DIR".to_string(), "x".to_string()),
        ("AWS_SECRET_ACCESS_KEY".to_string(), "canary".to_string()),
        ("ANTHROPIC_API_KEY".to_string(), "canary".to_string()),
        ("OPENAI_API_KEY".to_string(), "canary".to_string()),
        ("BULLET_CANARY_SECRET".to_string(), "canary".to_string()),
    ]);
    let keys: BTreeSet<&str> = kept.iter().map(|(k, _)| k.as_str()).collect();
    if keys != BTreeSet::from(["LANG", "TERM"]) {
        return Err(format!("env filter kept {keys:?}"));
    }
    if kept.iter().any(|(_, value)| value == "canary") {
        return Err("env filter retained a canary secret".to_string());
    }
    Ok(())
}

/// Envelope hygiene: strictly increasing sequences, unique event ids, one
/// session id.
///
/// # Errors
///
/// A description of the first corrupt envelope.
pub fn check_event_hygiene(events: &[AgentEvent]) -> Result<(), String> {
    let mut seen_ids = BTreeSet::new();
    let mut last_seq: Option<u64> = None;
    let mut session: Option<&str> = None;
    for event in events {
        if !seen_ids.insert(event.event_id.as_str().to_string()) {
            return Err(format!("duplicate event_id {}", event.event_id));
        }
        if last_seq.is_some_and(|last| event.sequence <= last) {
            return Err(format!("sequence regression at {}", event.sequence));
        }
        last_seq = Some(event.sequence);
        let sid = event.session_id.as_str();
        match session {
            None => session = Some(sid),
            Some(existing) if existing != sid => {
                return Err("mixed session ids in one stream".to_string());
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Usage honesty: absence of usage events is an honest Unknown; a present
/// usage event must carry at least one numeric dimension.
///
/// # Errors
///
/// A description of a dishonest usage report.
pub fn check_usage_honesty(events: &[AgentEvent]) -> Result<(), String> {
    for event in events {
        if event.kind != AgentEventKind::UsageReported {
            continue;
        }
        let object = event
            .payload
            .as_object()
            .ok_or("usage.reported payload is not an object")?;
        let numeric = object.values().any(|v| v.is_number())
            || object.values().any(|v| {
                v.as_object()
                    .is_some_and(|inner| inner.values().any(serde_json::Value::is_number))
            });
        if !numeric {
            return Err("usage.reported carries no numeric dimension".to_string());
        }
    }
    Ok(())
}

/// Probe identity: version must be nonempty; a verified identity must pass
/// against the expectation and fail closed against a bogus one.
///
/// # Errors
///
/// A description of the failed identity contract.
pub async fn check_probe_identity(
    adapter: &dyn HarnessAdapter,
    profile: &ProfileRef,
) -> Result<ProbeResult, String> {
    let provider = adapter.descriptor().provider;
    let result = adapter
        .probe(profile)
        .await
        .map_err(|err| format!("probe failed: {err}"))?;
    if result.version.trim().is_empty() {
        return Err("probe returned an empty version".to_string());
    }
    if matches!(result.profile, Observation::Value { .. }) {
        result
            .verify(&provider, &profile.expected)
            .map_err(|err| format!("expected profile rejected: {err}"))?;
        let bogus = ExpectedProfile {
            email: Some("bogus@example.invalid".to_string()),
            account_id_prefix: None,
        };
        match result.verify(&provider, &bogus) {
            Err(HarnessError::ProfileMismatch { .. }) => {}
            other => return Err(format!("bogus profile did not fail closed: {other:?}")),
        }
    } else {
        match result.verify(&provider, &profile.expected) {
            Err(HarnessError::ProfileUnverified { .. }) => {}
            other => {
                return Err(format!(
                    "unverified identity must fail closed, got {other:?}"
                ))
            }
        }
    }
    Ok(result)
}

/// Run one simple turn and (when `structured`) parse the PatchProposal out
/// of the `turn.completed` payload. Also checks event hygiene and usage
/// honesty over the produced stream.
///
/// # Errors
///
/// A description of the failed turn contract.
pub async fn run_simple_turn(
    adapter: &dyn HarnessAdapter,
    request: StartSession,
    turn: Turn,
    structured: bool,
) -> Result<(SessionHandle, Option<PatchProposal>), String> {
    let handle = adapter
        .start(request)
        .await
        .map_err(|err| format!("start failed: {err}"))?;
    let turn_handle = adapter
        .send(&handle, turn)
        .await
        .map_err(|err| format!("send failed: {err}"))?;
    if turn_handle.timed_out {
        return Err("turn timed out".to_string());
    }
    let events: Vec<AgentEvent> = adapter.events(&handle).collect().await;
    check_event_hygiene(&events)?;
    check_usage_honesty(&events)?;
    let completed = events
        .iter()
        .find(|e| e.kind == AgentEventKind::TurnCompleted)
        .ok_or("no turn.completed event")?;
    if !structured {
        return Ok((handle, None));
    }
    let proposal_value = completed
        .payload
        .get("proposal")
        .filter(|v| !v.is_null())
        .ok_or("turn.completed carries no proposal")?;
    let proposal = PatchProposal::from_value(proposal_value)
        .map_err(|err| format!("proposal invalid: {err}"))?;
    Ok((handle, Some(proposal)))
}

/// Interrupting a long turn must terminate it within `bound`.
///
/// # Errors
///
/// A description of the unbounded or unacknowledged interrupt.
pub async fn check_interrupt_bounded(
    adapter: Arc<dyn HarnessAdapter>,
    request: StartSession,
    long_turn: Turn,
    bound: Duration,
) -> Result<(), String> {
    let handle = adapter
        .start(request)
        .await
        .map_err(|err| format!("start failed: {err}"))?;
    let started = Instant::now();
    let send_adapter = Arc::clone(&adapter);
    let send_handle = handle.clone();
    let sender = tokio::spawn(async move { send_adapter.send(&send_handle, long_turn).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    adapter
        .interrupt(&handle)
        .await
        .map_err(|err| format!("interrupt failed: {err}"))?;
    let _ = sender.await;
    if started.elapsed() > bound {
        return Err(format!(
            "interrupt not bounded: took {:?} > {bound:?}",
            started.elapsed()
        ));
    }
    let events: Vec<AgentEvent> = adapter.events(&handle).collect().await;
    let acknowledged = events.iter().any(|e| {
        matches!(
            e.kind,
            AgentEventKind::InterruptAcknowledged | AgentEventKind::SessionTerminated
        )
    });
    if !acknowledged {
        return Err("no interrupt.acknowledged or session.terminated event".to_string());
    }
    Ok(())
}

/// The offline portion every adapter must pass without touching a provider.
///
/// # Errors
///
/// The first failed check's description.
pub async fn offline_suite(adapter: &dyn HarnessAdapter) -> Result<(), String> {
    check_descriptor(adapter)?;
    check_unsupported_methods(adapter).await?;
    check_argv_guardrails()?;
    Ok(())
}
