//! Shared test support: a real origin repo, a seeded memory ledger, and a
//! scripted wrapper over the deterministic harness simulator that can
//! substitute proposals and delay turns.
#![allow(dead_code)]

use bullet_application::{materialize_plan, MemoryLedger, PlanInput};
use bullet_domain::{TaskClass, WorkPackageId};
use bullet_harness_core::{
    Ack, AgentEventKind, AuthChallenge, CompactRequest, ContextTransition, HarnessAdapter,
    HarnessDescriptor, HarnessEventStream, HarnessResult, ModelSnapshot, PermissionDecision,
    PlanDecision, ProbeResult, ProfileRef, QuotaObservation, ResumeSession, SessionCheckpoint,
    SessionHandle, StartSession, SteeringMessage, Turn, TurnHandle,
};
use bullet_harness_sim::SimAdapter;
use futures::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Fail rather than silently passing when the real workspace daemon is absent.
pub fn require_gitd() {
    bullet_runner_core::gitd_binary().unwrap_or_else(|error| {
        panic!(
            "{}: set BULLET_GITD_BIN and BULLET_GITD_SHA256 to the admitted daemon",
            error.reason_code()
        )
    });
}

/// Create a real git origin with one commit; returns (repo path, base SHA).
pub fn build_origin(dir: &Path) -> (PathBuf, String) {
    let repo = dir.join("origin");
    std::fs::create_dir_all(&repo).expect("origin dir");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", dir)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "farm@bullet.local"]);
    git(&["config", "user.name", "Bullet Farm"]);
    std::fs::write(repo.join("README.md"), "origin\n").expect("seed file");
    git(&["add", "README.md"]);
    git(&["commit", "-q", "-m", "base"]);
    let sha = git(&["rev-parse", "HEAD"]);
    (repo, sha)
}

/// Memory ledger with one materialized mission graph (one ready package).
pub fn seeded_ledger(seed: &str) -> (Arc<Mutex<MemoryLedger>>, WorkPackageId) {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "runner lane".into(),
            objective: "create PONG.txt".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("plan");
    let package = graph.packages[0].id.clone();
    (Arc::new(Mutex::new(ledger)), package)
}

/// A complete done=true proposal wrapping the given change entries.
pub fn proposal_with_changes(intent: &str, changes: Value) -> Value {
    let operations = changes
        .as_array()
        .expect("test changes")
        .iter()
        .map(|change| {
            serde_json::json!({
                "path": change["path"],
                "preimage": {"kind": "absent"},
                "mutation": {"kind": "write", "content_utf8": change["contents"]}
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": intent,
        "operations": operations,
        "gate_ids": [bullet_runner_core::REPOSITORY_GATE_ID],
        "claims": [],
        "uncertainties": [],
        "done": true
    })
}

/// A proposal whose path is outside every test scope grant.
pub fn out_of_scope_proposal() -> Value {
    serde_json::json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "write a secret outside the granted scope",
        "operations": [
            {
                "path": "secrets/key.txt",
                "preimage": {"kind": "absent"},
                "mutation": {"kind": "write", "content_utf8": "nope\n"}
            }
        ],
        "gate_ids": [bullet_runner_core::REPOSITORY_GATE_ID],
        "claims": [],
        "uncertainties": [],
        "done": true
    })
}

/// The deterministic simulator with per-turn proposal overrides, per-turn
/// delays, and recorded prompts. Everything else delegates to `SimAdapter`.
pub struct ScriptedSim {
    inner: SimAdapter,
    turns: AtomicUsize,
    overrides: Mutex<HashMap<usize, Value>>,
    delays: Mutex<HashMap<usize, Duration>>,
    prompts: Mutex<Vec<String>>,
}

impl ScriptedSim {
    pub fn new() -> Self {
        Self {
            inner: SimAdapter::new(),
            turns: AtomicUsize::new(0),
            overrides: Mutex::new(HashMap::new()),
            delays: Mutex::new(HashMap::new()),
            prompts: Mutex::new(Vec::new()),
        }
    }

    /// Replace the proposal of the Nth completed turn (0-based).
    pub fn override_proposal(&self, turn: usize, proposal: Value) {
        self.overrides
            .lock()
            .expect("overrides")
            .insert(turn, proposal);
    }

    /// Delay the Nth send before it reaches the simulator.
    pub fn delay_turn(&self, turn: usize, delay: Duration) {
        self.delays.lock().expect("delays").insert(turn, delay);
    }

    /// Prompts received so far, in order.
    pub fn prompts(&self) -> Vec<String> {
        self.prompts.lock().expect("prompts").clone()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for ScriptedSim {
    fn descriptor(&self) -> HarnessDescriptor {
        self.inner.descriptor()
    }
    async fn probe(&self, profile: &ProfileRef) -> HarnessResult<ProbeResult> {
        self.inner.probe(profile).await
    }
    async fn list_models(&self, profile: &ProfileRef) -> HarnessResult<Vec<ModelSnapshot>> {
        self.inner.list_models(profile).await
    }
    async fn observe_quota(&self, profile: &ProfileRef) -> HarnessResult<Vec<QuotaObservation>> {
        self.inner.observe_quota(profile).await
    }
    async fn begin_login(&self, profile: &ProfileRef) -> HarnessResult<AuthChallenge> {
        self.inner.begin_login(profile).await
    }
    async fn start(&self, request: StartSession) -> HarnessResult<SessionHandle> {
        self.inner.start(request).await
    }
    async fn resume(&self, request: ResumeSession) -> HarnessResult<SessionHandle> {
        self.inner.resume(request).await
    }
    async fn send(&self, session: &SessionHandle, turn: Turn) -> HarnessResult<TurnHandle> {
        let index = self.turns.fetch_add(1, Ordering::SeqCst);
        self.prompts
            .lock()
            .expect("prompts")
            .push(turn.prompt.clone());
        let delay = self.delays.lock().expect("delays").get(&index).copied();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        self.inner.send(session, turn).await
    }
    async fn steer(&self, session: &SessionHandle, message: SteeringMessage) -> HarnessResult<Ack> {
        self.inner.steer(session, message).await
    }
    async fn approve_local_plan(
        &self,
        session: &SessionHandle,
        decision: PlanDecision,
    ) -> HarnessResult<Ack> {
        self.inner.approve_local_plan(session, decision).await
    }
    async fn respond_permission(
        &self,
        session: &SessionHandle,
        decision: PermissionDecision,
    ) -> HarnessResult<Ack> {
        self.inner.respond_permission(session, decision).await
    }
    async fn compact(
        &self,
        session: &SessionHandle,
        request: CompactRequest,
    ) -> HarnessResult<ContextTransition> {
        self.inner.compact(session, request).await
    }
    async fn checkpoint(&self, session: &SessionHandle) -> HarnessResult<SessionCheckpoint> {
        self.inner.checkpoint(session).await
    }
    async fn interrupt(&self, session: &SessionHandle) -> HarnessResult<Ack> {
        self.inner.interrupt(session).await
    }
    async fn terminate(&self, session: &SessionHandle) -> HarnessResult<Ack> {
        self.inner.terminate(session).await
    }
    fn events(&self, session: &SessionHandle) -> HarnessEventStream {
        let overrides = self.overrides.lock().expect("overrides").clone();
        let mut completed = 0usize;
        Box::pin(self.inner.events(session).map(move |mut event| {
            if event.kind == AgentEventKind::TurnCompleted {
                if let Some(proposal) = overrides.get(&completed) {
                    let mut proposal = proposal.clone();
                    for field in [
                        "schema_version",
                        "proposal_id",
                        "producing_attempt_id",
                        "base_checkpoint_id",
                        "base_checkpoint_digest",
                    ] {
                        proposal[field] = event.payload["proposal"][field].clone();
                    }
                    event.payload["proposal"] = proposal;
                }
                completed += 1;
            }
            event
        }))
    }
}
