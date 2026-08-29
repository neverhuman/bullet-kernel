//! Replay exported TLC traces against the real domain and SQLite implementations.

use std::path::{Path, PathBuf};

use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, receipt_id, EffectIntentRecord, EffectReceiptRecord, EffectState, LeaseGrant,
    LeaseService, Ledger, PlanInput, ReceiptVerdict, StoredGraph, ZERO_OID,
};
use bullet_domain::{
    Attempt, AttemptId, AuthorityToken, EffectId, MutationContext, MutationGuard, MutationRefusal,
    TaskClass,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

fn private_tempdir() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().expect("private tempdir")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    model: String,
    schema_version: String,
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    action: String,
    expected: String,
    #[serde(default)]
    runner: String,
    #[serde(default)]
    remote: String,
}

fn trace(name: &str) -> Trace {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formal")
        .join(name);
    let bytes = std::fs::read(path).expect("read generated formal trace");
    let trace = serde_json::from_slice::<Trace>(&bytes).expect("strict trace");
    assert_eq!(trace.schema_version, "v1alpha1");
    trace
}

fn t(offset: i64) -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_800_000_000 + offset)
}

fn ts(offset: i64) -> String {
    LeaseService::rfc3339(t(offset))
}

struct LeaseReplay {
    path: PathBuf,
    ledger: SqliteLedger,
    graph: StoredGraph,
    first_grant: Option<LeaseGrant>,
    first_token: Option<AuthorityToken>,
    second_attempt: Option<Attempt>,
    guard: Option<MutationGuard>,
    context: Option<MutationContext>,
}

impl LeaseReplay {
    fn new(path: &Path) -> Self {
        let mut ledger = SqliteLedger::open(path).expect("open SQLite");
        let graph = materialize_plan(
            &mut ledger,
            "formal-lease",
            &PlanInput {
                title: "formal lease".into(),
                objective: "trace replay".into(),
                packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
            },
            &ts(0),
        )
        .expect("materialize");
        Self {
            path: path.to_path_buf(),
            ledger,
            graph,
            first_grant: None,
            first_token: None,
            second_attempt: None,
            guard: None,
            context: None,
        }
    }

    fn apply(&mut self, step: &Step) -> &'static str {
        match step.action.as_str() {
            "acquire" => self.acquire(&step.runner),
            "tick" => {
                rusqlite::Connection::open(&self.path)
                    .expect("raw trace connection")
                    .execute(
                        "UPDATE active_leases
                         SET heartbeat_at = '2000-01-01T00:00:00.000Z',
                             expires_at = '2000-01-01T00:00:01.000Z'",
                        [],
                    )
                    .expect("advance exact test window");
                "time_advanced"
            }
            "heartbeat" => self.expired_heartbeat(),
            "reclaim" => {
                assert_eq!(self.ledger.expire_leases().unwrap().len(), 1);
                "accepted"
            }
            "apply_stale" => self.apply_stale(),
            "enter_barrier" => {
                self.guard.as_mut().unwrap().enter_barrier().unwrap();
                "accepted"
            }
            "append_scope" => {
                assert_eq!(self.guard.as_mut().unwrap().append_scope_revision(), Ok(2));
                "revision_2"
            }
            "apply_old_scope" => self.apply_old_scope(),
            "ack_scope" => self.ack_scope(),
            "resume" => {
                self.guard.as_mut().unwrap().resume().unwrap();
                "accepted"
            }
            "freeze" => self.freeze(),
            "apply" => self.apply_current(),
            "restore" => {
                assert_eq!(self.guard.as_mut().unwrap().restore(), 2);
                "authority_epoch_2"
            }
            "recover_active" => {
                self.guard.as_mut().unwrap().recover_active().unwrap();
                "active_epoch_2"
            }
            other => panic!("unknown LeaseFence action {other}"),
        }
    }

    fn acquire(&mut self, runner: &str) -> &'static str {
        let (attempt, token, grant) =
            LeaseService::acquire(&mut self.ledger, &self.graph, 0, runner, 1).expect("acquire");
        if runner == "r1" {
            self.first_grant = Some(grant);
            self.first_token = Some(token);
            "accepted"
        } else {
            assert_eq!(attempt.fence, 2);
            self.context = Some(MutationContext {
                fence: attempt.fence,
                scope_revision: 1,
                authority_epoch: 1,
                freeze_generation: 0,
            });
            self.guard = Some(MutationGuard::new(attempt.fence, 1, 1, 0));
            self.second_attempt = Some(attempt);
            "accepted_fence_2"
        }
    }

    fn expired_heartbeat(&mut self) -> &'static str {
        let request = LeaseService::heartbeat_of(self.first_grant.as_ref().unwrap());
        assert_eq!(
            self.ledger.heartbeat(&request).unwrap_err().reason_code(),
            "STALE_AUTHORITY"
        );
        "refused_expired"
    }

    fn apply_stale(&self) -> &'static str {
        assert!(LeaseService::authorize_patch_application(
            self.first_token.as_ref().unwrap(),
            self.second_attempt.as_ref().unwrap(),
        )
        .is_err());
        let mut request = self.context.unwrap();
        request.fence = 1;
        assert_eq!(
            self.guard.as_ref().unwrap().authorize_apply(request),
            Err(MutationRefusal::Fence)
        );
        "refused_fence"
    }

    fn apply_old_scope(&self) -> &'static str {
        assert_eq!(
            self.guard
                .as_ref()
                .unwrap()
                .authorize_apply(self.context.unwrap()),
            Err(MutationRefusal::ScopeRevision)
        );
        "refused_scope_revision"
    }

    fn ack_scope(&mut self) -> &'static str {
        self.guard.as_mut().unwrap().acknowledge_scope(2).unwrap();
        self.context.as_mut().unwrap().scope_revision = 2;
        "revision_2"
    }

    fn freeze(&mut self) -> &'static str {
        let generation = self.guard.as_mut().unwrap().freeze();
        self.context.as_mut().unwrap().freeze_generation = generation;
        assert_eq!(generation, 1);
        "generation_1"
    }

    fn apply_current(&self) -> &'static str {
        match self
            .guard
            .as_ref()
            .unwrap()
            .authorize_apply(self.context.unwrap())
        {
            Err(MutationRefusal::Frozen) => "refused_frozen",
            Err(MutationRefusal::AuthorityEpoch) => "refused_epoch",
            other => panic!("unexpected Apply result {other:?}"),
        }
    }
}

#[test]
fn lease_fence_trace_replays_against_sqlite_and_domain_guard() {
    let trace = trace("lease-fence-reclaim.json");
    assert_eq!(trace.model, "LeaseFence");
    let dir = private_tempdir();
    let mut replay = LeaseReplay::new(&dir.path().join("lease.sqlite"));
    for step in &trace.steps {
        assert_eq!(replay.apply(step), step.expected, "action {}", step.action);
    }
}

struct EffectReplay {
    path: PathBuf,
    ledger: Option<SqliteLedger>,
    intent_id: EffectId,
    effect_remote: &'static str,
    check_state: EffectState,
    check_remote: &'static str,
}

impl EffectReplay {
    fn new(path: PathBuf) -> Self {
        Self {
            ledger: Some(SqliteLedger::open(&path).unwrap()),
            path,
            intent_id: EffectId::from_seed("formal-effect"),
            effect_remote: "none",
            check_state: EffectState::Proposed,
            check_remote: "none",
        }
    }

    fn apply(&mut self, step: &Step) -> &'static str {
        let result = match step.action.as_str() {
            "persist_effect_intent" => self.persist_effect(),
            "dispatch_effect_response_lost" => {
                self.effect_remote = "desired";
                self.dispatch_unknown();
                "unknown"
            }
            "dispatch_effect_timeout" => {
                self.dispatch_unknown();
                "unknown"
            }
            "crash" => self.reopen_unknown(),
            "third_party_effect" => {
                self.effect_remote = "third_party";
                "unknown"
            }
            "readback_effect" => self.readback_effect(),
            "persist_proof" => {
                self.transition_effect(EffectState::Committed);
                "durable"
            }
            "persist_check_intent" => "intent",
            "dispatch_check_response_lost" => self.dispatch_check_unknown(),
            "readback_check" => self.readback_check(),
            other => panic!("unknown EffectCheck action {other}"),
        };
        let remote = if step.action.contains("check") {
            self.check_remote
        } else {
            self.effect_remote
        };
        assert_eq!(remote, step.remote, "remote for {}", step.action);
        result
    }

    fn persist_effect(&mut self) -> &'static str {
        let intent = EffectIntentRecord {
            id: self.intent_id.clone(),
            logical_effect_key: "formal:effect".into(),
            provider: "local-bare".into(),
            target_identity: "refs/heads/formal".into(),
            desired_state_hash: "b".repeat(40),
            expected_old_oid: ZERO_OID.into(),
            attempt_id: AttemptId::from_seed("formal-attempt"),
            fence: 1,
            policy_version: "policy-v1".into(),
            payload_hash: String::new(),
            provider_idempotency_key: None,
            state: EffectState::Proposed,
            unknown_retries: 0,
            created_at: "2026-08-24T00:00:00Z".into(),
        };
        assert!(self.ledger().record_effect_intent(&intent).unwrap().1);
        "intent"
    }

    fn dispatch_unknown(&mut self) {
        self.transition_effect(EffectState::Authorized);
        self.transition_effect(EffectState::Dispatching);
        self.transition_effect(EffectState::OutcomeUnknown);
    }

    fn reopen_unknown(&mut self) -> &'static str {
        drop(self.ledger.take());
        self.ledger = Some(SqliteLedger::open(&self.path).unwrap());
        let intent_id = self.intent_id.clone();
        let row = self
            .ledger()
            .get_effect_intent_by_id(&intent_id)
            .unwrap()
            .unwrap();
        assert_eq!(row.state, EffectState::OutcomeUnknown);
        "durable_unknown"
    }

    fn readback_effect(&mut self) -> &'static str {
        let (verdict, next, expected) = if self.effect_remote == "desired" {
            (
                ReceiptVerdict::Match,
                EffectState::Verified,
                "verified_exact",
            )
        } else {
            (
                ReceiptVerdict::Mismatch,
                EffectState::OrphanedRemote,
                "orphaned_remote",
            )
        };
        let receipt = EffectReceiptRecord {
            id: receipt_id(expected),
            effect_intent_id: self.intent_id.clone(),
            observed_remote_identity: "refs/heads/formal".into(),
            observed_state_hash: Some("c".repeat(40)),
            verification_method: "formal-readback".into(),
            verification_result: verdict,
            adopted_after_unknown: verdict == ReceiptVerdict::Match,
            recorded_at: "2026-08-24T00:00:01Z".into(),
        };
        assert!(self.ledger().record_effect_receipt(&receipt).unwrap());
        self.transition_effect(next);
        expected
    }

    fn dispatch_check_unknown(&mut self) -> &'static str {
        self.check_remote = "desired";
        for next in [
            EffectState::Authorized,
            EffectState::Dispatching,
            EffectState::OutcomeUnknown,
        ] {
            self.check_state = self.check_state.transition(next).unwrap();
        }
        "unknown"
    }

    fn readback_check(&mut self) -> &'static str {
        self.check_state = self.check_state.transition(EffectState::Verified).unwrap();
        "verified_exact"
    }

    fn transition_effect(&mut self, next: EffectState) {
        let intent_id = self.intent_id.clone();
        self.ledger().transition_effect(&intent_id, next).unwrap();
    }

    fn ledger(&mut self) -> &mut SqliteLedger {
        self.ledger.as_mut().unwrap()
    }
}

#[test]
fn effect_check_traces_replay_against_sqlite_and_effect_machine() {
    for name in ["effect-check-ambiguity.json", "effect-third-party.json"] {
        let trace = trace(name);
        assert_eq!(trace.model, "EffectCheck");
        let dir = private_tempdir();
        let mut replay = EffectReplay::new(dir.path().join("effect.sqlite"));
        for step in &trace.steps {
            assert_eq!(replay.apply(step), step.expected, "action {}", step.action);
        }
    }
}
