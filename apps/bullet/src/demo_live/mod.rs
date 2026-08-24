//! Two demonstration surfaces over one orchestration: `demo-synthetic`
//! (simulator-only integration scaffolding; cannot produce a five-plane
//! transaction receipt) and `demo-live` (the same story with real
//! providers, admitted ONLY by the operator's explicit BULLET_LIVE_ADMISSION
//! token; every spawn stays behind the harness-core default-deny gate).

mod council;
mod effect;
mod fixture;
mod live_adapters;
mod plan_types;
mod receipt;
mod runner;
mod synthetic_adapter;
mod synthetic_council;
mod turns;
mod verify;

use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, HeartbeatRequest, LeaseService, Ledger, PlanInput, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, Candidate, CandidateId, Digest, Evidence, EvidenceId,
    TaskClass,
};
use bullet_harness_core::{live_admission_granted, LIVE_ADMISSION_VAR};
use bullet_verifier_core::VerifierRequest;
use chrono::Utc;
use receipt::{compute_scaffold_failures, EffectOut, SyntheticIntegrationReceipt, UsageRow};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) type SharedLedger = Arc<Mutex<SqliteLedger>>;

fn lock(ledger: &SharedLedger) -> Result<MutexGuard<'_, SqliteLedger>, String> {
    ledger
        .lock()
        .map_err(|_| "ledger mutex poisoned".to_string())
}

/// Run the demonstration and emit its receipt. `sim` needs no admission;
/// any live provider refuses typed unless the operator's explicit
/// admission token is present — before any ledger write.
pub fn run(provider: &str, target: Option<PathBuf>, data_dir: PathBuf) -> Result<(), String> {
    if provider != "sim" {
        let admission = std::env::var(LIVE_ADMISSION_VAR).ok();
        if !live_admission_granted(admission.as_deref()) {
            return Err(format!(
                "LIVE_ADMISSION_UNAVAILABLE: live provider {provider} is default-denied; \
                 the operator must set {LIVE_ADMISSION_VAR} to the recorded admission token"
            ));
        }
    }
    let runtime = tokio::runtime::Runtime::new().map_err(|err| format!("tokio runtime: {err}"))?;
    runtime.block_on(run_async(provider, target, data_dir))
}

async fn run_async(
    provider: &str,
    target: Option<PathBuf>,
    data_dir: PathBuf,
) -> Result<(), String> {
    std::fs::create_dir_all(&data_dir).map_err(|err| format!("create data dir: {err}"))?;
    let ledger: SharedLedger = Arc::new(Mutex::new(
        SqliteLedger::open(data_dir.join("ledger.sqlite"))
            .map_err(|err| format!("open ledger: {err}"))?,
    ));
    let fixture = fixture::prepare(&data_dir, target)?;
    let mut assembly = Assembly::new(provider);
    if let Err(failure) = drive(provider, &ledger, &fixture, &data_dir, &mut assembly).await {
        assembly.step_failure = Some(failure);
    }
    finish(&ledger, &data_dir, assembly)
}

async fn drive(
    provider: &str,
    ledger: &SharedLedger,
    fixture: &fixture::Fixture,
    data_dir: &Path,
    assembly: &mut Assembly,
) -> Result<(), String> {
    let council = if provider == "sim" {
        synthetic_council::run_council(ledger)?
    } else {
        council::run_live_council(ledger, fixture, data_dir).await?
    };
    assembly.absorb_council(&council);
    let materialized = materialize(provider, ledger, &council)?;
    assembly.absorb_materialized(&materialized);
    let first = first_incarnation(ledger, &materialized.graph)?;
    assembly.fence_first = Some(first.fence);
    assembly.attempt_first_id = Some(first.attempt.id.to_string());
    let phase = runner::run_phase(provider, ledger, &materialized.graph, fixture, data_dir).await?;
    assembly.absorb_runner(provider, &phase);
    record_runner_journal(ledger, &phase)?;
    persist_candidate(ledger, &phase)?;
    assembly.stale_refused = stale_refused(
        ledger,
        &materialized.graph,
        &first.attempt,
        &phase.outcome.attempt_id,
    )?;
    assembly.evidence = Some(verify_candidate(ledger, fixture, &phase).await?);
    let labels = if provider == "sim" {
        effect::DeliveryLabels {
            policy_version: "synthetic-only-v1",
            lease_seed: "demo-synthetic-delivery",
        }
    } else {
        effect::DeliveryLabels {
            policy_version: "demo-live-v1",
            lease_seed: "demo-live-delivery",
        }
    };
    assembly.local_effect = Some(effect::deliver_local(
        ledger,
        &materialized.graph,
        &phase.outcome.candidate.id,
        &phase.outcome.candidate.head_commit,
        &phase.workspace_repo,
        data_dir,
        &labels,
    )?);
    assembly.jeryu = Some(effect::probe_jeryu(&format!(
        "refs/heads/bullet/candidate/{}",
        phase.outcome.candidate.id
    )));
    Ok(())
}

struct Materialized {
    graph: StoredGraph,
    once: bool,
    plan_hash: String,
}

fn materialize(
    provider: &str,
    ledger: &SharedLedger,
    council: &synthetic_council::CouncilOutcome,
) -> Result<Materialized, String> {
    let (seed_prefix, title) = if provider == "sim" {
        (
            "demo-synthetic",
            "synthetic integration: PONG component exercise",
        )
    } else {
        ("demo-live", "demo-live: verified PONG delivery")
    };
    let seed = format!(
        "{seed_prefix}:{}",
        &council.fused_digest[..16.min(council.fused_digest.len())]
    );
    let input = PlanInput {
        title: title.into(),
        objective: fixture::OBJECTIVE.into(),
        packages: vec![
            (
                format!(
                    "Implement the fused plan ({} steps)",
                    council.fused.steps.len()
                ),
                TaskClass::FeatureImplementation,
            ),
            (
                "Deliver the candidate to the forge".into(),
                TaskClass::MechanicalCodeEdit,
            ),
        ],
    };
    let now = LeaseService::rfc3339(Utc::now());
    let mut guard = lock(ledger)?;
    let first = materialize_plan(&mut *guard, &seed, &input, &now)
        .map_err(|err| format!("MATERIALIZE:{}: {err}", err.reason_code()))?;
    let second = materialize_plan(&mut *guard, &seed, &input, &now)
        .map_err(|err| format!("MATERIALIZE_REPLAY:{}: {err}", err.reason_code()))?;
    let once = first.mission.id == second.mission.id
        && first.plan.canonical_hash == second.plan.canonical_hash;
    Ok(Materialized {
        plan_hash: first.plan.canonical_hash.to_hex(),
        graph: second,
        once,
    })
}

struct FirstIncarnation {
    attempt: Attempt,
    fence: u64,
}

fn first_incarnation(
    ledger: &SharedLedger,
    graph: &StoredGraph,
) -> Result<FirstIncarnation, String> {
    let mut guard = lock(ledger)?;
    let store = &mut *guard;
    let (attempt, _token, grant) =
        LeaseService::acquire(store, graph, 0, "demo-synthetic-first", Utc::now(), 60)
            .map_err(|err| format!("FIRST_LEASE:{}: {err}", err.reason_code()))?;
    let mut running = attempt;
    running.state = running
        .state
        .transition(AttemptState::Running)
        .map_err(|err| format!("FIRST_TRANSITION: {err}"))?;
    store
        .put_attempt(&running)
        .map_err(|err| format!("FIRST_PUT:{}: {err}", err.reason_code()))?;
    store
        .heartbeat(&LeaseService::heartbeat_of(&grant, Utc::now(), 60))
        .map_err(|err| format!("FIRST_HEARTBEAT:{}: {err}", err.reason_code()))?;
    LeaseService::release(store, &grant, AttemptState::Superseded, true, Utc::now())
        .map_err(|err| format!("FIRST_RELEASE:{}: {err}", err.reason_code()))?;
    let fence = running.fence;
    Ok(FirstIncarnation {
        attempt: running,
        fence,
    })
}

/// Persist the runner's stage journal as one durable audit event.
fn record_runner_journal(ledger: &SharedLedger, phase: &runner::RunnerPhase) -> Result<(), String> {
    let stages: Vec<serde_json::Value> = phase
        .journal
        .iter()
        .map(|(stage, detail)| serde_json::json!({ "stage": stage, "detail": detail }))
        .collect();
    let body = serde_json::json!({
        "attempt_id": phase.outcome.attempt_id.as_str(),
        "stages": stages,
    });
    let mut guard = lock(ledger)?;
    guard
        .append_event("runner_journal", &body.to_string())
        .map_err(|err| format!("JOURNAL_EVENT:{}: {err}", err.reason_code()))?;
    Ok(())
}

fn persist_candidate(ledger: &SharedLedger, phase: &runner::RunnerPhase) -> Result<(), String> {
    let candidate = &phase.outcome.candidate;
    let row = Candidate {
        id: CandidateId::parse(&candidate.id).map_err(|err| format!("CANDIDATE_ID: {err}"))?,
        attempt_id: phase.outcome.attempt_id.clone(),
        base_sha: candidate.base_commit.clone(),
        head_sha: candidate.head_commit.clone(),
        tree_sha: candidate.tree_hash.clone(),
        patch_digest: Digest::from_hex(&candidate.patch_hash)
            .map_err(|err| format!("CANDIDATE_PATCH_DIGEST: {err}"))?,
    };
    let mut guard = lock(ledger)?;
    if guard
        .put_candidate(&row)
        .map_err(|err| format!("CANDIDATE_PUT:{}: {err}", err.reason_code()))?
    {
        guard
            .append_event("candidate_prepared", row.id.as_str())
            .map_err(|err| format!("CANDIDATE_EVENT:{}: {err}", err.reason_code()))?;
    }
    Ok(())
}

/// Both stale probes must be refused live: the superseded incarnation's
/// six-column heartbeat, and its reconstructed (wrong-fence) token.
fn stale_refused(
    ledger: &SharedLedger,
    graph: &StoredGraph,
    first: &Attempt,
    live_id: &AttemptId,
) -> Result<bool, String> {
    let mut guard = lock(ledger)?;
    let store = &mut *guard;
    let now = Utc::now();
    let heartbeat = HeartbeatRequest {
        variant_id: first.variant_id.clone(),
        attempt_id: first.id.clone(),
        fence: first.fence,
        runner_id: first.runner_id.clone(),
        runner_epoch: first.runner_epoch,
        workspace_nonce: first.workspace_nonce,
        now: LeaseService::rfc3339(now),
        expires_at: LeaseService::rfc3339(now + chrono::Duration::seconds(60)),
    };
    let heartbeat_refused = matches!(
        store.heartbeat(&heartbeat),
        Err(err) if err.reason_code() == "STALE_AUTHORITY"
    );
    let live = store
        .get_attempt(live_id)
        .map_err(|err| format!("STALE_READ:{}: {err}", err.reason_code()))?
        .ok_or("live attempt row missing")?;
    let stale_token = LeaseService::token_for(graph, first)
        .map_err(|err| format!("STALE_TOKEN:{}: {err}", err.reason_code()))?;
    let token_refused = LeaseService::authorize(&stale_token, &live).is_err();
    let refused = heartbeat_refused && token_refused;
    if refused {
        let _ = store.append_event("stale_refused", first.id.as_str());
    }
    Ok(refused)
}

async fn verify_candidate(
    ledger: &SharedLedger,
    fixture: &fixture::Fixture,
    phase: &runner::RunnerPhase,
) -> Result<receipt::EvidenceOut, String> {
    let candidate = &phase.outcome.candidate;
    let request = VerifierRequest {
        workspace_repo_path: phase.workspace_repo.display().to_string(),
        base_sha: candidate.base_commit.clone(),
        head_sha: candidate.head_commit.clone(),
        tree_sha: candidate.tree_hash.clone(),
        gate_command: fixture.gate_command.clone(),
        timeout_secs: 120,
        author_attempt_id: phase.outcome.attempt_id.to_string(),
    };
    let record = verify::run_verifier(&request).await?;
    let out = receipt::EvidenceOut {
        verifier_outcome: record.outcome.as_str().to_string(),
        tier: record.tier.as_str().to_string(),
        gate: record.gate.clone(),
        produced_by: record.produced_by.clone(),
    };
    let mut guard = lock(ledger)?;
    let evidence = Evidence {
        id: EvidenceId::from_seed(&format!("demo-synthetic:{}", candidate.id)),
        candidate_id: CandidateId::parse(&candidate.id)
            .map_err(|err| format!("CANDIDATE_ID: {err}"))?,
        tier: out.tier.clone(),
        gate: out.gate.clone(),
        result: out.verifier_outcome.clone(),
    };
    if guard
        .put_evidence(&evidence)
        .map_err(|err| format!("EVIDENCE_PUT:{}: {err}", err.reason_code()))?
    {
        let body = serde_json::to_string(&record).unwrap_or_else(|_| evidence.id.to_string());
        guard
            .append_event("evidence_attached", &body)
            .map_err(|err| format!("EVIDENCE_EVENT:{}: {err}", err.reason_code()))?;
    }
    Ok(out)
}

#[derive(Default)]
struct Assembly {
    provider: String,
    classification: String,
    mission_id: Option<String>,
    plan_hash: Option<String>,
    fused_plan_digest: Option<String>,
    mission_materialized_once: bool,
    fence_first: Option<u64>,
    fence_second: Option<u64>,
    stale_refused: bool,
    attempt_first_id: Option<String>,
    attempt_second_id: Option<String>,
    planning: Option<receipt::PlanningReceipt>,
    candidate: Option<receipt::CandidateOut>,
    gate: Option<receipt::GateOut>,
    evidence: Option<receipt::EvidenceOut>,
    local_effect: Option<receipt::LocalEffectOut>,
    jeryu: Option<receipt::JeryuOut>,
    provider_usage: Vec<UsageRow>,
    step_failure: Option<String>,
}

impl Assembly {
    fn new(provider: &str) -> Self {
        Self {
            provider: provider.to_string(),
            classification: if provider == "sim" {
                "SYNTHETIC_INTEGRATION_SCAFFOLD".to_string()
            } else {
                "LIVE_DEMONSTRATION".to_string()
            },
            ..Self::default()
        }
    }

    fn absorb_council(&mut self, council: &synthetic_council::CouncilOutcome) {
        self.fused_plan_digest = Some(council.fused_digest.clone());
        let providers = council
            .planners
            .iter()
            .map(|planner| receipt::PlannerSummary {
                provider: planner.provider.clone(),
                label: planner.label.clone(),
                session: planner.session.clone(),
                ok: planner.plan.is_some(),
                failure: planner.failure.clone(),
            })
            .collect();
        self.planning = Some(receipt::PlanningReceipt {
            providers,
            fused_by: council.fused_by.clone(),
            mode: council.fused.mode.clone(),
            provenance: plan_types::provenance_counts(&council.fused),
            degraded: council.degraded,
            failures: council.failures.clone(),
        });
        for planner in &council.planners {
            self.provider_usage.push(UsageRow {
                provider: planner.provider.clone(),
                role: format!("planner-{}", planner.label),
                session: planner.session.clone(),
                cost_usd: planner.cost_usd,
                wall_ms: planner.wall_ms,
            });
        }
        self.provider_usage.push(UsageRow {
            provider: council.fused_by.clone(),
            role: "fusion".into(),
            session: council.fused_session.clone(),
            cost_usd: council.fused_cost_usd,
            wall_ms: council.fused_wall_ms,
        });
    }

    fn absorb_materialized(&mut self, materialized: &Materialized) {
        self.mission_id = Some(materialized.graph.mission.id.to_string());
        self.plan_hash = Some(materialized.plan_hash.clone());
        self.mission_materialized_once = materialized.once;
    }

    fn absorb_runner(&mut self, provider: &str, phase: &runner::RunnerPhase) {
        let outcome = &phase.outcome;
        self.fence_second = Some(outcome.fence);
        self.attempt_second_id = Some(outcome.attempt_id.to_string());
        self.candidate = Some(receipt::CandidateOut {
            id: outcome.candidate.id.clone(),
            base: outcome.candidate.base_commit.clone(),
            head: outcome.candidate.head_commit.clone(),
            tree: outcome.candidate.tree_hash.clone(),
            patch_digest: outcome.candidate.patch_hash.clone(),
            actual_scope: outcome.candidate.actual_scope.clone(),
        });
        self.gate = Some(receipt::GateOut {
            writer_outcome: if outcome.gate.passed() {
                "PASS"
            } else {
                "FAIL"
            }
            .to_string(),
            exit_code: outcome.gate.exit_code,
            repair_rounds: outcome.repair_rounds,
            command: outcome.gate.command.clone(),
        });
        self.provider_usage.push(UsageRow {
            provider: provider.to_string(),
            role: "runner".into(),
            session: phase.session.clone(),
            cost_usd: phase.cost_usd,
            wall_ms: phase.wall_ms,
        });
    }

    fn into_receipt(self) -> SyntheticIntegrationReceipt {
        let mut receipt = SyntheticIntegrationReceipt {
            classification: self.classification,
            transaction_gate_eligible: false,
            provider: self.provider,
            mission_id: self.mission_id,
            plan_hash: self.plan_hash,
            fused_plan_digest: self.fused_plan_digest,
            mission_materialized_once: self.mission_materialized_once,
            fence_first: self.fence_first,
            fence_second: self.fence_second,
            stale_refused: self.stale_refused,
            attempt_first_id: self.attempt_first_id,
            attempt_second_id: self.attempt_second_id,
            planning: self.planning,
            candidate: self.candidate,
            gate: self.gate,
            evidence: self.evidence,
            effect: EffectOut {
                local: self.local_effect,
                jeryu: self.jeryu,
            },
            provider_usage: self.provider_usage,
            scaffold_failures: vec![],
        };
        let mut failures = compute_scaffold_failures(&receipt);
        if let Some(step) = self.step_failure {
            failures.insert(0, format!("STEP_FAILED:{step}"));
        }
        receipt.scaffold_failures = failures;
        receipt
    }
}

fn finish(ledger: &SharedLedger, data_dir: &Path, assembly: Assembly) -> Result<(), String> {
    let receipt = assembly.into_receipt();
    let json =
        serde_json::to_string_pretty(&receipt).map_err(|err| format!("encode receipt: {err}"))?;
    let (file_name, event_kind) = if receipt.classification == "LIVE_DEMONSTRATION" {
        ("demo-live-receipts.json", "demo_live_receipt")
    } else {
        (
            "synthetic-integration-receipt.json",
            "synthetic_integration_receipt",
        )
    };
    let path = data_dir.join(file_name);
    std::fs::write(&path, &json).map_err(|err| format!("write receipts: {err}"))?;
    if let Ok(mut guard) = ledger.lock() {
        let _ = guard.append_event(event_kind, &json);
    }
    println!("{json}");
    println!("receipts: {}", path.display());
    if receipt.scaffold_failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}",
            receipt.classification,
            receipt.scaffold_failures.join(", ")
        ))
    }
}
