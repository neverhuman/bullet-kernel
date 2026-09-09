//! Simulator-only integration scaffolding. It exercises several component
//! boundaries in-process but cannot produce a five-plane transaction receipt.

mod assembly;
mod effect;
mod fixture;
mod plan_types;
mod receipt;
mod runner;
mod synthetic_adapter;
mod synthetic_council;
mod turns;
mod verify;

use assembly::Assembly;
use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, HeartbeatRequest, LeaseService, Ledger, PlanInput, StoredGraph,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, Candidate, CandidateId, Digest, Evidence, EvidenceId, GateId,
    TaskClass,
};
use bullet_runner_core::REPOSITORY_GATE_ID;
use bullet_verifier_core::VerifierRequest;
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) type SharedLedger = Arc<Mutex<SqliteLedger>>;

fn lock(ledger: &SharedLedger) -> Result<MutexGuard<'_, SqliteLedger>, String> {
    ledger
        .lock()
        .map_err(|_| "ledger mutex poisoned".to_string())
}

/// Run the synthetic integration scaffold and emit a non-gating receipt.
pub fn run(target: Option<PathBuf>, data_dir: PathBuf) -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|err| format!("tokio runtime: {err}"))?;
    runtime.block_on(run_async(target, data_dir))
}

async fn run_async(target: Option<PathBuf>, data_dir: PathBuf) -> Result<(), String> {
    std::fs::create_dir_all(&data_dir).map_err(|err| format!("create data dir: {err}"))?;
    let ledger: SharedLedger = Arc::new(Mutex::new(
        SqliteLedger::open(data_dir.join("ledger.sqlite"))
            .map_err(|err| format!("open ledger: {err}"))?,
    ));
    let fixture = fixture::prepare(&data_dir, target)?;
    let mut assembly = Assembly::new();
    if let Err(failure) = drive(&ledger, &fixture, &data_dir, &mut assembly).await {
        assembly.step_failure = Some(failure);
    }
    assembly::finish(&ledger, &data_dir, assembly)
}

async fn drive(
    ledger: &SharedLedger,
    fixture: &fixture::Fixture,
    data_dir: &Path,
    assembly: &mut Assembly,
) -> Result<(), String> {
    let council = synthetic_council::run_council(ledger)?;
    assembly.absorb_council(&council);
    let materialized = materialize(ledger, &council)?;
    assembly.absorb_materialized(&materialized);
    let first = first_incarnation(ledger, &materialized.graph)?;
    assembly.fence_first = Some(first.fence);
    assembly.attempt_first_id = Some(first.attempt.id.to_string());
    let phase = runner::run_phase(ledger, &materialized.graph, fixture, data_dir).await?;
    assembly.absorb_runner(&phase);
    record_runner_journal(ledger, &phase)?;
    persist_candidate(ledger, &phase)?;
    assembly.stale_refused = stale_refused(
        ledger,
        &materialized.graph,
        &first.attempt,
        &phase.outcome.attempt_id,
    )?;
    assembly.evidence = Some(verify_candidate(ledger, &phase).await?);
    assembly.local_effect = Some(effect::deliver_local(
        ledger,
        &materialized.graph,
        &phase.outcome.candidate.id,
        &phase.outcome.candidate.head_commit,
        &phase.workspace_repo,
        data_dir,
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
    ledger: &SharedLedger,
    council: &synthetic_council::CouncilOutcome,
) -> Result<Materialized, String> {
    let seed = format!(
        "demo-synthetic:{}",
        &council.fused_digest[..16.min(council.fused_digest.len())]
    );
    let input = PlanInput {
        title: "synthetic integration: PONG component exercise".into(),
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
        LeaseService::acquire(store, graph, 0, "demo-synthetic-first", 15)
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
        .heartbeat(&LeaseService::heartbeat_of(&grant))
        .map_err(|err| format!("FIRST_HEARTBEAT:{}: {err}", err.reason_code()))?;
    LeaseService::release(store, &grant, AttemptState::Superseded, true)
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
    let heartbeat = HeartbeatRequest {
        variant_id: first.variant_id.clone(),
        attempt_id: first.id.clone(),
        fence: first.fence,
        runner_id: first.runner_id.clone(),
        runner_epoch: first.runner_epoch,
        workspace_nonce: first.workspace_nonce,
        ttl_seconds: 15,
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
    let token_refused = LeaseService::authorize_patch_application(&stale_token, &live).is_err();
    let refused = heartbeat_refused && token_refused;
    if refused {
        let _ = store.append_event("stale_refused", first.id.as_str());
    }
    Ok(refused)
}

async fn verify_candidate(
    ledger: &SharedLedger,
    phase: &runner::RunnerPhase,
) -> Result<receipt::EvidenceOut, String> {
    let candidate = &phase.outcome.candidate;
    let request = VerifierRequest {
        workspace_repo_path: phase.workspace_repo.display().to_string(),
        base_sha: candidate.base_commit.clone(),
        head_sha: candidate.head_commit.clone(),
        tree_sha: candidate.tree_hash.clone(),
        gate_id: GateId::parse(REPOSITORY_GATE_ID)
            .map_err(|err| format!("VERIFIER_GATE_ID: {err}"))?,
        author_attempt_id: phase.outcome.attempt_id.to_string(),
    };
    let record = verify::run_verifier(&request).await?;
    let out = receipt::EvidenceOut {
        verifier_outcome: record.outcome.as_str().to_string(),
        tier: record.tier.as_str().to_string(),
        gate: record.gate_id.to_string(),
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
