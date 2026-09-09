//! Shared behavioral conformance suite. Both the memory ledger and the
//! SQLite adapter must pass every check; tests in each crate call
//! `check_all` with a factory for a fresh ledger.

use crate::authority::ActiveLeaseSubject;
use crate::leases::LeaseService;
use crate::materializer::{materialize_plan, PlanInput};
use crate::records::{LeaseGrant, ReleaseRequest, StoredGraph};
use crate::store::Ledger;
use bullet_domain::{Attempt, AttemptId, AttemptState, Candidate, CommandPhase, Digest, TaskClass};
use chrono::{DateTime, Duration, Utc};

fn t(offset: i64) -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_770_000_000 + offset)
}

fn ts(offset: i64) -> String {
    LeaseService::rfc3339(t(offset))
}

fn setup<L: Ledger>(ledger: &mut L, seed: &str, packages: usize) -> Result<StoredGraph, String> {
    let input = PlanInput {
        title: format!("conformance {seed}"),
        objective: "shared ledger conformance".into(),
        packages: (0..packages)
            .map(|idx| (format!("pkg-{idx}"), TaskClass::BoundedBugFix))
            .collect(),
    };
    materialize_plan(ledger, seed, &input, &ts(0)).map_err(|err| format!("setup {seed}: {err}"))
}

fn acquire<L: Ledger>(
    ledger: &mut L,
    graph: &StoredGraph,
    index: usize,
    seed: &str,
    ttl: i64,
) -> Result<(Attempt, LeaseGrant), String> {
    LeaseService::acquire(ledger, graph, index, seed, ttl)
        .map(|(attempt, _token, grant)| (attempt, grant))
        .map_err(|err| format!("acquire {seed}: {err}"))
}

/// Run every conformance check, each against a fresh ledger from `make`.
///
/// # Errors
///
/// Returns the first failing check with context.
pub fn check_all<L: Ledger, F: FnMut() -> L>(mut make: F) -> Result<(), String> {
    single_writer(&mut make())?;
    fence_never_reused(&mut make())?;
    heartbeat_semantics(&mut make())?;
    active_lease_authority(&mut make())?;
    idempotent_replay(&mut make())?;
    command_conflict(&mut make())?;
    writer_linkage(&mut make())?;
    outbox_progression(&mut make())?;
    append_only_rows(&mut make())?;
    release_by_non_holder(&mut make())?;
    Ok(())
}

fn active_lease_authority<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-auth", 1)?;
    let (attempt, grant) = acquire(ledger, &graph, 0, "auth-a", 15)?;
    let subject = ActiveLeaseSubject::from_attempt(&attempt);
    ledger
        .check_active_lease(&subject)
        .map_err(|err| format!("active_lease_authority live: {err}"))?;

    let mut changed = Vec::new();
    let mut value = subject.clone();
    value.variant_id = bullet_domain::VariantId::from_seed("wrong-variant");
    changed.push(value);
    let mut value = subject.clone();
    value.attempt_id = AttemptId::from_seed("wrong-attempt");
    changed.push(value);
    let mut value = subject.clone();
    value.work_package_id = bullet_domain::WorkPackageId::from_seed("wrong-package");
    changed.push(value);
    let mut value = subject.clone();
    value.fence += 1;
    changed.push(value);
    let mut value = subject.clone();
    value.runner_id = bullet_domain::RunnerId::from_seed("wrong-runner");
    changed.push(value);
    let mut value = subject.clone();
    value.runner_epoch += 1;
    changed.push(value);
    let mut value = subject.clone();
    value.workspace_id = bullet_domain::WorkspaceId::from_seed("wrong-workspace");
    changed.push(value);
    let mut value = subject.clone();
    value.workspace_nonce[0] ^= 0xff;
    changed.push(value);
    let mut value = subject.clone();
    value.scope_revision += 1;
    changed.push(value);
    let mut value = subject.clone();
    value.context_revision += 1;
    changed.push(value);
    for changed_subject in changed {
        match ledger.check_active_lease(&changed_subject) {
            Err(err) if err.reason_code() == "STALE_AUTHORITY" => {}
            other => {
                return Err(format!(
                    "active_lease_authority: changed subject gave {other:?}"
                ));
            }
        }
    }

    LeaseService::release(ledger, &grant, AttemptState::Cancelled, true)
        .map_err(|err| format!("active_lease_authority release: {err}"))?;
    match ledger.check_active_lease(&subject) {
        Err(err) if err.reason_code() == "STALE_AUTHORITY" => {}
        other => {
            return Err(format!(
                "active_lease_authority: released subject gave {other:?}"
            ));
        }
    }
    let (successor, _grant) = acquire(ledger, &graph, 0, "auth-b", 15)?;
    if successor.fence != attempt.fence + 1 {
        return Err("active_lease_authority: successor did not advance fence".into());
    }
    ledger
        .check_active_lease(&ActiveLeaseSubject::from_attempt(&successor))
        .map_err(|err| format!("active_lease_authority successor: {err}"))?;

    Ok(())
}

fn single_writer<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-sw", 1)?;
    let (a1, _g1) = acquire(ledger, &graph, 0, "sw-a", 15)?;
    if a1.fence != 1 {
        return Err(format!("single_writer: first fence {} != 1", a1.fence));
    }
    if acquire(ledger, &graph, 0, "sw-b", 15).is_ok() {
        return Err("single_writer: second concurrent acquire succeeded".into());
    }
    let active = ledger
        .active_attempt(&graph.packages[0].id)
        .map_err(|err| format!("single_writer: {err}"))?
        .ok_or("single_writer: no active attempt after grant")?;
    if active.id != a1.id {
        return Err("single_writer: active attempt is not the grant holder".into());
    }
    Ok(())
}

fn fence_never_reused<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-fn", 1)?;
    let mut fences = Vec::new();
    for seed in ["fn-1", "fn-2", "fn-3"] {
        let (attempt, grant) = acquire(ledger, &graph, 0, seed, 15)?;
        fences.push(attempt.fence);
        LeaseService::release(ledger, &grant, AttemptState::Cancelled, true)
            .map_err(|err| format!("fence_never_reused release {seed}: {err}"))?;
    }
    if fences != vec![1, 2, 3] {
        return Err(format!("fence_never_reused: fences were {fences:?}"));
    }
    Ok(())
}

fn heartbeat_semantics<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-hb", 1)?;
    let (_a, grant) = acquire(ledger, &graph, 0, "hb-a", 15)?;
    ledger
        .heartbeat(&LeaseService::heartbeat_of(&grant))
        .map_err(|err| format!("heartbeat_semantics live: {err}"))?;
    let mut wrong = LeaseService::heartbeat_of(&grant);
    wrong.workspace_nonce = [0; 32];
    match ledger.heartbeat(&wrong) {
        Err(err) if err.reason_code() == "STALE_AUTHORITY" => {}
        other => {
            return Err(format!(
                "heartbeat_semantics: wrong nonce gave {other:?} instead of STALE_AUTHORITY"
            ))
        }
    }
    LeaseService::release(ledger, &grant, AttemptState::Cancelled, true)
        .map_err(|err| format!("heartbeat_semantics release: {err}"))?;
    match ledger.heartbeat(&LeaseService::heartbeat_of(&grant)) {
        Err(err) if err.reason_code() == "STALE_AUTHORITY" => Ok(()),
        other => Err(format!(
            "heartbeat_semantics: released lease heartbeat gave {other:?}"
        )),
    }
}

fn idempotent_replay<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-ir", 1)?;
    let first = LeaseService::request_for(&graph, 0, "ir-a", 15)
        .map_err(|err| format!("idempotent_replay: {err}"))?;
    let g1 = ledger
        .acquire_lease(&first)
        .map_err(|err| format!("idempotent_replay first: {err}"))?;
    let retry = LeaseService::request_for(&graph, 0, "ir-a", 15)
        .map_err(|err| format!("idempotent_replay: {err}"))?;
    let g2 = ledger
        .acquire_lease(&retry)
        .map_err(|err| format!("idempotent_replay retry: {err}"))?;
    if serde_json::to_vec(&g1).map_err(|err| err.to_string())?
        != serde_json::to_vec(&g2).map_err(|err| err.to_string())?
    {
        return Err("idempotent_replay: replay returned a different grant".into());
    }
    let lease = ledger
        .get_lease(&graph.variants[0].id)
        .map_err(|err| format!("idempotent_replay: {err}"))?
        .ok_or("idempotent_replay: lease vanished after replay")?;
    if lease.attempt_id != g1.attempt.id {
        return Err("idempotent_replay: replay changed the lease holder".into());
    }
    Ok(())
}

fn command_conflict<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-cc", 1)?;
    let a = crate::commands::CommandRequest::new("cc-key", "probe", &serde_json::json!({"a": 1}))
        .map_err(|err| format!("command_conflict: {err}"))?;
    ledger
        .record_command(&a)
        .map_err(|err| format!("command_conflict first: {err}"))?;
    let b = crate::commands::CommandRequest::new("cc-key", "probe", &serde_json::json!({"a": 2}))
        .map_err(|err| format!("command_conflict: {err}"))?;
    match ledger.record_command(&b) {
        Err(err) if err.reason_code() == "IDEMPOTENCY_CONFLICT" => {}
        other => return Err(format!("command_conflict: got {other:?}")),
    }
    let (_a1, _g1) = acquire(ledger, &graph, 0, "cc-a", 15)?;
    let mut forged = LeaseService::request_for(&graph, 0, "cc-a", 15)
        .map_err(|err| format!("command_conflict: {err}"))?;
    forged.runner_epoch = 99;
    match ledger.acquire_lease(&forged) {
        Err(err) if err.reason_code() == "IDEMPOTENCY_CONFLICT" => {}
        other => {
            return Err(format!(
                "command_conflict: same key different authority gave {other:?}"
            ))
        }
    }
    let mut changed_ttl = LeaseService::request_for(&graph, 0, "cc-a", 14)
        .map_err(|err| format!("command_conflict: {err}"))?;
    changed_ttl.runner_epoch = 1;
    match ledger.acquire_lease(&changed_ttl) {
        Err(err) if err.reason_code() == "IDEMPOTENCY_CONFLICT" => Ok(()),
        other => Err(format!(
            "command_conflict: same key different TTL gave {other:?}"
        )),
    }
}

fn writer_linkage<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-wl", 2)?;
    let (a1, _g1) = acquire(ledger, &graph, 0, "wl-a", 15)?;
    if ledger
        .active_attempt(&graph.packages[1].id)
        .map_err(|err| format!("writer_linkage: {err}"))?
        .is_some()
    {
        return Err("writer_linkage: writer on package A reported active on package B".into());
    }
    let (a2, _g2) = acquire(ledger, &graph, 1, "wl-b", 15)?;
    let on_a = ledger
        .active_attempt(&graph.packages[0].id)
        .map_err(|err| format!("writer_linkage: {err}"))?
        .ok_or("writer_linkage: package A lost its writer")?;
    let on_b = ledger
        .active_attempt(&graph.packages[1].id)
        .map_err(|err| format!("writer_linkage: {err}"))?
        .ok_or("writer_linkage: package B has no writer")?;
    if on_a.id != a1.id || on_b.id != a2.id {
        return Err("writer_linkage: writers attached to the wrong packages".into());
    }
    Ok(())
}

fn outbox_progression<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-ob", 1)?;
    let (_a, _g) = acquire(ledger, &graph, 0, "ob-a", 15)?;
    let pending = ledger
        .outbox_pending()
        .map_err(|err| format!("outbox_progression: {err}"))?;
    let dispatch = pending
        .iter()
        .find(|item| item.kind == "dispatch_attempt" && item.phase == CommandPhase::Pending)
        .ok_or("outbox_progression: no pending dispatch row after acquire")?;
    let seq = dispatch.seq;
    ledger
        .outbox_mark(seq, CommandPhase::Applied, &ts(1))
        .map_err(|err| format!("outbox_progression: {err}"))?;
    ledger
        .outbox_mark(seq, CommandPhase::Verified, &ts(2))
        .map_err(|err| format!("outbox_progression: {err}"))?;
    if ledger
        .outbox_pending()
        .map_err(|err| format!("outbox_progression: {err}"))?
        .iter()
        .any(|item| item.seq == seq)
    {
        return Err("outbox_progression: verified row still pending".into());
    }
    let all = ledger
        .outbox_all()
        .map_err(|err| format!("outbox_progression: {err}"))?;
    let row = all
        .iter()
        .find(|item| item.seq == seq)
        .ok_or("outbox_progression: row vanished")?;
    if row.phase != CommandPhase::Verified || row.acked_at.is_none() {
        return Err("outbox_progression: verified row missing phase or ack".into());
    }
    Ok(())
}

fn append_only_rows<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let attempt_id = AttemptId::from_seed("ao-attempt");
    let candidate = Candidate {
        id: bullet_domain::CandidateId::from_seed("ao-candidate"),
        attempt_id,
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        tree_sha: "c".repeat(40),
        patch_digest: Digest::of(b"ao"),
    };
    let created = ledger
        .put_candidate(&candidate)
        .map_err(|err| format!("append_only_rows: {err}"))?;
    let replayed = ledger
        .put_candidate(&candidate)
        .map_err(|err| format!("append_only_rows replay: {err}"))?;
    if !created || replayed {
        return Err("append_only_rows: created/replayed flags wrong".into());
    }
    let mut rewritten = candidate.clone();
    rewritten.head_sha = "d".repeat(40);
    match ledger.put_candidate(&rewritten) {
        Err(err) if err.reason_code() == "GRAPH_CONFLICT" => {}
        other => return Err(format!("append_only_rows: rewrite gave {other:?}")),
    }
    let effect = bullet_domain::Effect {
        id: bullet_domain::EffectId::from_seed("ao-effect"),
        attempt_id: AttemptId::from_seed("ao-attempt"),
        logical_key: "scm:push:ao".into(),
        desired: "ref-exists".into(),
        outcome: "unknown".into(),
    };
    ledger
        .put_effect(&effect)
        .map_err(|err| format!("append_only_rows effect: {err}"))?;
    let mut blind_replay = effect.clone();
    blind_replay.outcome = "verified".into();
    match ledger.put_effect(&blind_replay) {
        Err(err) if err.reason_code() == "GRAPH_CONFLICT" => Ok(()),
        other => Err(format!(
            "append_only_rows: ambiguous effect blind replay gave {other:?}"
        )),
    }
}

fn release_by_non_holder<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let graph = setup(ledger, "conf-rl", 1)?;
    let (_a1, g1) = acquire(ledger, &graph, 0, "rl-a", 15)?;
    let forged = ReleaseRequest {
        variant_id: g1.lease.variant_id.clone(),
        attempt_id: AttemptId::from_seed("rl-forged"),
        final_state: AttemptState::Cancelled,
        requeue: true,
    };
    match ledger.release_lease(&forged) {
        Err(err) if err.reason_code() == "STALE_AUTHORITY" => {}
        other => return Err(format!("release_by_non_holder: got {other:?}")),
    }
    if ledger
        .get_lease(&g1.lease.variant_id)
        .map_err(|err| format!("release_by_non_holder: {err}"))?
        .is_none()
    {
        return Err("release_by_non_holder: forged release removed the lease".into());
    }
    Ok(())
}
