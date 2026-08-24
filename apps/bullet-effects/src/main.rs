//! Effect broker process: drives one real LocalBareForge flow end to end —
//! commit with read-back receipt, idempotent replay, and the lost-response
//! path through OUTCOME_UNKNOWN into a reconciled retry. Prints a JSON
//! summary derived from ledger rows and exits nonzero on any dishonesty.

use bullet_application::{
    materialize_plan, EffectState, LeaseService, Ledger, MemoryLedger, PlanInput,
};
use bullet_domain::{AuthorityToken, TaskClass};
use bullet_effects_core::{
    authorize, dispatch, propose, reconcile, EffectsError, ForgeEffects, IntentInput,
    LocalBareForge, LossMode, LostResponseForge, ReconcileOutcome, ZERO_OID,
};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fail(context: &str, detail: &str) -> ! {
    eprintln!(
        "{}",
        serde_json::json!({ "error": context, "detail": detail })
    );
    std::process::exit(1);
}

fn sh(dir: &Path, script: &str) {
    let out = Command::new("sh")
        .arg("-ec")
        .arg(script)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| fail("spawn fixture shell", &err.to_string()));
    if !out.status.success() {
        fail("fixture script", &String::from_utf8_lossy(&out.stderr));
    }
}

fn workspace_repo(root: &Path) -> (PathBuf, String) {
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace)
        .unwrap_or_else(|err| fail("create workspace", &err.to_string()));
    sh(
        &workspace,
        "git init -q -b main . && \
         git config user.name bullet && git config user.email bullet@test && \
         echo demo > f && git add . && git commit -qm demo",
    );
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&workspace)
        .output()
        .unwrap_or_else(|err| fail("rev-parse", &err.to_string()));
    let head = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (workspace, head)
}

fn leased_authority(ledger: &mut MemoryLedger) -> AuthorityToken {
    let now = LeaseService::rfc3339(Utc::now());
    let graph = materialize_plan(
        ledger,
        "effects-demo",
        &PlanInput {
            title: "effect broker demo".into(),
            objective: "verified external mutation with honest unknowns".into(),
            packages: vec![("demo".into(), TaskClass::BoundedBugFix)],
        },
        &now,
    )
    .unwrap_or_else(|err| fail("materialize", &err.to_string()));
    let (_attempt, token, _grant) =
        LeaseService::acquire(ledger, &graph, 0, "effects-demo-a1", Utc::now(), 300)
            .unwrap_or_else(|err| fail("acquire lease", &err.to_string()));
    token
}

fn input(token: &AuthorityToken, head: &str, suffix: &str) -> IntentInput {
    IntentInput {
        provider: "local-bare".into(),
        logical_effect_key: format!("push:demo:{suffix}"),
        target_ref: format!("refs/heads/bullet/candidate/{suffix}"),
        new_oid: head.into(),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: token.attempt_id.clone(),
        fence: token.attempt_fence,
        policy_version: "policy-v1".into(),
        provider_idempotency_key: None,
    }
}

fn or_die<T>(result: Result<T, EffectsError>, context: &str) -> T {
    result.unwrap_or_else(|err| fail(context, &format!("{} ({})", err, err.reason_code())))
}

struct LostFlow {
    unknown: EffectState,
    outcome: ReconcileOutcome,
    settled: EffectState,
}

/// Drive the lost-response path: unknown, then reconcile retries once.
fn lost_response_flow(
    ledger: &mut MemoryLedger,
    token: &AuthorityToken,
    forge: LocalBareForge,
    workspace: &Path,
    head: &str,
) -> LostFlow {
    let now = || LeaseService::rfc3339(Utc::now());
    let mut lossy = LostResponseForge::new(forge);
    let second_input = input(token, head, "demo-lost");
    let (row2, _) = or_die(propose(ledger, &second_input, &now()), "propose lost");
    let (_r2, seq2) = or_die(authorize(ledger, &row2.id, token, &now()), "authorize lost");
    lossy.lose_next(LossMode::BeforePush);
    let unknown = or_die(
        dispatch(ledger, &mut lossy, &row2.id, workspace, Some(seq2), &now()),
        "dispatch lost",
    );
    let outcome = or_die(
        reconcile(ledger, &mut lossy, &row2.id, workspace, Some(seq2), &now()),
        "reconcile",
    );
    let settled = ledger
        .get_effect_intent_by_id(&row2.id)
        .ok()
        .flatten()
        .map(|record| record.state)
        .unwrap_or_else(|| fail("load settled intent", "row missing"));
    LostFlow {
        unknown,
        outcome,
        settled,
    }
}

fn main() {
    let scratch = tempfile::tempdir().unwrap_or_else(|err| fail("tempdir", &err.to_string()));
    let (workspace, head) = workspace_repo(scratch.path());
    let mut ledger = MemoryLedger::new();
    let token = leased_authority(&mut ledger);
    let now = || LeaseService::rfc3339(Utc::now());

    // Commit path with independent read-back.
    let mut forge = LocalBareForge::init(&scratch.path().join("target.git"))
        .unwrap_or_else(|err| fail("init bare", &err.to_string()));
    let first_input = input(&token, &head, "demo");
    let (row, created) = or_die(propose(&mut ledger, &first_input, &now()), "propose");
    let (_r, seq) = or_die(authorize(&mut ledger, &row.id, &token, &now()), "authorize");
    let first = or_die(
        dispatch(
            &mut ledger,
            &mut forge,
            &row.id,
            &workspace,
            Some(seq),
            &now(),
        ),
        "dispatch",
    );
    let read_back = or_die(forge.read_ref(&first_input.target_ref), "read back");
    let (_replay, replay_created) =
        or_die(propose(&mut ledger, &first_input, &now()), "replay propose");

    let lost = lost_response_flow(&mut ledger, &token, forge, &workspace, &head);
    let summary = serde_json::json!({
        "first": first.as_str(),
        "created": created,
        "replay_created": replay_created,
        "read_back_matches": read_back.as_deref() == Some(head.as_str()),
        "after_lost_response": lost.unknown.as_str(),
        "reconcile": format!("{:?}", lost.outcome),
        "lost_intent_settled": lost.settled.as_str(),
    });
    println!("{summary}");
    let honest = first == EffectState::Committed
        && created
        && !replay_created
        && read_back.as_deref() == Some(head.as_str())
        && lost.unknown == EffectState::OutcomeUnknown
        && lost.outcome == ReconcileOutcome::Retried(EffectState::Committed)
        && lost.settled == EffectState::Committed;
    if !honest {
        std::process::exit(1);
    }
}
