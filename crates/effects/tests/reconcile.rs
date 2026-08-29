//! Lost responses land in OUTCOME_UNKNOWN, and reconcile is the only exit:
//! adopt what happened, retry exactly once on proven non-execution, and
//! quarantine contradictions. Blind retry is refused by construction.

mod support;

use bullet_application::{EffectState, Ledger};
use bullet_domain::CommandPhase;
use bullet_effects_core::{
    authorize, dispatch, propose, reconcile, ForgeEffects, LocalBareForge, LossMode,
    LostResponseForge, ReconcileOutcome,
};
use support::{authority, intent_input, now, repos, sh, Repos};

type Setup = (
    support::Authority,
    LostResponseForge<LocalBareForge>,
    bullet_domain::EffectId,
    u64,
);

/// Propose + authorize one create-intent and return the armed pieces.
fn setup(seed: &str, repos: &Repos, suffix: &str) -> Setup {
    let mut auth = authority(seed);
    let forge = LostResponseForge::new(LocalBareForge::init(&repos.bare).expect("bare"));
    let input = intent_input(&auth.token, repos, suffix);
    let (row, _) = propose(&mut auth.ledger, &input, &now()).expect("propose");
    let (_row, seq) = authorize(&mut auth.ledger, &row.id, &auth.token, &now()).expect("authorize");
    (auth, forge, row.id, seq)
}

#[test]
fn lost_response_after_push_is_unknown_then_adopted() {
    let repos = repos();
    let (mut auth, mut forge, id, seq) = setup("rc-adopt", &repos, "adopt");
    forge.lose_next(LossMode::AfterPush);
    let state = dispatch(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("dispatch");
    assert_eq!(state, EffectState::OutcomeUnknown);
    let outbox = auth.ledger.outbox_all().expect("outbox");
    assert_eq!(
        outbox
            .iter()
            .find(|item| item.seq == seq)
            .expect("row")
            .phase,
        CommandPhase::Unknown
    );
    // The push actually landed; reconcile must adopt, not re-push.
    let outcome = reconcile(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("reconcile");
    assert_eq!(outcome, ReconcileOutcome::Adopted);
    let stored = auth
        .ledger
        .get_effect_intent_by_id(&id)
        .expect("get")
        .expect("row");
    assert_eq!(stored.state, EffectState::Committed);
    assert_eq!(stored.unknown_retries, 0, "adoption consumed no retry");
    let receipts = auth.ledger.effect_receipts(&id).expect("receipts");
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].adopted_after_unknown);
    assert_eq!(
        auth.ledger
            .outbox_all()
            .expect("outbox")
            .iter()
            .find(|item| item.seq == seq)
            .expect("row")
            .phase,
        CommandPhase::Verified
    );
    let inner = forge.into_inner().expect("settled forge handoff");
    assert_eq!(inner.bare_path(), repos.bare);
}

#[test]
fn proven_non_execution_permits_exactly_one_retry() {
    let repos = repos();
    let (mut auth, mut forge, id, seq) = setup("rc-retry", &repos, "retry");
    forge.lose_next(LossMode::BeforePush);
    let state = dispatch(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("dispatch");
    assert_eq!(state, EffectState::OutcomeUnknown);
    assert_eq!(
        forge
            .read_ref("refs/heads/bullet/candidate/retry")
            .expect("read"),
        None
    );
    let outcome = reconcile(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("reconcile");
    assert_eq!(outcome, ReconcileOutcome::Retried(EffectState::Committed));
    let stored = auth
        .ledger
        .get_effect_intent_by_id(&id)
        .expect("get")
        .expect("row");
    assert_eq!(stored.state, EffectState::Committed);
    assert_eq!(stored.unknown_retries, 1);
    assert_eq!(
        forge
            .read_ref("refs/heads/bullet/candidate/retry")
            .expect("read"),
        Some(repos.head.clone())
    );
}

#[test]
fn second_unknown_exhausts_the_retry_budget_into_quarantine() {
    let repos = repos();
    let (mut auth, mut forge, id, seq) = setup("rc-budget", &repos, "budget");
    forge.lose_next(LossMode::BeforePush);
    dispatch(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("dispatch");
    // The single permitted retry also loses its response before pushing.
    forge.lose_next(LossMode::BeforePush);
    let outcome = reconcile(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("first reconcile");
    assert_eq!(
        outcome,
        ReconcileOutcome::Retried(EffectState::OutcomeUnknown)
    );
    // Non-execution is proven again, but the budget is spent: quarantine.
    let second = reconcile(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("second reconcile");
    assert_eq!(second, ReconcileOutcome::Quarantined);
    let stored = auth
        .ledger
        .get_effect_intent_by_id(&id)
        .expect("get")
        .expect("row");
    assert_eq!(stored.state, EffectState::Quarantined);
    assert_eq!(stored.unknown_retries, 1);
}

#[test]
fn remote_moved_while_unknown_is_quarantined_not_retried() {
    let repos = repos();
    let (mut auth, mut forge, id, seq) = setup("rc-moved", &repos, "moved");
    forge.lose_next(LossMode::BeforePush);
    dispatch(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("dispatch");
    // While the outcome is unknown, another writer creates the ref with a
    // different OID: neither desired nor the expected precondition.
    sh(
        &repos.workspace,
        &format!(
            "git push -q {} {}:refs/heads/bullet/candidate/moved",
            repos.bare.display(),
            repos.base
        ),
    );
    let outcome = reconcile(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("reconcile");
    assert_eq!(outcome, ReconcileOutcome::Quarantined);
    let stored = auth
        .ledger
        .get_effect_intent_by_id(&id)
        .expect("get")
        .expect("row");
    assert_eq!(stored.state, EffectState::Quarantined);
    // The foreign value stays untouched.
    assert_eq!(
        forge
            .read_ref("refs/heads/bullet/candidate/moved")
            .expect("read"),
        Some(repos.base.clone())
    );
    // Unresolved listing no longer carries the quarantined intent.
    assert!(auth
        .ledger
        .unresolved_effects()
        .expect("unresolved")
        .is_empty());
}

#[test]
fn dispatch_on_unknown_is_refused_as_retry_without_reconcile() {
    let repos = repos();
    let (mut auth, mut forge, id, seq) = setup("rc-blind", &repos, "blind");
    forge.lose_next(LossMode::BeforePush);
    dispatch(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("dispatch");
    let err = dispatch(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect_err("blind retry");
    assert_eq!(err.reason_code(), "RETRY_WITHOUT_RECONCILE");
    // The intent is listed as unresolved until reconciled.
    let unresolved = auth.ledger.unresolved_effects().expect("unresolved");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, id);
}

#[test]
fn reconcile_outside_unknown_is_a_typed_phase_refusal() {
    let repos = repos();
    let (mut auth, mut forge, id, seq) = setup("rc-phase", &repos, "phase");
    let err = reconcile(
        &mut auth.ledger,
        &mut forge,
        &id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect_err("authorized is not unknown");
    assert_eq!(err.reason_code(), "ILLEGAL_EFFECT_PHASE");
    forge.lose_next(LossMode::AfterPush);
    assert_eq!(
        forge
            .into_inner()
            .expect_err("armed loss cannot be discarded")
            .reason_code(),
        "DURABLE_QUEUE_INVALID"
    );
}
