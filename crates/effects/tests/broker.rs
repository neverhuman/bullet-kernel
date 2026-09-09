//! Broker flow against a real bare repository: commit path, idempotent
//! replay, precondition conflicts, namespace denial, and fence staleness.

mod support;

use bullet_application::{EffectState, Ledger};
use bullet_domain::{AttemptState, CommandPhase};
use bullet_effects_core::{
    authorize, dispatch, propose, EffectsError, ForgeEffects, LocalBareForge, ReceiptVerdict,
};
use support::{authority, intent_input, now, repos, sh};

#[test]
fn full_flow_commits_with_read_back_receipt_and_settled_outbox() {
    let repos = repos();
    let mut auth = authority("br-full");
    let mut forge = LocalBareForge::init(&repos.bare).expect("bare");
    let input = intent_input(&auth.token, &repos, "full");
    let (row, created) = propose(&mut auth.ledger, &input, &now()).expect("propose");
    assert!(created);
    assert_eq!(row.state, EffectState::Proposed);
    let (_row, seq) = authorize(&mut auth.ledger, &row.id, &auth.token, &now()).expect("authorize");
    let state = dispatch(
        &mut auth.ledger,
        &mut forge,
        &row.id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("dispatch");
    assert_eq!(state, EffectState::Committed);
    // The remote ref really points at the pushed OID.
    assert_eq!(
        forge.read_ref(&input.target_ref).expect("read"),
        Some(repos.head.clone())
    );
    // The receipt records the read-back, not the push answer.
    let receipts = auth.ledger.effect_receipts(&row.id).expect("receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].verification_result, ReceiptVerdict::Match);
    assert_eq!(
        receipts[0].observed_state_hash.as_deref(),
        Some(repos.head.as_str())
    );
    assert!(!receipts[0].adopted_after_unknown);
    // The outbox row settled to verified.
    let outbox = auth.ledger.outbox_all().expect("outbox");
    let item = outbox.iter().find(|item| item.seq == seq).expect("row");
    assert_eq!(item.kind, "effect_dispatch");
    assert_eq!(item.phase, CommandPhase::Verified);
    // Replaying the proposal returns the stored (now committed) row.
    let (replay, replay_created) = propose(&mut auth.ledger, &input, &now()).expect("replay");
    assert!(!replay_created);
    assert_eq!(replay.id, row.id);
    assert_eq!(replay.state, EffectState::Committed);
    // A second dispatch of the settled intent is a typed refusal.
    let err = dispatch(
        &mut auth.ledger,
        &mut forge,
        &row.id,
        &repos.workspace,
        None,
        &now(),
    )
    .expect_err("settled");
    assert_eq!(err.reason_code(), "ILLEGAL_EFFECT_PHASE");
}

#[test]
fn divergent_payload_under_same_key_is_typed_conflict() {
    let repos = repos();
    let mut auth = authority("br-div");
    let input = intent_input(&auth.token, &repos, "div");
    propose(&mut auth.ledger, &input, &now()).expect("first");
    let mut divergent = input.clone();
    divergent.new_oid = repos.base.clone();
    let err = propose(&mut auth.ledger, &divergent, &now()).expect_err("divergent");
    assert_eq!(err.reason_code(), "IDEMPOTENCY_CONFLICT");
}

#[test]
fn moved_ref_fails_the_lease_and_quarantines() {
    let repos = repos();
    let mut auth = authority("br-moved");
    let mut forge = LocalBareForge::init(&repos.bare).expect("bare");
    let input = intent_input(&auth.token, &repos, "moved");
    // Another writer creates the ref first, so the create precondition
    // (`ZERO_OID`, ref must not exist) no longer holds.
    sh(
        &repos.workspace,
        &format!(
            "git push -q {} {}:{}",
            repos.bare.display(),
            repos.base,
            input.target_ref
        ),
    );
    let (row, _) = propose(&mut auth.ledger, &input, &now()).expect("propose");
    let (_row, seq) = authorize(&mut auth.ledger, &row.id, &auth.token, &now()).expect("authorize");
    let state = dispatch(
        &mut auth.ledger,
        &mut forge,
        &row.id,
        &repos.workspace,
        Some(seq),
        &now(),
    )
    .expect("dispatch settles into quarantine");
    assert_eq!(state, EffectState::Quarantined);
    // The other writer's value is untouched.
    assert_eq!(
        forge.read_ref(&input.target_ref).expect("read"),
        Some(repos.base.clone())
    );
    let receipts = auth.ledger.effect_receipts(&row.id).expect("receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].verification_result, ReceiptVerdict::Mismatch);
    let outbox = auth.ledger.outbox_all().expect("outbox");
    let item = outbox.iter().find(|item| item.seq == seq).expect("row");
    assert_eq!(item.phase, CommandPhase::Unknown);
}

#[test]
fn refs_outside_candidate_namespace_are_denied_before_any_row() {
    let repos = repos();
    let mut auth = authority("br-ns");
    for denied in ["refs/heads/main", "HEAD", "refs/tags/v1"] {
        let mut input = intent_input(&auth.token, &repos, "ns");
        input.target_ref = denied.into();
        let err = propose(&mut auth.ledger, &input, &now()).expect_err(denied);
        assert_eq!(err.reason_code(), "REF_DENIED", "{denied}");
    }
    assert!(auth
        .ledger
        .get_effect_intent("local-bare", "push:ns")
        .expect("get")
        .is_none());
}

#[test]
fn superseded_fence_cannot_authorize() {
    let repos = repos();
    let mut auth = authority("br-fence");
    let input = intent_input(&auth.token, &repos, "fence");
    let (row, _) = propose(&mut auth.ledger, &input, &now()).expect("propose");
    // The writer is superseded and a successor takes the lease at fence 2.
    bullet_application::LeaseService::release(
        &mut auth.ledger,
        &auth.grant,
        AttemptState::Superseded,
        true,
    )
    .expect("release");
    bullet_application::LeaseService::acquire(&mut auth.ledger, &auth.graph, 0, "br-fence-a2", 15)
        .expect("successor");
    let err = authorize(&mut auth.ledger, &row.id, &auth.token, &now()).expect_err("stale");
    assert_eq!(err.reason_code(), "STALE_AUTHORITY");
    let stored = auth
        .ledger
        .get_effect_intent_by_id(&row.id)
        .expect("get")
        .expect("row");
    assert_eq!(stored.state, EffectState::Proposed);
}

#[test]
fn unknown_intent_id_is_a_typed_store_failure() {
    let mut auth = authority("br-none");
    let err = authorize(
        &mut auth.ledger,
        &bullet_domain::EffectId::from_seed("br-nothing"),
        &auth.token,
        &now(),
    )
    .expect_err("unknown");
    assert_eq!(err.reason_code(), "STORE_FAILURE");
    let _: &EffectsError = &err;
}
