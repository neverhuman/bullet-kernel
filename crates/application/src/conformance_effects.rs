//! Shared effect-persistence conformance. Both the memory ledger and the
//! SQLite adapter must pass every check; each ledger crate's tests call
//! [`check_effects`] with a factory for a fresh ledger.

use crate::effect_state::EffectState;
use crate::effects::{
    receipt_id, EffectIntentRecord, EffectReceiptRecord, ReceiptVerdict, ZERO_OID,
};
use crate::store::Ledger;
use bullet_domain::{AttemptId, EffectId};

fn intent(seed: &str) -> EffectIntentRecord {
    EffectIntentRecord {
        id: EffectId::from_seed(seed),
        logical_effect_key: format!("push:{seed}:refs/heads/bullet/candidate/{seed}"),
        provider: "local-bare".into(),
        target_identity: format!("refs/heads/bullet/candidate/{seed}"),
        desired_state_hash: "b".repeat(40),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: AttemptId::from_seed("ce-attempt"),
        fence: 1,
        policy_version: "policy-v1".into(),
        payload_hash: String::new(),
        provider_idempotency_key: None,
        state: EffectState::Proposed,
        unknown_retries: 0,
        created_at: "2026-08-24T00:00:00Z".into(),
    }
}

fn receipt(intent_id: &EffectId, seed: &str) -> EffectReceiptRecord {
    EffectReceiptRecord {
        id: receipt_id(seed),
        effect_intent_id: intent_id.clone(),
        observed_remote_identity: "refs/heads/bullet/candidate/x".into(),
        observed_state_hash: Some("b".repeat(40)),
        verification_method: "git-ls-remote-read-back".into(),
        verification_result: ReceiptVerdict::Match,
        adopted_after_unknown: false,
        recorded_at: "2026-08-24T00:00:01Z".into(),
    }
}

/// Run every effect conformance check, each against a fresh ledger.
///
/// # Errors
///
/// Returns the first failing check with context.
pub fn check_effects<L: Ledger, F: FnMut() -> L>(mut make: F) -> Result<(), String> {
    intent_replay_and_conflict(&mut make())?;
    intent_requires_proposed(&mut make())?;
    legal_edges_only(&mut make())?;
    retry_counter_on_reconcile_edge(&mut make())?;
    receipts_append_only(&mut make())?;
    unresolved_listing(&mut make())?;
    Ok(())
}

fn intent_replay_and_conflict<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let first = intent("ce-ir");
    let (stored, created) = ledger
        .record_effect_intent(&first)
        .map_err(|err| format!("intent_replay first: {err}"))?;
    if !created || stored.id != first.id || stored.state != EffectState::Proposed {
        return Err("intent_replay: first insert wrong".into());
    }
    let mut replay = intent("ce-ir");
    replay.created_at = "2026-08-24T09:00:00Z".into();
    let (again, created_again) = ledger
        .record_effect_intent(&replay)
        .map_err(|err| format!("intent_replay replay: {err}"))?;
    if created_again || again.id != first.id || again.created_at != stored.created_at {
        return Err("intent_replay: replay did not return the stored row".into());
    }
    let mut divergent = intent("ce-ir");
    divergent.desired_state_hash = "c".repeat(40);
    match ledger.record_effect_intent(&divergent) {
        Err(err) if err.reason_code() == "IDEMPOTENCY_CONFLICT" => {}
        other => return Err(format!("intent_replay: divergent replay gave {other:?}")),
    }
    let by_key = ledger
        .get_effect_intent(&first.provider, &first.logical_effect_key)
        .map_err(|err| format!("intent_replay get: {err}"))?
        .ok_or("intent_replay: key lookup empty")?;
    if by_key.id != first.id {
        return Err("intent_replay: key lookup returned another row".into());
    }
    Ok(())
}

fn intent_requires_proposed<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let mut early = intent("ce-rp");
    early.state = EffectState::Authorized;
    match ledger.record_effect_intent(&early) {
        Err(err) if err.reason_code() == "GRAPH_CONFLICT" => Ok(()),
        other => Err(format!("intent_requires_proposed: got {other:?}")),
    }
}

fn legal_edges_only<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let (row, _) = ledger
        .record_effect_intent(&intent("ce-le"))
        .map_err(|err| format!("legal_edges: {err}"))?;
    match ledger.transition_effect(&row.id, EffectState::Dispatching) {
        Err(err) if err.reason_code() == "INVALID_TRANSITION" => {}
        other => return Err(format!("legal_edges: PROPOSED->DISPATCHING gave {other:?}")),
    }
    for to in [
        EffectState::Authorized,
        EffectState::Dispatching,
        EffectState::ReceiptPending,
        EffectState::Verified,
        EffectState::Committed,
    ] {
        let updated = ledger
            .transition_effect(&row.id, to)
            .map_err(|err| format!("legal_edges {}: {err}", to.as_str()))?;
        if updated.state != to {
            return Err(format!("legal_edges: state not {}", to.as_str()));
        }
    }
    match ledger.transition_effect(&row.id, EffectState::Dispatching) {
        Err(err) if err.reason_code() == "INVALID_TRANSITION" => {}
        other => {
            return Err(format!(
                "legal_edges: COMMITTED->DISPATCHING gave {other:?}"
            ))
        }
    }
    match ledger.transition_effect(&EffectId::from_seed("ce-none"), EffectState::Authorized) {
        Err(err) if err.reason_code() == "STORE_FAILURE" => Ok(()),
        other => Err(format!("legal_edges: unknown id gave {other:?}")),
    }
}

fn retry_counter_on_reconcile_edge<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let (row, _) = ledger
        .record_effect_intent(&intent("ce-rc"))
        .map_err(|err| format!("retry_counter: {err}"))?;
    for to in [
        EffectState::Authorized,
        EffectState::Dispatching,
        EffectState::OutcomeUnknown,
    ] {
        ledger
            .transition_effect(&row.id, to)
            .map_err(|err| format!("retry_counter {}: {err}", to.as_str()))?;
    }
    let retried = ledger
        .transition_effect(&row.id, EffectState::Dispatching)
        .map_err(|err| format!("retry_counter retry: {err}"))?;
    if retried.unknown_retries != 1 {
        return Err(format!(
            "retry_counter: unknown_retries {} != 1",
            retried.unknown_retries
        ));
    }
    let stored = ledger
        .get_effect_intent_by_id(&row.id)
        .map_err(|err| format!("retry_counter get: {err}"))?
        .ok_or("retry_counter: row vanished")?;
    if stored.unknown_retries != 1 || stored.state != EffectState::Dispatching {
        return Err("retry_counter: durable row does not carry the retry".into());
    }
    Ok(())
}

fn receipts_append_only<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let (row, _) = ledger
        .record_effect_intent(&intent("ce-ra"))
        .map_err(|err| format!("receipts: {err}"))?;
    let first = receipt(&row.id, "ce-ra-r1");
    let created = ledger
        .record_effect_receipt(&first)
        .map_err(|err| format!("receipts first: {err}"))?;
    let replayed = ledger
        .record_effect_receipt(&first)
        .map_err(|err| format!("receipts replay: {err}"))?;
    if !created || replayed {
        return Err("receipts: created/replayed flags wrong".into());
    }
    let mut rewritten = first.clone();
    rewritten.verification_result = ReceiptVerdict::Mismatch;
    match ledger.record_effect_receipt(&rewritten) {
        Err(err) if err.reason_code() == "GRAPH_CONFLICT" => {}
        other => return Err(format!("receipts: rewrite gave {other:?}")),
    }
    let listed = ledger
        .effect_receipts(&row.id)
        .map_err(|err| format!("receipts list: {err}"))?;
    if listed != vec![first] {
        return Err("receipts: listing does not return the stored receipt".into());
    }
    Ok(())
}

fn unresolved_listing<L: Ledger>(ledger: &mut L) -> Result<(), String> {
    let (open, _) = ledger
        .record_effect_intent(&intent("ce-u1"))
        .map_err(|err| format!("unresolved: {err}"))?;
    for to in [EffectState::Authorized, EffectState::Dispatching] {
        ledger
            .transition_effect(&open.id, to)
            .map_err(|err| format!("unresolved open {}: {err}", to.as_str()))?;
    }
    let (settled, _) = ledger
        .record_effect_intent(&intent("ce-u2"))
        .map_err(|err| format!("unresolved: {err}"))?;
    for to in [
        EffectState::Authorized,
        EffectState::Dispatching,
        EffectState::ReceiptPending,
        EffectState::Verified,
        EffectState::Committed,
    ] {
        ledger
            .transition_effect(&settled.id, to)
            .map_err(|err| format!("unresolved settled {}: {err}", to.as_str()))?;
    }
    let unresolved = ledger
        .unresolved_effects()
        .map_err(|err| format!("unresolved list: {err}"))?;
    let ids: Vec<&str> = unresolved.iter().map(|row| row.id.as_str()).collect();
    if ids != vec![open.id.as_str()] {
        return Err(format!("unresolved: listing was {ids:?}"));
    }
    Ok(())
}
