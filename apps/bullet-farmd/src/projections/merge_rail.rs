//! Spec section 25.13 Merge Rail: exact Candidates, the effect intent state
//! machine with every catalog state counted, append-only receipts, and the
//! first-slice effect rows. One atomic read; states are the stored labels.

use crate::api::{snapshot_response, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::Response;
use bullet_application::store::ProjectionReader;
use bullet_application::{EffectIntentRecord, EffectReceiptRecord, EffectState, LedgerError};
use bullet_domain::{Candidate, Effect};
use serde::Serialize;

use super::{count_labels, LabelCount};

#[derive(Serialize)]
pub(crate) struct CandidateRow {
    id: String,
    attempt_id: String,
    base_sha: String,
    head_sha: String,
    tree_sha: String,
    patch_digest: String,
}

#[derive(Serialize)]
pub(crate) struct EffectRow {
    id: String,
    attempt_id: String,
    logical_key: String,
    desired: String,
    outcome: String,
}

#[derive(Serialize)]
pub(crate) struct EffectIntentRow {
    id: String,
    logical_effect_key: String,
    provider: String,
    target_identity: String,
    desired_state_hash: String,
    expected_old_oid: String,
    attempt_id: String,
    fence: u64,
    policy_version: String,
    payload_hash: String,
    provider_idempotency_key: Option<String>,
    state: String,
    unknown_retries: u32,
    created_at: String,
}

#[derive(Serialize)]
pub(crate) struct EffectReceiptRow {
    id: String,
    effect_intent_id: String,
    observed_remote_identity: String,
    observed_state_hash: Option<String>,
    verification_method: String,
    verification_result: String,
    adopted_after_unknown: bool,
    recorded_at: String,
}

/// Merge Rail projection body.
#[derive(Serialize)]
pub(crate) struct MergeRailView {
    candidates: Vec<CandidateRow>,
    effects: Vec<EffectRow>,
    intents: Vec<EffectIntentRow>,
    receipts: Vec<EffectReceiptRow>,
    intent_state_counts: Vec<LabelCount>,
}

fn candidate_row(candidate: Candidate) -> CandidateRow {
    CandidateRow {
        id: candidate.id.to_string(),
        attempt_id: candidate.attempt_id.to_string(),
        base_sha: candidate.base_sha,
        head_sha: candidate.head_sha,
        tree_sha: candidate.tree_sha,
        patch_digest: candidate.patch_digest.to_hex(),
    }
}

fn effect_row(effect: Effect) -> EffectRow {
    EffectRow {
        id: effect.id.to_string(),
        attempt_id: effect.attempt_id.to_string(),
        logical_key: effect.logical_key,
        desired: effect.desired,
        outcome: effect.outcome,
    }
}

fn intent_row(intent: EffectIntentRecord) -> EffectIntentRow {
    EffectIntentRow {
        id: intent.id.to_string(),
        logical_effect_key: intent.logical_effect_key,
        provider: intent.provider,
        target_identity: intent.target_identity,
        desired_state_hash: intent.desired_state_hash,
        expected_old_oid: intent.expected_old_oid,
        attempt_id: intent.attempt_id.to_string(),
        fence: intent.fence,
        policy_version: intent.policy_version,
        payload_hash: intent.payload_hash,
        provider_idempotency_key: intent.provider_idempotency_key,
        state: intent.state.as_str().to_string(),
        unknown_retries: intent.unknown_retries,
        created_at: intent.created_at,
    }
}

fn receipt_row(receipt: EffectReceiptRecord) -> EffectReceiptRow {
    EffectReceiptRow {
        id: receipt.id.to_string(),
        effect_intent_id: receipt.effect_intent_id.to_string(),
        observed_remote_identity: receipt.observed_remote_identity,
        observed_state_hash: receipt.observed_state_hash,
        verification_method: receipt.verification_method,
        verification_result: receipt.verification_result.as_str().to_string(),
        adopted_after_unknown: receipt.adopted_after_unknown,
        recorded_at: receipt.recorded_at,
    }
}

pub(crate) fn build(
    candidates: Vec<Candidate>,
    effects: Vec<Effect>,
    intents: Vec<EffectIntentRecord>,
    receipts: Vec<EffectReceiptRecord>,
) -> MergeRailView {
    let catalog = EffectState::all();
    let intent_state_counts = count_labels(
        catalog.iter().map(|state| state.as_str()),
        intents.iter().map(|intent| intent.state.as_str()),
    );
    MergeRailView {
        candidates: candidates.into_iter().map(candidate_row).collect(),
        effects: effects.into_iter().map(effect_row).collect(),
        intents: intents.into_iter().map(intent_row).collect(),
        receipts: receipts.into_iter().map(receipt_row).collect(),
        intent_state_counts,
    }
}

pub(crate) fn read<L: ProjectionReader>(ledger: &L) -> Result<MergeRailView, LedgerError> {
    Ok(build(
        ledger.list_candidates()?,
        ledger.list_effects()?,
        ledger.list_effect_intents()?,
        ledger.list_effect_receipts()?,
    ))
}

pub(crate) async fn merge_rail(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (view, as_of_sequence) = ledger.read_snapshot(read)?;
    snapshot_response(view, as_of_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rail_lists_all_thirteen_states_at_zero() {
        let view = build(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        assert_eq!(view.intent_state_counts.len(), 13);
        assert!(view.intent_state_counts.iter().all(|row| row.count == 0));
        assert!(view
            .intent_state_counts
            .iter()
            .any(|row| row.label == "OUTCOME_UNKNOWN"));
    }
}
