//! Broker the candidate onto the local bare forge with a read-back receipt.
//! Live forge credentials and host profiles are never inspected here.

use crate::demo_synthetic::receipt::{JeryuOut, LocalEffectOut};
use crate::demo_synthetic::SharedLedger;
use bullet_adapters::SqliteLedger;
use bullet_application::{LeaseService, Ledger, StoredGraph};
use bullet_domain::{Attempt, AttemptState};
use bullet_effects_core::{
    authorize, dispatch, propose, EffectsError, ForgeEffects, IntentInput, LocalBareForge,
    LOCAL_PROVIDER, ZERO_OID,
};
use chrono::Utc;
use std::path::Path;

fn eff(step: &'static str) -> impl Fn(EffectsError) -> String {
    move |err| format!("{step}:{}: {err}", err.reason_code())
}

fn advance(
    store: &mut SqliteLedger,
    attempt: &Attempt,
    to: AttemptState,
) -> Result<Attempt, String> {
    let mut next = attempt.clone();
    next.state = next
        .state
        .transition(to)
        .map_err(|err| format!("DELIVERY_TRANSITION: {err}"))?;
    store
        .put_attempt(&next)
        .map_err(|err| format!("DELIVERY_PUT:{}: {err}", err.reason_code()))?;
    Ok(next)
}

fn open_forge(data_dir: &Path) -> Result<LocalBareForge, String> {
    let bare = data_dir.join("local-forge.git");
    let result = if bare.exists() {
        LocalBareForge::open(&bare)
    } else {
        LocalBareForge::init(&bare)
    };
    result.map_err(|err| format!("LOCAL_FORGE:{}: {err}", err.reason_code()))
}

/// Push the candidate ref to the local bare forge through the durable
/// intent/receipt broker, under a local lease on the delivery variant.
pub fn deliver_local(
    ledger: &SharedLedger,
    graph: &StoredGraph,
    candidate_id: &str,
    head: &str,
    workspace_repo: &Path,
    data_dir: &Path,
) -> Result<LocalEffectOut, String> {
    let mut guard = ledger
        .lock()
        .map_err(|_| "ledger mutex poisoned".to_string())?;
    let store = &mut *guard;
    let mut forge = open_forge(data_dir)?;
    let now = || LeaseService::rfc3339(Utc::now());
    let (attempt, token, grant) =
        LeaseService::acquire(store, graph, 1, "demo-synthetic-delivery", 15)
            .map_err(|err| format!("DELIVERY_LEASE:{}: {err}", err.reason_code()))?;
    let attempt = advance(store, &attempt, AttemptState::Running)?;
    let ref_name = format!("refs/heads/bullet/candidate/{candidate_id}");
    let input = IntentInput {
        provider: LOCAL_PROVIDER.into(),
        logical_effect_key: format!("push:{candidate_id}:{ref_name}"),
        target_ref: ref_name.clone(),
        new_oid: head.to_string(),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: token.attempt_id.clone(),
        fence: token.attempt_fence,
        policy_version: "synthetic-only-v1".into(),
        provider_idempotency_key: None,
    };
    let (row, _created) = propose(store, &input, &now()).map_err(eff("EFFECT_PROPOSE"))?;
    let (_authorized, seq) =
        authorize(store, &row.id, &token, &now()).map_err(eff("EFFECT_AUTHORIZE"))?;
    let state = dispatch(
        store,
        &mut forge,
        &row.id,
        workspace_repo,
        Some(seq),
        &now(),
    )
    .map_err(eff("EFFECT_DISPATCH"))?;
    let read_back = forge.read_ref(&ref_name).map_err(eff("EFFECT_READ_BACK"))?;
    let attempt = advance(store, &attempt, AttemptState::Preparing)?;
    let _ = attempt;
    LeaseService::release(store, &grant, AttemptState::Succeeded, false)
        .map_err(|err| format!("DELIVERY_RELEASE:{}: {err}", err.reason_code()))?;
    Ok(LocalEffectOut {
        ref_name,
        old_oid: ZERO_OID.into(),
        new_oid: head.to_string(),
        read_back_verified: read_back.as_deref() == Some(head),
        state: state.as_str().to_string(),
    })
}

/// Record the Wave-0 forge quarantine without reading host credentials.
#[must_use]
pub fn probe_jeryu(_candidate_ref: &str) -> JeryuOut {
    JeryuOut {
        status: "LIVE_FORGE_QUARANTINED".into(),
        authenticated: false,
        note: "Wave 0 admits no credential or network probe".into(),
    }
}
