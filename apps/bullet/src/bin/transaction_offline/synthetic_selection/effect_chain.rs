//! Selected-Candidate verification and local effect closure under fresh authority.

use super::effect_records::{ClosedEffectIntent, ClosedEffectReceipt};
use super::selected_subject::SelectedCandidateSubject;
use super::{configure_kernel_authority, fail, fault, LaneRun};
use crate::transaction_offline::chaos::{self, Boundary};
use crate::transaction_offline::farmd_fixture::{spawn_synthetic_effect_farmd, RunnerRegistration};
use crate::transaction_offline::forge_chain::{close_local_forge, LocalForgeClosure};
use crate::transaction_offline::signed_verification::{
    verify_candidate, SignedVerificationClosure,
};
use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{LeaseSettlementRequest, SyntheticSelectedAcquireBody};
use bullet_application::{receipt_id, EffectIntentRecord, EffectState, Ledger};
use bullet_domain::{Digest, EffectId, RunnerId, WorkPackageId};
use bullet_effects_core::{
    authorize, dispatch, propose, reconcile, IntentInput, LocalBareForge, LossMode,
    LostResponseForge, ReconcileOutcome, ZERO_OID,
};
use bullet_runner_core::AcquireGrant;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub(super) struct ClosedEffect {
    pub(super) grant: AcquireGrant,
    pub(super) settlement: LeaseSettlementRequest,
    pub(super) chain: EffectChainClosure,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EffectChainClosure {
    provider: String,
    logical_effect_key: String,
    target_ref: String,
    effect_attempt_id: String,
    effect_fence: u64,
    effect_authority_digest: String,
    dispatch_state: String,
    reconciliation: String,
    settled_state: String,
    durable_intent: ClosedEffectIntent,
    durable_receipts: Vec<ClosedEffectReceipt>,
    signed_verification: SignedVerificationClosure,
    local_forge: LocalForgeClosure,
}

impl EffectChainClosure {
    pub(super) fn validate(
        &self,
        selected: &SelectedCandidateSubject,
        authority_attempt: &str,
        authority_fence: u64,
        authority_digest: &str,
    ) -> Result<(), String> {
        let head = strip_tag(selected.head_oid());
        let expected_target = format!("refs/heads/bullet/candidate/{}", selected.candidate_id());
        let expected_logical = format!(
            "selected-push:{}:{authority_attempt}:{authority_fence}",
            selected.candidate_id()
        );
        let expected_effect = EffectId::from_seed(&format!("local-bare:{expected_logical}"));
        self.durable_intent.validate_payload()?;
        self.signed_verification.validate_selected(
            selected.candidate_id(),
            selected.repository(),
            strip_tag(selected.base_oid()),
            head,
            strip_tag(selected.tree_oid()),
            selected.author_attempt_id(),
            selected.policy_digest(),
        )?;
        self.local_forge.validate_selected(
            selected.candidate_id(),
            strip_tag(selected.base_oid()),
            head,
            self.signed_verification.proof_bundle_id(),
            self.signed_verification.proof_root(),
        )?;
        let receipt = self
            .durable_receipts
            .first()
            .ok_or_else(|| fail("selected effect receipt is absent"))?;
        let expected_receipt = receipt_id(&format!(
            "{}:MATCH:true:{}",
            expected_effect, self.durable_intent.created_at
        ));
        let timestamp_exact = self.durable_intent.created_at == receipt.recorded_at
            && chrono::DateTime::parse_from_rfc3339(&self.durable_intent.created_at).is_ok();
        let exact = self.provider == "local-bare"
            && self.logical_effect_key == expected_logical
            && self.target_ref == expected_target
            && self.effect_attempt_id == authority_attempt
            && self.effect_fence == authority_fence
            && self.effect_authority_digest == authority_digest
            && self.effect_fence == selected.author_fence() + 1
            && self.dispatch_state == EffectState::OutcomeUnknown.as_str()
            && self.reconciliation == "ADOPTED"
            && self.settled_state == EffectState::Committed.as_str()
            && self.durable_intent.provider == self.provider
            && self.durable_intent.logical_effect_key == self.logical_effect_key
            && self.durable_intent.id == expected_effect.as_str()
            && self.durable_intent.target_identity == self.target_ref
            && self.durable_intent.desired_state_hash == head
            && self.durable_intent.expected_old_oid == ZERO_OID
            && self.durable_intent.attempt_id == self.effect_attempt_id
            && self.durable_intent.fence == self.effect_fence
            && self.durable_intent.policy_version == "policy-v1"
            && self.durable_intent.provider_idempotency_key.is_none()
            && self.durable_intent.state == EffectState::Committed.as_str()
            && self.durable_intent.unknown_retries == 0
            && !self.durable_intent.created_at.is_empty()
            && self.durable_receipts.len() == 1
            && receipt.effect_intent_id == self.durable_intent.id
            && receipt.id == expected_receipt.as_str()
            && receipt.observed_remote_identity == self.target_ref
            && receipt.observed_state_hash.as_deref() == Some(head)
            && receipt.verification_method == "git-ls-remote-read-back"
            && receipt.verification_result == "MATCH"
            && receipt.adopted_after_unknown
            && timestamp_exact;
        exact
            .then_some(())
            .ok_or_else(|| fail("selected local effect closure differs from durable subjects"))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_selected(
    database: &Path,
    data: &Path,
    artifacts: &Path,
    selected: &SelectedCandidateSubject,
    lanes: [&LaneRun; 2],
) -> Result<ClosedEffect, String> {
    let selection_digest = Digest::from_hex(selected.plan_digest())
        .map_err(|error| fail(format!("selected plan digest: {error}")))?;
    let package = WorkPackageId::parse(selected.work_package_id())
        .map_err(|error| fail(format!("selected work package: {error}")))?;
    let author = lanes
        .into_iter()
        .find(|lane| lane.barrier.candidate.id.as_str() == selected.candidate_id())
        .ok_or_else(|| fail("sealed selected Candidate has no author lane"))?;
    let registration = RunnerRegistration {
        runner_id: RunnerId::from_seed("df-dog1-selected-effect-runner"),
        runner_epoch: 1,
    };
    if lanes
        .iter()
        .any(|lane| lane.registration.runner_id == registration.runner_id)
    {
        return Err(fail("selected effect Runner reuses an author principal"));
    }
    let farmd = spawn_synthetic_effect_farmd(data, &registration)?;
    crate::transaction_offline::support::wait_for(&farmd.lease_socket, 120)?;
    crate::transaction_offline::support::wait_for(&farmd.kernel_socket, 120)?;
    configure_kernel_authority(&farmd);
    let client = match farmd.client(0, &registration) {
        Ok(client) => client,
        Err(error) => return stop_with_error(farmd, error),
    };
    let request = SyntheticSelectedAcquireBody::new(
        selection_digest,
        package,
        registration.runner_id.clone(),
        registration.runner_epoch,
        author.variant_id.clone(),
        15,
    )
    .map_err(|error| fail(format!("build selected effect request: {error}")))?;
    let authority = match super::effect_authority::EffectAuthority::new(
        client,
        request,
        author.grant.clone(),
    ) {
        Ok(authority) => authority,
        Err(error) => return stop_with_error(farmd, fail(error.to_string())),
    };
    let acquired = match authority.acquire().await {
        Ok(grant) => grant,
        Err(error) => return stop_with_error(farmd, fail(error.to_string())),
    };
    let grant = match authority.grant() {
        Ok(grant) if grant.attempt == acquired.attempt && grant.lease == acquired.lease => grant,
        Ok(_) => {
            let changed = if fault::effect_grant_changed() {
                fail("SYNTHETIC_DOGFOOD_FAULT_EFFECT_GRANT_CHANGED")
            } else {
                fail("effect authority grant readback changed")
            };
            return abort_acquired(&authority, farmd, changed).await;
        }
        Err(error) => return abort_acquired(&authority, farmd, fail(error.to_string())).await,
    };
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let work = async {
        authority
            .activate()
            .await
            .map_err(|error| fail(format!("activate selected effect authority: {error}")))?;
        authority
            .heartbeat()
            .await
            .map_err(|error| fail(format!("heartbeat selected effect authority: {error}")))?;
        execute(database, artifacts, selected, &grant, &now).await
    }
    .await;
    let chain = match work {
        Ok(chain) => chain,
        Err(original) => {
            let cleanup = authority
                .cleanup_failed()
                .await
                .map_err(|error| fail(format!("selected effect cleanup outcome UNKNOWN: {error}")));
            let stopped = farmd.stop();
            return Err(combine_failure(original, cleanup, stopped));
        }
    };
    if let Err(error) = authority.settle_superseded().await {
        return stop_with_error(
            farmd,
            fail(format!(
                "selected effect settlement outcome UNKNOWN: {error}"
            )),
        );
    }
    let settlement = match authority.settlement_request() {
        Ok(settlement) => settlement,
        Err(error) => return stop_with_error(farmd, fail(error.to_string())),
    };
    farmd.stop()?;
    Ok(ClosedEffect {
        grant,
        settlement,
        chain,
    })
}

pub(super) async fn execute(
    database: &Path,
    artifacts: &Path,
    selected: &SelectedCandidateSubject,
    effect_grant: &AcquireGrant,
    now: &str,
) -> Result<EffectChainClosure, String> {
    chaos::refuse_if_selected(Boundary::VerifierHandoff)?;
    let verification = verify_candidate(
        selected.candidate_id(),
        selected.repository(),
        strip_tag(selected.base_oid()),
        strip_tag(selected.head_oid()),
        strip_tag(selected.tree_oid()),
        selected.author_attempt_id(),
        selected.policy_digest(),
    )
    .await?;

    let effects_root = artifacts.join("selected-effects");
    fs::create_dir(&effects_root)
        .map_err(|error| fail(format!("create selected effects root: {error}")))?;
    let forge = LocalBareForge::init(&effects_root.join("target.git"))
        .map_err(|error| fail(format!("initialize selected local forge: {error}")))?;
    let logical_effect_key = format!(
        "selected-push:{}:{}:{}",
        selected.candidate_id(),
        effect_grant.attempt.id,
        effect_grant.attempt.fence
    );
    let target_ref = format!("refs/heads/bullet/candidate/{}", selected.candidate_id());
    let intent = IntentInput {
        provider: "local-bare".into(),
        logical_effect_key: logical_effect_key.clone(),
        target_ref: target_ref.clone(),
        new_oid: strip_tag(selected.head_oid()).into(),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: effect_grant.attempt.id.clone(),
        fence: effect_grant.attempt.fence,
        policy_version: "policy-v1".into(),
        provider_idempotency_key: None,
    };
    let mut ledger = SqliteLedger::open(database)
        .map_err(|error| fail(format!("open selected effect ledger: {error}")))?;
    let (row, _) = propose(&mut ledger, &intent, now)
        .map_err(|error| fail(format!("propose selected delivery: {error}")))?;
    let (_, outbox_seq) =
        authorize_with_retry(&mut ledger, &row, &effect_grant.authority_token, now)?;

    let mut lossy = LostResponseForge::new(forge);
    lossy.lose_next(LossMode::AfterPush);
    chaos::refuse_if_selected(Boundary::CandidateDelivery)?;
    let dispatch_state = dispatch(
        &mut ledger,
        &mut lossy,
        &row.id,
        selected.repository(),
        Some(outbox_seq),
        now,
    )
    .map_err(|error| fail(format!("dispatch selected delivery: {error}")))?;
    if dispatch_state != EffectState::OutcomeUnknown {
        return Err(fail(format!(
            "selected delivery response loss was {dispatch_state:?}, not UNKNOWN"
        )));
    }
    if fault::after_delivery_unknown() {
        return Err(fail("SYNTHETIC_DOGFOOD_FAULT_AFTER_DELIVERY_UNKNOWN"));
    }
    let reconciliation = reconcile(
        &mut ledger,
        &mut lossy,
        &row.id,
        selected.repository(),
        Some(outbox_seq),
        now,
    )
    .map_err(|error| fail(format!("reconcile selected delivery: {error}")))?;
    if reconciliation != ReconcileOutcome::Adopted {
        return Err(fail(format!(
            "selected delivery reconciliation was {reconciliation:?}, not Adopted"
        )));
    }
    let durable_intent = ledger
        .get_effect_intent_by_id(&row.id)
        .map_err(|error| fail(format!("read selected effect intent: {error}")))?
        .ok_or_else(|| fail("selected effect intent disappeared"))?;
    let durable_receipts = ledger
        .effect_receipts(&row.id)
        .map_err(|error| fail(format!("read selected effect receipts: {error}")))?;
    let local_forge = close_local_forge(
        lossy,
        &target_ref,
        selected.candidate_id(),
        selected.base_oid(),
        selected.head_oid(),
        verification.proof_bundle_id(),
        verification.proof_root(),
    )?;
    let closure = EffectChainClosure {
        provider: "local-bare".into(),
        logical_effect_key,
        target_ref,
        effect_attempt_id: effect_grant.attempt.id.to_string(),
        effect_fence: effect_grant.attempt.fence,
        effect_authority_digest: effect_grant
            .authority_token
            .digest()
            .map_err(|error| fail(format!("effect authority digest: {error}")))?
            .to_hex(),
        dispatch_state: dispatch_state.as_str().into(),
        reconciliation: "ADOPTED".into(),
        settled_state: durable_intent.state.as_str().into(),
        durable_intent: ClosedEffectIntent::from_record(&durable_intent)?,
        durable_receipts: durable_receipts
            .iter()
            .map(ClosedEffectReceipt::from_record)
            .collect(),
        signed_verification: verification,
        local_forge,
    };
    closure.validate(
        selected,
        effect_grant.attempt.id.as_str(),
        effect_grant.attempt.fence,
        &effect_grant
            .authority_token
            .digest()
            .map_err(|error| fail(format!("effect authority digest: {error}")))?
            .to_hex(),
    )?;
    Ok(closure)
}

fn authorize_with_retry(
    ledger: &mut SqliteLedger,
    row: &EffectIntentRecord,
    token: &bullet_domain::AuthorityToken,
    now: &str,
) -> Result<(EffectIntentRecord, u64), String> {
    let mut last = None;
    for _ in 0..8 {
        match authorize(ledger, &row.id, token, now) {
            Ok(value) => return Ok(value),
            Err(error) => {
                last = Some(error.to_string());
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Err(fail(format!(
        "authorize selected delivery: {}",
        last.unwrap_or_else(|| "no authorization attempt executed".into())
    )))
}

fn strip_tag(oid: &str) -> &str {
    oid.split_once(':').map_or(oid, |(_, hex)| hex)
}

fn stop_with_error(
    farmd: crate::transaction_offline::farmd_fixture::SyntheticFarmd,
    original: String,
) -> Result<ClosedEffect, String> {
    match farmd.stop() {
        Ok(()) => Err(original),
        Err(stop) => Err(fail(format!("{original}; stop effect farmd: {stop}"))),
    }
}

async fn abort_acquired(
    authority: &super::effect_authority::EffectAuthority,
    farmd: crate::transaction_offline::farmd_fixture::SyntheticFarmd,
    original: String,
) -> Result<ClosedEffect, String> {
    let cleanup = authority
        .cleanup_failed()
        .await
        .map_err(|error| fail(format!("effect grant cleanup outcome UNKNOWN: {error}")));
    Err(combine_failure(original, cleanup, farmd.stop()))
}

fn combine_failure(
    original: String,
    cleanup: Result<(), String>,
    stopped: Result<(), String>,
) -> String {
    let mut failures = vec![original];
    if let Err(error) = cleanup {
        failures.push(error);
    }
    if let Err(error) = stopped {
        failures.push(format!("stop effect farmd: {error}"));
    }
    fail(failures.join("; "))
}
