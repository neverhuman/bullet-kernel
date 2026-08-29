//! Create-once hard-false receipt for the selected local effect closure.

use super::effect_chain::EffectChainClosure;
use super::effect_settlement::ClosedSettlement;
use super::selected_subject::SelectedCandidateSubject;
use super::{fail, fault};
use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{LeaseSettlementOutcome, LeaseSettlementRequest};
use bullet_application::Ledger;
use bullet_domain::{AttemptState, Digest, RunnerId};
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical, hash_framed_bytes};
use bullet_runner_core::AcquireGrant;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "bullet.synthetic-effect-chain-receipt.component.v1";
const BODY_DOMAIN: &str = "bullet.synthetic-effect-chain-receipt.body.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: String,
    body_digest: String,
    body: Body,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Body {
    evidence_class: String,
    signing_trust: String,
    execution_schedule: String,
    authority_class: String,
    selection_binding: SelectionBinding,
    selection_receipt_hex: String,
    selected_candidate: SelectedCandidateSubject,
    effect_authority: EffectAuthorityReceipt,
    effect_chain: EffectChainClosure,
    grants: GrantAbsence,
    eligibility: Eligibility,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SelectionBinding {
    subject_digest: String,
    canonical_blake3: String,
    receipt_digest: String,
    receipt_body_digest: String,
    plan_digest: String,
    selected_handle: String,
    work_package_id: String,
    patch_digest: String,
    candidate_row_digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectAuthorityReceipt {
    runner_id: String,
    runner_epoch: u64,
    variant_id: String,
    attempt_id: String,
    attempt_fence: u64,
    workspace_id: String,
    workspace_nonce_hex: String,
    authority_digest: String,
    author_attempt_id: String,
    author_fence: u64,
    terminal_state: String,
    settlement: ClosedSettlement,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantAbsence {
    delivery_grant_present: bool,
    check_grant_present: bool,
    integration_grant_present: bool,
    distinct_verifier_os_identity: bool,
    distinct_observer_os_identity: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Eligibility {
    independent_evidence_eligible: bool,
    transaction_gate_eligible: bool,
    five_plane_eligible: bool,
    provider_certification_eligible: bool,
    team_recipe_eligible: bool,
    evolution_profile_eligible: bool,
    live_eligible: bool,
    release_gate_eligible: bool,
    routing_activation_eligible: bool,
    comparative_claim_eligible: bool,
    restart_recovery_eligible: bool,
}

impl Envelope {
    fn validate(&self) -> Result<(), String> {
        let body = canonical_json(&self.body)
            .map_err(|error| fail(format!("canonical effect receipt body: {error}")))?;
        validate_envelope_metadata(&self.schema_version, &self.body_digest, &body)?;
        self.body.validate()
    }
}

pub(super) fn create(
    receipt_path: &Path,
    database: &Path,
    selection_receipt: &[u8],
    selected: &SelectedCandidateSubject,
    effect_grant: &AcquireGrant,
    settlement_request: &LeaseSettlementRequest,
    effect_chain: EffectChainClosure,
) -> Result<Vec<u8>, String> {
    selected.validate_origin_receipt(selection_receipt)?;
    let authority_digest = effect_grant
        .authority_token
        .digest()
        .map_err(|error| fail(format!("effect authority digest: {error}")))?
        .to_hex();
    effect_chain.validate(
        selected,
        effect_grant.attempt.id.as_str(),
        effect_grant.attempt.fence,
        &authority_digest,
    )?;
    let settlement = rederive_terminal(database, effect_grant, settlement_request)?;
    let selected_bytes = selected.canonical_bytes()?;
    let selection_binding = SelectionBinding {
        subject_digest: selected.digest()?,
        canonical_blake3: Digest::of(&selected_bytes).to_hex(),
        receipt_digest: selected.selection_receipt_digest().into(),
        receipt_body_digest: selected.selection_body_digest().into(),
        plan_digest: selected.plan_digest().into(),
        selected_handle: selected.selected_handle().into(),
        work_package_id: selected.work_package_id().into(),
        patch_digest: selected.patch_digest().into(),
        candidate_row_digest: selected.candidate_row_digest().into(),
    };
    let effect_authority = EffectAuthorityReceipt {
        runner_id: effect_grant.attempt.runner_id.to_string(),
        runner_epoch: effect_grant.attempt.runner_epoch,
        variant_id: effect_grant.attempt.variant_id.to_string(),
        attempt_id: effect_grant.attempt.id.to_string(),
        attempt_fence: effect_grant.attempt.fence,
        workspace_id: effect_grant.attempt.workspace_id.to_string(),
        workspace_nonce_hex: lower_hex(&effect_grant.attempt.workspace_nonce),
        authority_digest,
        author_attempt_id: selected.author_attempt_id().into(),
        author_fence: selected.author_fence(),
        terminal_state: "Superseded".into(),
        settlement,
    };
    let body = Body {
        evidence_class: "COMPONENT_PROOF".into(),
        signing_trust: "UNSIGNED_FIXTURE".into(),
        execution_schedule: "SEQUENTIAL_SELECTED_COMPONENT".into(),
        authority_class: "ACTIVE_SYNTHETIC_WRITER_LEASE_FIXTURE".into(),
        selection_binding,
        selection_receipt_hex: lower_hex(selection_receipt),
        selected_candidate: selected.clone(),
        effect_authority,
        effect_chain,
        grants: GrantAbsence::none(),
        eligibility: Eligibility::none(),
    };
    body.validate()?;
    let body_bytes = canonical_json(&body)
        .map_err(|error| fail(format!("canonical effect receipt body: {error}")))?;
    let envelope = Envelope {
        schema_version: SCHEMA.into(),
        body_digest: hash_framed_bytes(BODY_DOMAIN, &body_bytes)
            .map_err(|error| fail(format!("effect receipt body digest: {error}")))?,
        body,
    };
    envelope.validate()?;
    let bytes = canonical_json(&envelope)
        .map_err(|error| fail(format!("canonical effect receipt: {error}")))?;
    if fault::before_effect_receipt() {
        return Err(fail("SYNTHETIC_DOGFOOD_FAULT_BEFORE_EFFECT_RECEIPT"));
    }
    let created = super::receipt_storage::create_once(receipt_path, &bytes)?;
    let reopened = super::receipt_storage::reopen_exact(receipt_path, &bytes)?;
    let decoded = decode_canonical::<Envelope>(&reopened)
        .map_err(|error| fail(format!("decode effect receipt readback: {error}")))?;
    decoded.validate()?;
    let recanonical = canonical_json(&decoded)
        .map_err(|error| fail(format!("recanonicalize effect receipt readback: {error}")))?;
    if created != bytes || reopened != bytes || recanonical != reopened {
        return Err(fail("durable effect receipt readback differs"));
    }
    Ok(reopened)
}

fn rederive_terminal(
    database: &Path,
    grant: &AcquireGrant,
    request: &LeaseSettlementRequest,
) -> Result<ClosedSettlement, String> {
    let settlement_id = request
        .settlement_id()
        .map_err(|error| fail(format!("effect settlement id: {error}")))?;
    let mut ledger = SqliteLedger::open(database)
        .map_err(|error| fail(format!("reopen effect ledger: {error}")))?;
    let attempt = ledger
        .get_attempt(&grant.attempt.id)
        .map_err(|error| fail(format!("read effect Attempt: {error}")))?
        .ok_or_else(|| fail("effect Attempt disappeared"))?;
    if attempt.state != AttemptState::Superseded
        || ledger
            .get_lease(&grant.attempt.variant_id)
            .map_err(|error| fail(format!("read terminal effect lease: {error}")))?
            .is_some()
    {
        return Err(fail("effect authority is not durably terminal"));
    }
    let settlement = ledger
        .with_lease_transport(|transaction| transaction.get_transport_settlement(&settlement_id))
        .map_err(|error| fail(format!("read effect settlement: {error}")))?
        .ok_or_else(|| fail("effect settlement disappeared"))?;
    let released = matches!(
        &settlement.outcome,
        LeaseSettlementOutcome::Released(value)
            if value.id == grant.attempt.id && value.state == AttemptState::Superseded
    );
    if settlement.request != *request || !released {
        return Err(fail("effect settlement durable truth differs"));
    }
    ClosedSettlement::from_record(&settlement, request)
}

impl GrantAbsence {
    const fn none() -> Self {
        Self {
            delivery_grant_present: false,
            check_grant_present: false,
            integration_grant_present: false,
            distinct_verifier_os_identity: false,
            distinct_observer_os_identity: false,
        }
    }

    const fn all_false(&self) -> bool {
        !self.delivery_grant_present
            && !self.check_grant_present
            && !self.integration_grant_present
            && !self.distinct_verifier_os_identity
            && !self.distinct_observer_os_identity
    }
}

impl Eligibility {
    const fn none() -> Self {
        Self {
            independent_evidence_eligible: false,
            transaction_gate_eligible: false,
            five_plane_eligible: false,
            provider_certification_eligible: false,
            team_recipe_eligible: false,
            evolution_profile_eligible: false,
            live_eligible: false,
            release_gate_eligible: false,
            routing_activation_eligible: false,
            comparative_claim_eligible: false,
            restart_recovery_eligible: false,
        }
    }

    fn all_false(&self) -> bool {
        serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .is_some_and(|values| values.len() == 11 && values.values().all(|value| value == false))
    }
}

impl Body {
    fn validate(&self) -> Result<(), String> {
        self.selected_candidate.validate()?;
        let selection_receipt = decode_lower_hex(&self.selection_receipt_hex)?;
        self.selected_candidate
            .validate_origin_receipt(&selection_receipt)?;
        let selected_bytes = self.selected_candidate.canonical_bytes()?;
        let binding = &self.selection_binding;
        let binding_exact = binding.subject_digest == self.selected_candidate.digest()?
            && binding.canonical_blake3 == Digest::of(&selected_bytes).to_hex()
            && binding.receipt_digest == self.selected_candidate.selection_receipt_digest()
            && binding.receipt_body_digest == self.selected_candidate.selection_body_digest()
            && binding.plan_digest == self.selected_candidate.plan_digest()
            && binding.selected_handle == self.selected_candidate.selected_handle()
            && binding.work_package_id == self.selected_candidate.work_package_id()
            && binding.patch_digest == self.selected_candidate.patch_digest()
            && binding.candidate_row_digest == self.selected_candidate.candidate_row_digest();
        self.effect_authority.validate(&self.selected_candidate)?;
        self.effect_chain.validate(
            &self.selected_candidate,
            &self.effect_authority.attempt_id,
            self.effect_authority.attempt_fence,
            &self.effect_authority.authority_digest,
        )?;
        let exact = self.evidence_class == "COMPONENT_PROOF"
            && self.signing_trust == "UNSIGNED_FIXTURE"
            && self.execution_schedule == "SEQUENTIAL_SELECTED_COMPONENT"
            && self.authority_class == "ACTIVE_SYNTHETIC_WRITER_LEASE_FIXTURE"
            && binding_exact
            && self.grants.all_false()
            && self.eligibility.all_false();
        exact
            .then_some(())
            .ok_or_else(|| fail("effect receipt classification is not hard-false component"))
    }
}

impl EffectAuthorityReceipt {
    fn validate(&self, selected: &SelectedCandidateSubject) -> Result<(), String> {
        let expected_runner = RunnerId::from_seed("df-dog1-selected-effect-runner");
        let (acquire, attempt, workspace, workspace_nonce, authority_digest) =
            selected.effect_authority_binding()?;
        let acquire_digest = acquire
            .inner()
            .request_digest()
            .map_err(|error| fail(format!("selected effect acquire digest: {error}")))?;
        self.settlement.validate_authority(
            &self.runner_id,
            self.runner_epoch,
            &self.variant_id,
            &self.attempt_id,
            self.attempt_fence,
            &self.workspace_id,
            &self.workspace_nonce_hex,
            selected.work_package_id(),
            &acquire_digest,
            &acquire.inner().idempotency_key,
        )?;
        let successor = selected
            .author_fence()
            .checked_add(1)
            .ok_or_else(|| fail("selected author fence cannot produce an effect successor"))?;
        let exact = self.runner_id == expected_runner.as_str()
            && self.runner_epoch == 1
            && self.variant_id == selected.variant_id()
            && self.attempt_fence == successor
            && self.attempt_id == attempt.as_str()
            && self.runner_id != selected.author_runner_id()
            && self.workspace_id == workspace
            && self.workspace_id != selected.author_workspace_id()
            && self.workspace_nonce_hex == lower_hex(&workspace_nonce)
            && self.authority_digest == authority_digest
            && self.author_attempt_id == selected.author_attempt_id()
            && self.author_fence == selected.author_fence()
            && self.terminal_state == "Superseded";
        exact
            .then_some(())
            .ok_or_else(|| fail("effect authority receipt differs from selected successor"))
    }
}

fn validate_envelope_metadata(schema: &str, digest: &str, body: &[u8]) -> Result<(), String> {
    let expected = hash_framed_bytes(BODY_DOMAIN, body)
        .map_err(|error| fail(format!("effect receipt body digest: {error}")))?;
    (schema == SCHEMA && digest == expected)
        .then_some(())
        .ok_or_else(|| fail("effect receipt schema or body digest differs"))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() > 2_097_152
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fail("retained selection receipt hex is invalid"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| fail("retained selection receipt hex is not UTF-8"))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| fail("retained selection receipt hex cannot be decoded"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_higher_claim_is_hard_false() {
        assert!(GrantAbsence::none().all_false());
        assert!(Eligibility::none().all_false());
        let mut true_claim = serde_json::to_value(Eligibility::none()).expect("eligibility");
        true_claim["release_gate_eligible"] = serde_json::Value::Bool(true);
        let admitted: Eligibility = serde_json::from_value(true_claim).expect("closed fields");
        assert!(!admitted.all_false());

        let mut unknown = serde_json::to_value(Eligibility::none()).expect("eligibility");
        unknown["unknown"] = serde_json::Value::Bool(false);
        let bytes = canonical_json(&unknown).expect("canonical hostile");
        assert!(decode_canonical::<Eligibility>(&bytes).is_err());
    }

    #[test]
    fn envelope_metadata_rejects_wrong_schema_and_body_digest() {
        let body = br#"{"closed":true}"#;
        let digest = hash_framed_bytes(BODY_DOMAIN, body).expect("body digest");
        assert!(validate_envelope_metadata(SCHEMA, &digest, body).is_ok());
        assert!(validate_envelope_metadata("retired", &digest, body).is_err());
        assert!(validate_envelope_metadata(SCHEMA, &"0".repeat(64), body).is_err());
    }

    #[test]
    fn retained_selection_hex_is_exact_lowercase_and_bounded() {
        assert_eq!(decode_lower_hex("007f").unwrap(), [0, 127]);
        for invalid in ["", "0", "AA", "gg"] {
            assert!(decode_lower_hex(invalid).is_err());
        }
    }
}
