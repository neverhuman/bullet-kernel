//! Closed release-settlement projection retained by the component receipt.

use super::fail;
use bullet_application::lease_transport::{
    LeaseSettlementOutcome, LeaseSettlementRecord, LeaseSettlementRequest,
    ReleaseSettlementRequest, LEASE_SETTLEMENT_RECORD_VERSION,
};
use bullet_domain::{AttemptId, AttemptState, Digest, RunnerId, VariantId, WorkPackageId};
use bullet_harness_core::candidate_preparation_scope_paths_digest;
use bullet_harness_core::launch_grant::{
    canonical_json, hash_framed_bytes, workspace_nonce_digest,
};
use serde::{Deserialize, Serialize};

const SUBJECT_DOMAIN: &str = "bullet.synthetic-effect-settlement-subject.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClosedSettlement {
    version: String,
    settlement_id: String,
    request_digest: String,
    acquire_request_digest: String,
    work_package_id: String,
    runner_id: String,
    runner_epoch: u64,
    idempotency_key: String,
    variant_id: String,
    attempt_id: String,
    attempt_fence: u64,
    expected_state: String,
    final_state: String,
    requeue: bool,
    subject_digest: String,
    subject: ClosedLeaseSubject,
    outcome_attempt_id: String,
    outcome_variant_id: String,
    outcome_work_package_id: String,
    outcome_fence: u64,
    outcome_runner_id: String,
    outcome_runner_epoch: u64,
    outcome_workspace_id: String,
    outcome_workspace_nonce_hex: String,
    outcome_scope_revision: u64,
    outcome_context_revision: u64,
    outcome_state: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClosedLeaseSubject {
    workspace_id: String,
    workspace_generation: u64,
    workspace_nonce_digest: String,
    scope_digest: String,
    policy_generation: u64,
    freeze_generation: u64,
    graph_revision: u64,
    routing_generation: u64,
    authority_epoch: u64,
    incarnation: ClosedIncarnation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClosedIncarnation {
    variant_id: String,
    attempt_id: String,
    fence: u64,
    scope_revision: u64,
    context_revision: u64,
}

impl ClosedSettlement {
    pub(super) fn from_record(
        record: &LeaseSettlementRecord,
        request: &LeaseSettlementRequest,
    ) -> Result<Self, String> {
        if record.request != *request {
            return Err(fail("effect settlement request differs from durable row"));
        }
        let (release, attempt) = match (&record.request, &record.outcome) {
            (
                LeaseSettlementRequest::Release(release),
                LeaseSettlementOutcome::Released(attempt),
            ) => (release, attempt),
            _ => return Err(fail("effect settlement is not a released Attempt")),
        };
        let subject = canonical_json(&record.subject)
            .map_err(|error| fail(format!("canonical effect settlement subject: {error}")))?;
        let incarnation = record
            .subject
            .incarnation
            .as_ref()
            .ok_or_else(|| fail("effect settlement subject has no incarnation"))?;
        let closed_subject = ClosedLeaseSubject {
            workspace_id: record.subject.workspace_id.clone(),
            workspace_generation: record.subject.workspace_generation,
            workspace_nonce_digest: record.subject.workspace_nonce_digest.clone(),
            scope_digest: record.subject.scope_digest.clone(),
            policy_generation: record.subject.policy_generation,
            freeze_generation: record.subject.freeze_generation,
            graph_revision: record.subject.graph_revision,
            routing_generation: record.subject.routing_generation,
            authority_epoch: record.subject.authority_epoch,
            incarnation: ClosedIncarnation {
                variant_id: incarnation.variant_id.clone(),
                attempt_id: incarnation.attempt_id.clone(),
                fence: incarnation.fence,
                scope_revision: incarnation.scope_revision,
                context_revision: incarnation.context_revision,
            },
        };
        let closed = Self {
            version: record.version.clone(),
            settlement_id: record.settlement_id.clone(),
            request_digest: record.request_digest.clone(),
            acquire_request_digest: release.acquire_request_digest.clone(),
            work_package_id: release.work_package_id.to_string(),
            runner_id: release.runner_id.to_string(),
            runner_epoch: release.runner_epoch,
            idempotency_key: release.idempotency_key.clone(),
            variant_id: release.variant_id.to_string(),
            attempt_id: release.attempt_id.to_string(),
            attempt_fence: release.attempt_fence,
            expected_state: format!("{:?}", release.expected_state),
            final_state: format!("{:?}", release.final_state),
            requeue: release.requeue,
            subject_digest: hash_framed_bytes(SUBJECT_DOMAIN, &subject)
                .map_err(|error| fail(format!("effect settlement subject digest: {error}")))?,
            subject: closed_subject,
            outcome_attempt_id: attempt.id.to_string(),
            outcome_variant_id: attempt.variant_id.to_string(),
            outcome_work_package_id: attempt.work_package_id.to_string(),
            outcome_fence: attempt.fence,
            outcome_runner_id: attempt.runner_id.to_string(),
            outcome_runner_epoch: attempt.runner_epoch,
            outcome_workspace_id: attempt.workspace_id.to_string(),
            outcome_workspace_nonce_hex: lower_hex(&attempt.workspace_nonce),
            outcome_scope_revision: attempt.scope_revision,
            outcome_context_revision: attempt.context_revision,
            outcome_state: format!("{:?}", attempt.state),
        };
        closed.validate_internal()?;
        Ok(closed)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate_authority(
        &self,
        runner_id: &str,
        runner_epoch: u64,
        variant_id: &str,
        attempt_id: &str,
        attempt_fence: u64,
        workspace_id: &str,
        workspace_nonce_hex: &str,
        work_package_id: &str,
        acquire_request_digest: &str,
        idempotency_key: &str,
    ) -> Result<(), String> {
        self.validate_internal()?;
        let exact = self.runner_id == runner_id
            && self.runner_epoch == runner_epoch
            && self.variant_id == variant_id
            && self.attempt_id == attempt_id
            && self.attempt_fence == attempt_fence
            && self.outcome_runner_id == runner_id
            && self.outcome_runner_epoch == runner_epoch
            && self.outcome_variant_id == variant_id
            && self.outcome_attempt_id == attempt_id
            && self.outcome_fence == attempt_fence
            && self.outcome_workspace_id == workspace_id
            && self.outcome_workspace_nonce_hex == workspace_nonce_hex
            && self.work_package_id == work_package_id
            && self.acquire_request_digest == acquire_request_digest
            && self.idempotency_key == idempotency_key;
        exact
            .then_some(())
            .ok_or_else(|| fail("closed settlement differs from effect authority"))
    }

    fn validate_internal(&self) -> Result<(), String> {
        let expected_scope_digest =
            candidate_preparation_scope_paths_digest(&["src".to_owned(), "PONG.txt".to_owned()])
                .map_err(|error| fail(format!("closed settlement scope digest: {error}")))?;
        let request = LeaseSettlementRequest::Release(ReleaseSettlementRequest {
            acquire_request_digest: self.acquire_request_digest.clone(),
            work_package_id: WorkPackageId::parse(&self.work_package_id)
                .map_err(|error| fail(error.to_string()))?,
            runner_id: RunnerId::parse(&self.runner_id).map_err(|error| fail(error.to_string()))?,
            runner_epoch: self.runner_epoch,
            idempotency_key: self.idempotency_key.clone(),
            variant_id: VariantId::parse(&self.variant_id)
                .map_err(|error| fail(error.to_string()))?,
            attempt_id: AttemptId::parse(&self.attempt_id)
                .map_err(|error| fail(error.to_string()))?,
            attempt_fence: self.attempt_fence,
            expected_state: AttemptState::Running,
            final_state: AttemptState::Superseded,
            requeue: true,
        });
        let digest = request
            .digest()
            .map_err(|error| fail(format!("closed settlement request digest: {error}")))?;
        let valid_digest =
            |value: &str| Digest::from_hex(value).is_ok_and(|decoded| decoded.to_hex() == value);
        let nonce = Digest::from_hex(&self.outcome_workspace_nonce_hex)
            .map_err(|error| fail(format!("closed settlement workspace nonce: {error}")))?;
        let nonce_digest = workspace_nonce_digest(nonce.as_bytes())
            .map_err(|error| fail(format!("closed settlement nonce digest: {error}")))?;
        let subject = canonical_json(&self.subject)
            .map_err(|error| fail(format!("canonical closed settlement subject: {error}")))?;
        let subject_digest = hash_framed_bytes(SUBJECT_DOMAIN, &subject)
            .map_err(|error| fail(format!("closed settlement subject digest: {error}")))?;
        let incarnation = &self.subject.incarnation;
        let exact = self.version == LEASE_SETTLEMENT_RECORD_VERSION
            && self.request_digest == digest
            && self.settlement_id == format!("lts_{digest}")
            && valid_digest(&self.acquire_request_digest)
            && self.subject_digest == subject_digest
            && !self.idempotency_key.is_empty()
            && self.runner_epoch > 0
            && self.attempt_fence > 0
            && self.expected_state == "Running"
            && self.final_state == "Superseded"
            && self.requeue
            && self.outcome_attempt_id == self.attempt_id
            && self.outcome_variant_id == self.variant_id
            && self.outcome_work_package_id == self.work_package_id
            && self.outcome_fence == self.attempt_fence
            && self.outcome_runner_id == self.runner_id
            && self.outcome_runner_epoch == self.runner_epoch
            && !self.outcome_workspace_id.is_empty()
            && is_lower_hex_64(&self.outcome_workspace_nonce_hex)
            && self.outcome_scope_revision > 0
            && self.outcome_context_revision > 0
            && self.outcome_state == "Superseded"
            && self.subject.workspace_id == self.outcome_workspace_id
            && self.subject.workspace_generation == 1
            && self.subject.workspace_nonce_digest == nonce_digest
            && self.subject.scope_digest == expected_scope_digest
            && self.subject.policy_generation == 1
            && self.subject.freeze_generation == 0
            && self.subject.graph_revision == 1
            && self.subject.routing_generation == 1
            && self.subject.authority_epoch == 2
            && incarnation.variant_id == self.variant_id
            && incarnation.attempt_id == self.attempt_id
            && incarnation.fence == self.attempt_fence
            && incarnation.scope_revision == self.outcome_scope_revision
            && incarnation.context_revision == self.outcome_context_revision
            && incarnation.scope_revision == 1
            && incarnation.context_revision == 1;
        exact
            .then_some(())
            .ok_or_else(|| fail("closed settlement is not the exact durable release"))
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_settlement_rejects_unknown_fields() {
        let mut value = serde_json::json!({
            "version":"lease-transport-settlement.v1alpha1", "settlement_id":"lts_x",
            "request_digest":"x", "acquire_request_digest":"x", "work_package_id":"wpk_x",
            "runner_id":"run_x", "runner_epoch":1, "idempotency_key":"key", "variant_id":"var_x",
            "attempt_id":"atm_x", "attempt_fence":2, "expected_state":"Running",
            "final_state":"Superseded", "requeue":true, "subject_digest":"x",
            "subject":{"workspace_id":"wsp_x", "workspace_generation":1,
              "workspace_nonce_digest":"x", "scope_digest":"x", "policy_generation":1,
              "freeze_generation":0, "graph_revision":1, "routing_generation":1,
              "authority_epoch":1, "incarnation":{"variant_id":"var_x", "attempt_id":"atm_x",
                "fence":2, "scope_revision":1, "context_revision":1}},
            "outcome_attempt_id":"atm_x", "outcome_variant_id":"var_x",
            "outcome_work_package_id":"wpk_x", "outcome_fence":2, "outcome_runner_id":"run_x",
            "outcome_runner_epoch":1, "outcome_workspace_id":"wsp_x",
            "outcome_workspace_nonce_hex":"x", "outcome_scope_revision":1,
            "outcome_context_revision":1, "outcome_state":"Superseded"
        });
        value["unknown"] = serde_json::Value::Bool(false);
        assert!(serde_json::from_value::<ClosedSettlement>(value).is_err());

        let mut nested = serde_json::json!({
            "workspace_id":"wsp_x", "workspace_generation":1, "workspace_nonce_digest":"x",
            "scope_digest":"x", "policy_generation":1, "freeze_generation":0,
            "graph_revision":1, "routing_generation":1, "authority_epoch":1,
            "incarnation":{"variant_id":"var_x", "attempt_id":"atm_x", "fence":2,
              "scope_revision":1, "context_revision":1}, "unknown":false
        });
        assert!(serde_json::from_value::<ClosedLeaseSubject>(nested.take()).is_err());
    }
}
