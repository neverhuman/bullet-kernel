//! Durable terminal-request invariants for the Runner recovery journal.

use super::*;
use bullet_application::lease_transport::{LeaseSettlementOutcome, LeaseSettlementRecord};
use bullet_domain::{Attempt, AttemptState};
use bullet_harness_core::launch_grant::workspace_nonce_digest;

impl RecoveryJournal {
    pub(in crate::signed_lease_rpc) fn pending_for(
        &self,
        attempt: &AttemptId,
    ) -> Option<LeaseSettlementRequest> {
        self.settlements.get(attempt.as_str()).cloned()
    }

    pub(in crate::signed_lease_rpc) fn completed_for(
        &self,
        attempt: &AttemptId,
    ) -> Option<LeaseSettlementRecord> {
        self.completed.get(attempt.as_str()).cloned()
    }

    pub(in crate::signed_lease_rpc) fn reserve_settlement(
        &mut self,
        request: LeaseSettlementRequest,
    ) -> Result<bool, RunnerError> {
        validate_source(&self.intents, &request)?;
        let slot = request_attempt(&request).to_string();
        if let Some(existing) = self.settlements.get(&slot) {
            if existing != &request {
                return Err(rpc_err(
                    "IDEMPOTENCY_CONFLICT",
                    "terminal request changed while its outcome is unresolved",
                ));
            }
            return Ok(false);
        }
        if self.settlements.len() >= MAX_SETTLEMENTS {
            return Err(rpc_err(
                "LEASE_RECOVERY_CAPACITY",
                "terminal recovery intent capacity is exhausted",
            ));
        }
        if !self.completed.contains_key(&slot) && self.completed.len() >= MAX_SETTLEMENTS {
            return Err(rpc_err(
                "LEASE_RECOVERY_CAPACITY",
                "completed settlement recovery capacity is exhausted",
            ));
        }
        self.settlements.insert(slot, request);
        self.bump_sequence()?;
        Ok(true)
    }

    pub(in crate::signed_lease_rpc) fn complete_settlement(
        &mut self,
        request: &LeaseSettlementRequest,
        record: &LeaseSettlementRecord,
    ) -> Result<(), RunnerError> {
        let slot = request_attempt(request).to_string();
        if self.settlements.get(&slot) != Some(request) {
            return Err(corrupt());
        }
        let current = self
            .intents
            .get(&slot)
            .and_then(|meta| meta.current_attempt.as_ref())
            .ok_or_else(corrupt)?;
        validate_record(request, record, current)?;
        let meta = self.intents.get_mut(&slot).ok_or_else(corrupt)?;
        let _grant = meta.grant.as_ref().ok_or_else(corrupt)?;
        let current = meta.current_attempt.as_mut().ok_or_else(corrupt)?;
        let outcome = outcome_attempt(&record.outcome);
        let mut expected = current.clone();
        expected.state = resulting_state(request);
        if expected != *outcome {
            return Err(RunnerError::Protocol(
                "settlement outcome differs from durable attempt incarnation".into(),
            ));
        }
        *current = outcome.clone();
        if matches!(request, LeaseSettlementRequest::Release(_)) {
            self.intents.remove(&slot);
        }
        self.completed.insert(slot.clone(), record.clone());
        self.settlements.remove(&slot);
        self.bump_sequence()
    }

    pub(in crate::signed_lease_rpc) fn abandon_settlement(
        &mut self,
        request: &LeaseSettlementRequest,
    ) -> Result<(), RunnerError> {
        let slot = request_attempt(request).to_string();
        if self.settlements.get(&slot) != Some(request) {
            return Err(corrupt());
        }
        self.settlements.remove(&slot);
        self.bump_sequence()
    }
}

pub(super) fn request_attempt(request: &LeaseSettlementRequest) -> &AttemptId {
    match request {
        LeaseSettlementRequest::Advance(body) => &body.attempt_id,
        LeaseSettlementRequest::Release(body) => &body.attempt_id,
    }
}

pub(super) fn validate_source(
    intents: &BTreeMap<String, AcquireMeta>,
    request: &LeaseSettlementRequest,
) -> Result<(), RunnerError> {
    let (digest, package, runner, epoch, key, variant, attempt, fence, expected) =
        request_fields(request);
    let meta = intents.get(attempt.as_str()).ok_or_else(corrupt)?;
    let grant = meta.grant.as_ref().ok_or_else(corrupt)?;
    let current = meta.current_attempt.as_ref().ok_or_else(corrupt)?;
    let coherent = digest == &meta.request_digest
        && package == &meta.body.work_package_id
        && runner == &meta.body.runner_id
        && epoch == meta.body.runner_epoch
        && key == &meta.body.idempotency_key
        && variant == &current.variant_id
        && attempt == &current.id
        && fence == current.fence
        && expected == current.state
        && super::same_incarnation(&grant.attempt, current);
    coherent.then_some(()).ok_or_else(corrupt)
}

pub(super) fn validate_completed(
    slot: &str,
    record: &LeaseSettlementRecord,
    runner: &RunnerId,
    epoch: u64,
) -> Result<(), RunnerError> {
    record.encode().map_err(|_| corrupt())?;
    let attempt = outcome_attempt(&record.outcome);
    let request = &record.request;
    if slot == request_attempt(request).as_str()
        && attempt.id.as_str() == slot
        && request_fields(request).2 == runner
        && request_fields(request).3 == epoch
        && validate_subject(attempt, &record.subject).is_ok()
    {
        Ok(())
    } else {
        Err(corrupt())
    }
}

fn validate_record(
    request: &LeaseSettlementRequest,
    record: &LeaseSettlementRecord,
    current: &Attempt,
) -> Result<(), RunnerError> {
    record
        .encode()
        .map_err(|error| RunnerError::Protocol(format!("settlement record: {error}")))?;
    let digest = request
        .digest()
        .map_err(|error| RunnerError::Protocol(error.to_string()))?;
    let id = request
        .settlement_id()
        .map_err(|error| RunnerError::Protocol(error.to_string()))?;
    if record.request == *request
        && record.request_digest == digest
        && record.settlement_id == id
        && validate_subject(current, &record.subject).is_ok()
    {
        Ok(())
    } else {
        Err(RunnerError::Protocol(
            "settlement record differs from durable request".into(),
        ))
    }
}

fn validate_subject(
    attempt: &Attempt,
    subject: &bullet_harness_core::lease_transport::LeaseSubjectClaims,
) -> Result<(), RunnerError> {
    let nonce_digest = workspace_nonce_digest(&attempt.workspace_nonce)
        .map_err(|error| RunnerError::Protocol(format!("settlement subject: {error}")))?;
    let incarnation = subject.incarnation.as_ref().ok_or_else(|| {
        RunnerError::Protocol("settlement subject has no Attempt incarnation".into())
    })?;
    let agrees = subject.workspace_id == attempt.workspace_id.as_str()
        && subject.workspace_nonce_digest == nonce_digest
        && incarnation.variant_id == attempt.variant_id.as_str()
        && incarnation.attempt_id == attempt.id.as_str()
        && incarnation.fence == attempt.fence
        && incarnation.scope_revision == attempt.scope_revision
        && incarnation.context_revision == attempt.context_revision;
    agrees.then_some(()).ok_or_else(|| {
        RunnerError::Protocol("settlement subject differs from durable Attempt incarnation".into())
    })
}

fn request_fields(
    request: &LeaseSettlementRequest,
) -> (
    &String,
    &bullet_domain::WorkPackageId,
    &RunnerId,
    u64,
    &String,
    &bullet_domain::VariantId,
    &AttemptId,
    u64,
    AttemptState,
) {
    match request {
        LeaseSettlementRequest::Advance(body) => (
            &body.acquire_request_digest,
            &body.work_package_id,
            &body.runner_id,
            body.runner_epoch,
            &body.idempotency_key,
            &body.variant_id,
            &body.attempt_id,
            body.attempt_fence,
            body.expected_state,
        ),
        LeaseSettlementRequest::Release(body) => (
            &body.acquire_request_digest,
            &body.work_package_id,
            &body.runner_id,
            body.runner_epoch,
            &body.idempotency_key,
            &body.variant_id,
            &body.attempt_id,
            body.attempt_fence,
            body.expected_state,
        ),
    }
}

fn resulting_state(request: &LeaseSettlementRequest) -> AttemptState {
    match request {
        LeaseSettlementRequest::Advance(body) => body.target_state,
        LeaseSettlementRequest::Release(body) => body.final_state,
    }
}

pub(super) fn outcome_attempt(outcome: &LeaseSettlementOutcome) -> &Attempt {
    match outcome {
        LeaseSettlementOutcome::Advanced(attempt) | LeaseSettlementOutcome::Released(attempt) => {
            attempt
        }
    }
}
