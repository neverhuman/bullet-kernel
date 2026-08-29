//! One exact selected-Variant participant over the accepted signed UDS client.

use bullet_application::lease_transport::{
    LeaseSettlementRequest, ReleaseSettlementRequest, SyntheticSelectedAcquireBody,
};
use bullet_domain::{AttemptId, AttemptState};
use bullet_runner_core::lease::{
    AcquireGrant, AcquireRequest, HeartbeatCall, LeaseClient, ReadyView, ReleaseCall,
};
use bullet_runner_core::{CandidatePreparationRpcClient, RunnerError, SignedLeaseRpcClient};
use std::sync::{Arc, Mutex};
use std::{future::Future, pin::Pin};

const PARTICIPANT_REFUSED: &str = "SYNTHETIC_PARTICIPANT_REFUSED";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Fresh,
    Priming,
    Primed,
    Running,
    Terminal,
    Unknown,
}

struct State {
    phase: Phase,
    grant: Option<AcquireGrant>,
    current: Option<AttemptState>,
    settlement: Option<LeaseSettlementRequest>,
}

pub(super) struct SelectionParticipantClient {
    signed: Arc<SignedLeaseRpcClient>,
    selected: SyntheticSelectedAcquireBody,
    state: Mutex<State>,
}

impl SelectionParticipantClient {
    pub(super) fn new(
        signed: Arc<SignedLeaseRpcClient>,
        selected: SyntheticSelectedAcquireBody,
    ) -> Result<Self, RunnerError> {
        selected
            .validate_binding()
            .map_err(|error| refused(error.to_string()))?;
        Ok(Self {
            signed,
            selected,
            state: Mutex::new(State {
                phase: Phase::Fresh,
                grant: None,
                current: None,
                settlement: None,
            }),
        })
    }

    pub(super) async fn pre_acquire(&self) -> Result<AcquireGrant, RunnerError> {
        {
            let mut state = self.lock()?;
            if state.phase != Phase::Fresh {
                return Err(refused("selected participant can be primed only once"));
            }
            state.phase = Phase::Priming;
        }
        let grant = match self.signed.acquire_synthetic_selected(&self.selected).await {
            Ok(grant) => grant,
            Err(error) => {
                self.lock()?.phase = Phase::Unknown;
                return Err(error);
            }
        };
        if let Err(error) = validate_grant(&self.selected, &grant, 1) {
            let cleanup = self
                .signed
                .release(&ReleaseCall {
                    attempt_id: grant.attempt.id.clone(),
                    outcome: AttemptState::Failed,
                    requeue: true,
                })
                .await;
            self.lock()?.phase = Phase::Unknown;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(refused(format!(
                    "{error}; mismatched selected grant cleanup is unknown: {cleanup}"
                ))),
            };
        }
        let mut state = self.lock()?;
        state.phase = Phase::Primed;
        state.current = Some(grant.attempt.state);
        state.grant = Some(grant.clone());
        Ok(grant)
    }

    pub(super) async fn abort_primed_failed(&self) -> Result<(), RunnerError> {
        let (call, request) = {
            let state = self.lock()?;
            let grant = state
                .grant
                .as_ref()
                .ok_or_else(|| refused("primed abort has no selected grant"))?;
            if state.phase != Phase::Primed || state.current != Some(AttemptState::Starting) {
                return Err(refused("primed abort requires exact Starting grant"));
            }
            let call = ReleaseCall {
                attempt_id: grant.attempt.id.clone(),
                outcome: AttemptState::Failed,
                requeue: true,
            };
            let request = release_request(
                &self.selected,
                grant,
                AttemptState::Starting,
                AttemptState::Failed,
                true,
            )?;
            (call, request)
        };
        let result = self.signed.release(&call).await;
        let mut state = self.lock()?;
        state.settlement = Some(request);
        match result {
            Ok(()) => {
                state.phase = Phase::Terminal;
                state.current = Some(AttemptState::Failed);
                Ok(())
            }
            Err(error) => {
                state.phase = Phase::Unknown;
                Err(error)
            }
        }
    }

    pub(super) fn settlement_request(&self) -> Result<LeaseSettlementRequest, RunnerError> {
        self.lock()?
            .settlement
            .clone()
            .ok_or_else(|| refused("successful terminal settlement is absent"))
    }

    pub(super) fn grant(&self) -> Result<AcquireGrant, RunnerError> {
        self.lock()?
            .grant
            .clone()
            .ok_or_else(|| refused("selected grant is absent"))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, RunnerError> {
        self.state
            .lock()
            .map_err(|_| refused("selected participant state is poisoned"))
    }
}

impl LeaseClient for SelectionParticipantClient {
    fn candidate_preparation_rpc(&self) -> Option<&dyn CandidatePreparationRpcClient> {
        self.signed.candidate_preparation_rpc()
    }

    fn acquire<'life0, 'life1, 'async_trait>(
        &'life0 self,
        request: &'life1 AcquireRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AcquireGrant, RunnerError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            require_request(self.selected.inner(), request)?;
            let mut state = self.lock()?;
            if state.phase != Phase::Primed {
                return Err(refused("run_attempt acquire requires one primed grant"));
            }
            let grant = state
                .grant
                .clone()
                .ok_or_else(|| refused("primed selected grant is absent"))?;
            state.phase = Phase::Running;
            Ok(grant)
        })
    }

    fn heartbeat<'life0, 'life1, 'async_trait>(
        &'life0 self,
        call: &'life1 HeartbeatCall,
    ) -> Pin<Box<dyn Future<Output = Result<(), RunnerError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let grant = self
                .lock()?
                .grant
                .clone()
                .ok_or_else(|| refused("heartbeat has no selected grant"))?;
            let exact = call.variant_id == grant.lease.variant_id
                && call.attempt_id == grant.attempt.id
                && call.fence == grant.attempt.fence
                && call.runner_id == grant.attempt.runner_id
                && call.runner_epoch == grant.attempt.runner_epoch
                && call.workspace_nonce == grant.attempt.workspace_nonce
                && call.ttl_seconds == grant.lease.ttl_seconds;
            if !exact {
                return Err(refused("heartbeat differs from selected grant"));
            }
            self.signed.heartbeat(call).await
        })
    }

    fn advance<'life0, 'life1, 'async_trait>(
        &'life0 self,
        attempt_id: &'life1 AttemptId,
        state: AttemptState,
    ) -> Pin<Box<dyn Future<Output = Result<(), RunnerError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let current = {
                let locked = self.lock()?;
                let grant = locked
                    .grant
                    .as_ref()
                    .ok_or_else(|| refused("advance has no selected grant"))?;
                if attempt_id != &grant.attempt.id || locked.phase != Phase::Running {
                    return Err(refused("advance differs from active selected Attempt"));
                }
                locked
                    .current
                    .ok_or_else(|| refused("selected Attempt state is absent"))?
            };
            current
                .transition(state)
                .map_err(|_| refused("selected Attempt transition is illegal"))?;
            self.signed.advance(attempt_id, state).await?;
            self.lock()?.current = Some(state);
            Ok(())
        })
    }

    fn release<'life0, 'life1, 'async_trait>(
        &'life0 self,
        call: &'life1 ReleaseCall,
    ) -> Pin<Box<dyn Future<Output = Result<(), RunnerError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let (mapped, settlement) = {
                let locked = self.lock()?;
                let grant = locked
                    .grant
                    .as_ref()
                    .ok_or_else(|| refused("release has no selected grant"))?;
                if call.attempt_id != grant.attempt.id || locked.phase != Phase::Running {
                    return Err(refused("release differs from active selected Attempt"));
                }
                let current = locked
                    .current
                    .ok_or_else(|| refused("selected Attempt state is absent"))?;
                if call.outcome == AttemptState::Succeeded && !call.requeue {
                    if current != AttemptState::Preparing {
                        return Err(refused("success release requires Preparing"));
                    }
                    let mapped = ReleaseCall {
                        attempt_id: call.attempt_id.clone(),
                        outcome: AttemptState::Superseded,
                        requeue: true,
                    };
                    let request = release_request(
                        &self.selected,
                        grant,
                        current,
                        AttemptState::Superseded,
                        true,
                    )?;
                    (mapped, Some(request))
                } else if call.outcome == AttemptState::Failed && call.requeue {
                    (call.clone(), None)
                } else {
                    return Err(refused(
                        "terminal shape is not admitted for synthetic participant",
                    ));
                }
            };
            let result = self.signed.release(&mapped).await;
            let mut locked = self.lock()?;
            match result {
                Ok(()) => {
                    locked.phase = Phase::Terminal;
                    locked.current = Some(mapped.outcome);
                    locked.settlement = settlement;
                    Ok(())
                }
                Err(error) => {
                    locked.phase = Phase::Unknown;
                    locked.settlement = settlement;
                    Err(error)
                }
            }
        })
    }

    fn next_ready<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ReadyView>, RunnerError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.signed.next_ready().await })
    }
}

fn require_request(
    inner: &bullet_application::lease_transport::SignedAcquireBody,
    request: &AcquireRequest,
) -> Result<(), RunnerError> {
    let exact = request.work_package_id == inner.work_package_id
        && request.runner_id == inner.runner_id
        && request.runner_epoch == inner.runner_epoch
        && request.idempotency_key == inner.idempotency_key
        && request.ttl_seconds == inner.ttl_seconds;
    exact
        .then_some(())
        .ok_or_else(|| refused("run_attempt acquire differs from closed selected body"))
}

pub(super) fn validate_grant(
    selected: &SyntheticSelectedAcquireBody,
    grant: &AcquireGrant,
    expected_fence: u64,
) -> Result<(), RunnerError> {
    let inner = selected.inner();
    let attempt = &grant.attempt;
    let lease = &grant.lease;
    let token = &grant.authority_token;
    let exact = attempt.id == AttemptId::from_seed(&inner.idempotency_key)
        && attempt.variant_id == *selected.selected_variant_id()
        && attempt.work_package_id == inner.work_package_id
        && attempt.runner_id == inner.runner_id
        && attempt.runner_epoch == inner.runner_epoch
        && attempt.fence == expected_fence
        && attempt.scope_revision == 1
        && attempt.context_revision == 1
        && attempt.state == AttemptState::Starting
        && lease.variant_id == attempt.variant_id
        && lease.attempt_id == attempt.id
        && lease.fence == attempt.fence
        && lease.runner_id == attempt.runner_id
        && lease.runner_epoch == attempt.runner_epoch
        && lease.workspace_nonce == attempt.workspace_nonce
        && token.variant_id == attempt.variant_id
        && token.attempt_id == attempt.id
        && token.attempt_fence == attempt.fence
        && token.runner_id == attempt.runner_id
        && token.runner_epoch == attempt.runner_epoch
        && token.workspace_id == attempt.workspace_id
        && token.workspace_nonce == attempt.workspace_nonce
        && attempt.variant_id == *selected.selected_variant_id();
    exact
        .then_some(())
        .ok_or_else(|| refused("selected grant differs from expected fresh Attempt"))
}

fn release_request(
    selected: &SyntheticSelectedAcquireBody,
    grant: &AcquireGrant,
    expected_state: AttemptState,
    final_state: AttemptState,
    requeue: bool,
) -> Result<LeaseSettlementRequest, RunnerError> {
    let inner = selected.inner();
    Ok(LeaseSettlementRequest::Release(ReleaseSettlementRequest {
        acquire_request_digest: inner
            .request_digest()
            .map_err(|error| refused(error.to_string()))?,
        work_package_id: inner.work_package_id.clone(),
        runner_id: inner.runner_id.clone(),
        runner_epoch: inner.runner_epoch,
        idempotency_key: inner.idempotency_key.clone(),
        variant_id: grant.attempt.variant_id.clone(),
        attempt_id: grant.attempt.id.clone(),
        attempt_fence: grant.attempt.fence,
        expected_state,
        final_state,
        requeue,
    }))
}

fn refused(message: impl Into<String>) -> RunnerError {
    RunnerError::Lease {
        code: PARTICIPANT_REFUSED.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
