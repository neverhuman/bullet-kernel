//! Fresh selected-Variant writer authority for one synthetic effect chain.

use super::participant;
use bullet_application::lease_transport::{
    LeaseSettlementRequest, ReleaseSettlementRequest, SyntheticSelectedAcquireBody,
};
use bullet_domain::AttemptState;
use bullet_runner_core::{
    AcquireGrant, HeartbeatCall, LeaseClient, ReleaseCall, RunnerError, SignedLeaseRpcClient,
};
use std::sync::{Arc, Mutex};

const REFUSED: &str = "SYNTHETIC_EFFECT_AUTHORITY_REFUSED";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Fresh,
    Acquired,
    Active,
    Terminal,
    Unknown,
}

struct State {
    phase: Phase,
    grant: Option<AcquireGrant>,
    current: Option<AttemptState>,
    settlement: Option<LeaseSettlementRequest>,
}

/// One third logical Runner's authority, separated from the terminal author lane.
pub(super) struct EffectAuthority {
    signed: Arc<SignedLeaseRpcClient>,
    selected: SyntheticSelectedAcquireBody,
    author: AcquireGrant,
    successor_fence: u64,
    state: Mutex<State>,
}

impl EffectAuthority {
    /// Bind fresh selected authority to one already-terminal author incarnation.
    pub(super) fn new(
        signed: Arc<SignedLeaseRpcClient>,
        selected: SyntheticSelectedAcquireBody,
        author: AcquireGrant,
    ) -> Result<Self, RunnerError> {
        selected
            .validate_binding()
            .map_err(|error| refused(error.to_string()))?;
        let successor_fence = author
            .attempt
            .fence
            .checked_add(1)
            .ok_or_else(|| refused("author fence cannot produce a successor"))?;
        require_author_binding(&author, &selected)?;
        Ok(Self {
            signed,
            selected,
            author,
            successor_fence,
            state: Mutex::new(State {
                phase: Phase::Fresh,
                grant: None,
                current: None,
                settlement: None,
            }),
        })
    }

    /// Acquire the selected Variant under a distinct Runner and successor fence.
    pub(super) async fn acquire(&self) -> Result<AcquireGrant, RunnerError> {
        {
            let mut state = self.lock()?;
            if state.phase != Phase::Fresh {
                return Err(refused("effect authority can acquire only once"));
            }
            state.phase = Phase::Unknown;
        }
        let grant = match self.signed.acquire_synthetic_selected(&self.selected).await {
            Ok(grant) => grant,
            Err(error) => return Err(error),
        };
        if let Err(error) = self.validate_successor(&grant) {
            let settlement = release_request(
                &self.selected,
                &grant,
                AttemptState::Starting,
                AttemptState::Failed,
            )?;
            let cleanup = self
                .signed
                .release(&ReleaseCall {
                    attempt_id: grant.attempt.id.clone(),
                    outcome: AttemptState::Failed,
                    requeue: true,
                })
                .await;
            let mut state = self.lock()?;
            state.grant = Some(grant);
            state.settlement = Some(settlement);
            return match cleanup {
                Ok(()) => {
                    state.phase = Phase::Terminal;
                    state.current = Some(AttemptState::Failed);
                    Err(error)
                }
                Err(cleanup) => {
                    state.phase = Phase::Unknown;
                    Err(refused(format!(
                        "invalid effect grant cleanup is outcome-unknown: {error}; {cleanup}"
                    )))
                }
            };
        }
        let mut state = self.lock()?;
        state.phase = Phase::Acquired;
        state.current = Some(AttemptState::Starting);
        state.grant = Some(grant.clone());
        Ok(grant)
    }

    /// Enter the active writer state before a local effect operation starts.
    pub(super) async fn activate(&self) -> Result<(), RunnerError> {
        let grant = self.require_active_source(Phase::Acquired, AttemptState::Starting)?;
        if let Err(error) = self
            .signed
            .advance(&grant.attempt.id, AttemptState::Running)
            .await
        {
            self.mark_unknown()?;
            return Err(error);
        }
        let mut state = self.lock()?;
        state.phase = Phase::Active;
        state.current = Some(AttemptState::Running);
        Ok(())
    }

    /// Renew only the exact active effect lease.
    pub(super) async fn heartbeat(&self) -> Result<(), RunnerError> {
        let grant = self.require_active_source(Phase::Active, AttemptState::Running)?;
        let call = HeartbeatCall::for_grant(&grant)?;
        if let Err(error) = self.signed.heartbeat(&call).await {
            self.mark_unknown()?;
            return Err(error);
        }
        Ok(())
    }

    /// Close a pre-effect or failed effect path without leaving authority active.
    pub(super) async fn cleanup_failed(&self) -> Result<(), RunnerError> {
        self.release(AttemptState::Failed).await
    }

    /// Close a completed local effect path as superseded and requeue it.
    pub(super) async fn settle_superseded(&self) -> Result<(), RunnerError> {
        self.release(AttemptState::Superseded).await
    }

    /// Return the exact active grant only after acquisition validation.
    pub(super) fn grant(&self) -> Result<AcquireGrant, RunnerError> {
        let state = self.lock()?;
        if !matches!(state.phase, Phase::Acquired | Phase::Active) {
            return Err(refused("effect authority grant is not active"));
        }
        let mut grant = state
            .grant
            .clone()
            .ok_or_else(|| refused("effect authority active grant is absent"))?;
        if super::fault::effect_grant_readback_error() {
            return Err(refused(
                "SYNTHETIC_DOGFOOD_FAULT_EFFECT_GRANT_READBACK_ERROR",
            ));
        }
        if super::fault::effect_grant_changed() {
            grant.attempt.runner_epoch = grant.attempt.runner_epoch.saturating_add(1);
        }
        Ok(grant)
    }

    /// Return a known terminal request; `UNKNOWN` is intentionally not readable as settled.
    pub(super) fn settlement_request(&self) -> Result<LeaseSettlementRequest, RunnerError> {
        let state = self.lock()?;
        if state.phase != Phase::Terminal {
            return Err(refused("effect authority settlement outcome is unknown"));
        }
        state
            .settlement
            .clone()
            .ok_or_else(|| refused("effect authority terminal settlement is absent"))
    }

    async fn release(&self, final_state: AttemptState) -> Result<(), RunnerError> {
        let (grant, expected_state) = {
            let state = self.lock()?;
            if !matches!(state.phase, Phase::Acquired | Phase::Active) {
                return Err(refused(
                    "effect authority cleanup requires acquired authority",
                ));
            }
            let grant = state
                .grant
                .clone()
                .ok_or_else(|| refused("effect authority cleanup grant is absent"))?;
            let expected_state = state
                .current
                .ok_or_else(|| refused("effect authority cleanup state is absent"))?;
            expected_state
                .transition(final_state)
                .map_err(|_| refused("effect authority terminal transition is illegal"))?;
            (grant, expected_state)
        };
        let settlement = release_request(&self.selected, &grant, expected_state, final_state)?;
        let call = ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: final_state,
            requeue: true,
        };
        let result = self.signed.release(&call).await;
        let mut state = self.lock()?;
        state.settlement = Some(settlement);
        match result {
            Ok(()) => {
                state.phase = Phase::Terminal;
                state.current = Some(final_state);
                Ok(())
            }
            Err(error) => {
                state.phase = Phase::Unknown;
                Err(error)
            }
        }
    }

    fn validate_successor(&self, grant: &AcquireGrant) -> Result<(), RunnerError> {
        participant::validate_grant(&self.selected, grant, self.successor_fence)?;
        let distinct = grant.attempt.id != self.author.attempt.id
            && grant.attempt.runner_id != self.author.attempt.runner_id
            && grant.attempt.workspace_id != self.author.attempt.workspace_id
            && grant.attempt.workspace_nonce != self.author.attempt.workspace_nonce
            && grant.authority_token != self.author.authority_token
            && grant.authority_token.attempt_id != self.author.authority_token.attempt_id
            && grant.authority_token.workspace_id != self.author.authority_token.workspace_id
            && grant.authority_token.workspace_nonce != self.author.authority_token.workspace_nonce
            && grant.attempt.fence == self.successor_fence;
        distinct
            .then_some(())
            .ok_or_else(|| refused("effect grant reuses terminal author authority"))
    }

    fn require_active_source(
        &self,
        phase: Phase,
        current: AttemptState,
    ) -> Result<AcquireGrant, RunnerError> {
        let state = self.lock()?;
        if state.phase != phase || state.current != Some(current) {
            return Err(refused("effect authority state differs from operation"));
        }
        state
            .grant
            .clone()
            .ok_or_else(|| refused("effect authority operation grant is absent"))
    }

    fn mark_unknown(&self) -> Result<(), RunnerError> {
        self.lock()?.phase = Phase::Unknown;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, RunnerError> {
        self.state
            .lock()
            .map_err(|_| refused("effect authority state is poisoned"))
    }
}

fn require_author_binding(
    author: &AcquireGrant,
    selected: &SyntheticSelectedAcquireBody,
) -> Result<(), RunnerError> {
    let inner = selected.inner();
    let terminal = author.attempt.state == AttemptState::Superseded;
    let distinct_runner = author.attempt.runner_id != inner.runner_id;
    let exact_selected = author.attempt.variant_id == *selected.selected_variant_id()
        && author.attempt.work_package_id == inner.work_package_id
        && author.authority_token.variant_id == author.attempt.variant_id
        && author.authority_token.attempt_id == author.attempt.id
        && author.authority_token.attempt_fence == author.attempt.fence
        && author.authority_token.runner_id == author.attempt.runner_id
        && author.authority_token.runner_epoch == author.attempt.runner_epoch
        && author.authority_token.workspace_id == author.attempt.workspace_id
        && author.authority_token.workspace_nonce == author.attempt.workspace_nonce;
    (terminal && distinct_runner && exact_selected)
        .then_some(())
        .ok_or_else(|| refused("effect authority rejects nonterminal or rebound author token"))
}

fn release_request(
    selected: &SyntheticSelectedAcquireBody,
    grant: &AcquireGrant,
    expected_state: AttemptState,
    final_state: AttemptState,
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
        requeue: true,
    }))
}

fn refused(message: impl Into<String>) -> RunnerError {
    RunnerError::Lease {
        code: REFUSED.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::{
        materialize_synthetic_selection, LeaseRequest, LeaseService, Ledger, MemoryLedger,
        PlanInput,
    };
    use bullet_domain::{Digest, RunnerId, TaskClass, WorkspaceId};
    use bullet_runner_core::ExpectedLeaseServer;
    use std::sync::Arc;

    fn fixture() -> (
        Arc<SignedLeaseRpcClient>,
        SyntheticSelectedAcquireBody,
        AcquireGrant,
    ) {
        let mut ledger = MemoryLedger::new();
        let now = ledger.simulation_time();
        let graph = materialize_synthetic_selection(
            &mut ledger,
            "effect-authority-hostile",
            &PlanInput {
                title: "effect authority hostile".into(),
                objective: "bind a distinct successor writer".into(),
                packages: vec![("one".into(), TaskClass::BoundedBugFix)],
            },
            &now,
        )
        .expect("graph");
        let author_runner = RunnerId::from_seed("effect-authority-author");
        let author_key = "effect-authority-author-key";
        let acquired = ledger
            .acquire_lease(&LeaseRequest {
                idempotency_key: author_key.into(),
                mission_id: graph.mission.id.clone(),
                variant_id: graph.variants[0].id.clone(),
                attempt_seed: author_key.into(),
                runner_id: author_runner,
                runner_epoch: 1,
                workspace_id: WorkspaceId::from_seed(author_key),
                workspace_nonce: *Digest::of(author_key.as_bytes()).as_bytes(),
                scope_revision: 1,
                context_revision: 1,
                ttl_seconds: 9,
            })
            .expect("author grant");
        let mut author = AcquireGrant {
            authority_token: LeaseService::token_for(&graph, &acquired.attempt)
                .expect("author token"),
            attempt: acquired.attempt,
            lease: acquired.lease,
        };
        author.attempt.state = AttemptState::Superseded;
        let selected = SyntheticSelectedAcquireBody::new(
            Digest::of(b"effect-authority-selection"),
            graph.packages[0].id.clone(),
            RunnerId::from_seed("effect-authority-runner"),
            2,
            graph.variants[0].id.clone(),
            9,
        )
        .expect("selected request");
        let root = tempfile::tempdir().expect("root");
        let signed = Arc::new(SignedLeaseRpcClient::new_admitted(
            root.path().join("absent.sock"),
            selected.inner().runner_id.clone(),
            selected.inner().runner_epoch,
            ExpectedLeaseServer::new(0, 0),
        ));
        (signed, selected, author)
    }

    #[test]
    fn terminal_author_requires_a_distinct_effect_runner() {
        let (signed, selected, author) = fixture();
        EffectAuthority::new(signed, selected, author).expect("terminal distinct author");
    }

    #[test]
    fn nonterminal_author_refuses_before_socket() {
        let (signed, selected, mut author) = fixture();
        author.attempt.state = AttemptState::Starting;
        let error = EffectAuthority::new(signed, selected, author)
            .err()
            .expect("nonterminal author");
        assert_eq!(lease_code(&error), REFUSED);
    }

    #[test]
    fn author_runner_rebinding_refuses_before_socket() {
        let (signed, selected, mut author) = fixture();
        author.attempt.runner_id = selected.inner().runner_id.clone();
        author.authority_token.runner_id = selected.inner().runner_id.clone();
        let error = EffectAuthority::new(signed, selected, author)
            .err()
            .expect("rebound author");
        assert_eq!(lease_code(&error), REFUSED);
    }

    fn lease_code(error: &RunnerError) -> &str {
        match error {
            RunnerError::Lease { code, .. } => code,
            other => panic!("expected lease refusal, found {other}"),
        }
    }
}
