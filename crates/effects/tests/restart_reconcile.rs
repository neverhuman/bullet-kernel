use bullet_application::{
    EffectIntentRecord, EffectRecoveryAuthority, EffectRecoveryClaim,
    EffectRecoveryContainmentReason, EffectRecoveryDisposition, EffectRecoveryError,
    EffectRecoveryStore, EffectRecoveryTransition, EffectState, CANDIDATE_REF_PREFIX,
    EFFECT_RECOVERY_CLAIM_SCHEMA, LOCAL_BARE_RECOVERY_PROVIDER, ZERO_OID,
};
use bullet_domain::{
    AcceptanceContractId, AttemptId, AuthorityToken, CandidateId, Digest, EffectId, MissionId,
    OrganizationId, PlanRevisionId, RepositoryId, RunnerId, SelectionGroupId, VariantId,
    WorkPackageId, WorkspaceId,
};
use bullet_effects_core::{
    reconcile_local_bare_restart, EffectsError, ForgeDescriptor, ForgeEffects, PushRequest,
    RestartReconcileOutcome,
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    path::Path,
};

fn authority() -> EffectRecoveryAuthority {
    let token = AuthorityToken {
        organization_id: OrganizationId::from_seed("recovery-org"),
        repository_id: RepositoryId::from_seed("recovery-repo"),
        mission_id: MissionId::from_seed("recovery-mission"),
        acceptance_contract_id: AcceptanceContractId::from_seed("recovery-contract"),
        plan_revision_id: PlanRevisionId::from_seed("recovery-plan"),
        graph_sequence: 9,
        work_package_id: WorkPackageId::from_seed("recovery-package"),
        selection_group_id: SelectionGroupId::from_seed("recovery-selection"),
        variant_id: VariantId::from_seed("recovery-variant"),
        attempt_id: AttemptId::from_seed("recovery-attempt"),
        attempt_fence: 2,
        runner_id: RunnerId::from_seed("recovery-runner"),
        runner_epoch: 2,
        workspace_id: WorkspaceId::from_seed("recovery-workspace"),
        workspace_nonce: [2; 32],
        scope_revision: 1,
        context_revision: 1,
        config_snapshot_hash: Digest::of(b"recovery-config"),
        policy_snapshot_hash: Digest::of(b"recovery-policy"),
        routing_policy_hash: Digest::of(b"recovery-routing"),
        credential_profile_id: None,
        credential_generation: None,
    };
    EffectRecoveryAuthority::from_token(&token, 7, 3, 2).expect("authority")
}

fn claimed() -> EffectRecoveryClaim {
    let authority = authority();
    let candidate = CandidateId::from_seed("recovery-candidate");
    let mut intent = EffectIntentRecord {
        id: EffectId::from_seed("recovery-effect"),
        logical_effect_key: format!("push:{candidate}"),
        provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
        target_identity: format!("{CANDIDATE_REF_PREFIX}{candidate}"),
        desired_state_hash: "b".repeat(40),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: AttemptId::from_seed("original-attempt"),
        fence: 1,
        policy_version: "policy-v1".into(),
        payload_hash: String::new(),
        provider_idempotency_key: None,
        state: EffectState::OutcomeUnknown,
        unknown_retries: 0,
        created_at: "2026-08-28T03:00:00Z".into(),
    };
    intent.payload_hash = intent.payload_digest().expect("payload digest");
    EffectRecoveryClaim {
        schema_version: EFFECT_RECOVERY_CLAIM_SCHEMA.into(),
        claim_id: format!("ecl_{}", "a".repeat(64)),
        original_attempt_id: intent.attempt_id.clone(),
        original_fence: intent.fence,
        intent_payload_digest: intent.stable_payload_digest().expect("stable digest"),
        successor_authority_digest: authority.successor_authority_digest,
        successor_authority_fingerprint: authority.fingerprint().expect("fingerprint"),
        recovery_runner_id: authority.runner_id.clone(),
        recovery_runner_epoch: authority.runner_epoch,
        recovery_attempt_id: authority.attempt_id.clone(),
        recovery_attempt_fence: authority.attempt_fence,
        recovery_variant_id: authority.variant_id.clone(),
        recovery_workspace_id: authority.workspace_id.clone(),
        recovery_workspace_nonce: authority.workspace_nonce,
        authority_epoch: authority.authority_epoch,
        freeze_generation: authority.freeze_generation,
        restore_epoch: authority.restore_epoch,
        claim_generation: 1,
        outbox_sequence: 41,
        disposition: EffectRecoveryDisposition::Claimed,
        invalidated_from: None,
        claimed_at: "2026-08-28T03:01:00Z".into(),
        updated_at: "2026-08-28T03:01:00Z".into(),
        intent,
    }
}

fn reserved() -> EffectRecoveryClaim {
    let mut claim = claimed();
    claim.disposition = EffectRecoveryDisposition::RetryReserved;
    claim.intent.state = EffectState::Dispatching;
    claim.intent.unknown_retries = 1;
    claim.validate().expect("reserved claim");
    claim
}

fn unknown(retries: u32) -> EffectRecoveryClaim {
    let mut claim = claimed();
    claim.disposition = EffectRecoveryDisposition::ReadbackUnknown;
    claim.intent.unknown_retries = retries;
    claim.validate().expect("unknown claim");
    claim
}

struct Store {
    claim: Option<EffectRecoveryClaim>,
    recheck: Option<EffectRecoveryClaim>,
    stale: bool,
    transitions: Vec<EffectRecoveryTransition>,
    readback_calls: usize,
}

impl Store {
    fn active(claim: EffectRecoveryClaim) -> Self {
        Self {
            claim: Some(claim),
            recheck: None,
            stale: false,
            transitions: Vec::new(),
            readback_calls: 0,
        }
    }
}

impl EffectRecoveryStore for Store {
    fn claim_effect_recovery(
        &mut self,
        _intent_id: &EffectId,
        _authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
        if self.stale {
            return Err(EffectRecoveryError::StaleAuthority("dead owner".into()));
        }
        Ok(self.claim.clone())
    }

    fn readback_effect_recovery(
        &self,
        _intent_id: &EffectId,
        _authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
        Ok(self.recheck.clone().or_else(|| self.claim.clone()))
    }

    fn apply_effect_recovery(
        &mut self,
        request: &EffectRecoveryTransition,
        authority: &EffectRecoveryAuthority,
    ) -> Result<EffectRecoveryClaim, EffectRecoveryError> {
        self.readback_calls += 1;
        let current = self
            .claim
            .as_ref()
            .ok_or(EffectRecoveryError::UnknownClaim)?;
        request.validate_for(current, authority)?;
        let mut next = current.clone();
        next.disposition = request.to;
        match request.to {
            EffectRecoveryDisposition::RetryReserved => {
                next.intent.state = EffectState::Dispatching;
                next.intent.unknown_retries += 1;
            }
            EffectRecoveryDisposition::ReadbackUnknown => {
                next.intent.state = EffectState::OutcomeUnknown
            }
            EffectRecoveryDisposition::Adopted => next.intent.state = EffectState::Committed,
            EffectRecoveryDisposition::Orphaned => next.intent.state = EffectState::OrphanedRemote,
            EffectRecoveryDisposition::Quarantined => next.intent.state = EffectState::Quarantined,
            _ => {
                return Err(EffectRecoveryError::InvalidTransition {
                    from: current.disposition.as_str().into(),
                    to: request.to.as_str().into(),
                })
            }
        }
        next.validate()?;
        self.transitions.push(request.clone());
        self.claim = Some(next.clone());
        Ok(next)
    }
}

struct Forge {
    reads: RefCell<VecDeque<Result<Option<String>, EffectsError>>>,
    pushes: VecDeque<Result<(), EffectsError>>,
    requests: Vec<PushRequest>,
    descriptor: ForgeDescriptor,
    descriptor_calls: Cell<usize>,
}

impl Forge {
    fn scripted(reads: impl IntoIterator<Item = Result<Option<String>, EffectsError>>) -> Self {
        Self {
            reads: RefCell::new(reads.into_iter().collect()),
            pushes: VecDeque::from([Ok(())]),
            requests: Vec::new(),
            descriptor: ForgeDescriptor {
                provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
                authenticated: true,
                can_push_candidate_ref: true,
                notes: "scripted local bare".into(),
            },
            descriptor_calls: Cell::new(0),
        }
    }
}

impl ForgeEffects for Forge {
    fn descriptor(&self) -> ForgeDescriptor {
        self.descriptor_calls.set(self.descriptor_calls.get() + 1);
        self.descriptor.clone()
    }

    fn push_candidate_ref(&mut self, request: &PushRequest) -> Result<(), EffectsError> {
        self.requests.push(request.clone());
        self.pushes.pop_front().expect("scripted push")
    }

    fn read_ref(&self, _ref_name: &str) -> Result<Option<String>, EffectsError> {
        self.reads.borrow_mut().pop_front().expect("scripted read")
    }
}

fn run(store: &mut Store, forge: &mut Forge) -> Result<RestartReconcileOutcome, String> {
    let authority = authority();
    let intent_id = claimed().intent.id;
    reconcile_local_bare_restart(
        store,
        forge,
        &intent_id,
        &authority,
        Path::new("/workspace"),
    )
    .map_err(|error| error.to_string())
}

#[test]
fn desired_readback_adopts_with_application_owned_deterministic_receipt() {
    let mut store = Store::active(claimed());
    let mut forge = Forge::scripted([Ok(Some("b".repeat(40)))]);
    assert_eq!(
        run(&mut store, &mut forge),
        Ok(RestartReconcileOutcome::Adopted)
    );
    let terminal = store.claim.expect("adopted claim");
    terminal.validate().expect("terminal validates");
    let request = store.transitions.first().expect("adopt transition");
    let observation = request.observation.as_ref().expect("observation");
    assert_eq!(
        request.receipt_id,
        Some(observation.receipt_id(&terminal.intent).expect("receipt"))
    );
    assert!(forge.requests.is_empty());
}

#[test]
fn third_oid_is_orphaned_without_push() {
    let mut store = Store::active(claimed());
    let mut forge = Forge::scripted([Ok(Some("c".repeat(40)))]);
    assert_eq!(
        run(&mut store, &mut forge),
        Ok(RestartReconcileOutcome::OrphanedRemote)
    );
    store
        .claim
        .expect("orphaned claim")
        .validate()
        .expect("terminal validates");
    assert_eq!(store.transitions[0].to, EffectRecoveryDisposition::Orphaned);
    assert!(forge.requests.is_empty());
}

#[test]
fn absence_reserves_once_then_pushes_create_only_and_adopts() {
    let mut store = Store::active(claimed());
    let mut forge = Forge::scripted([Ok(None), Ok(Some("b".repeat(40)))]);
    assert_eq!(
        run(&mut store, &mut forge),
        Ok(RestartReconcileOutcome::Adopted)
    );
    store
        .claim
        .expect("adopted claim")
        .validate()
        .expect("terminal validates");
    assert_eq!(
        store
            .transitions
            .iter()
            .map(|transition| transition.to)
            .collect::<Vec<_>>(),
        [
            EffectRecoveryDisposition::RetryReserved,
            EffectRecoveryDisposition::ReadbackUnknown,
            EffectRecoveryDisposition::Adopted,
        ]
    );
    assert_eq!(forge.requests.len(), 1);
    assert_eq!(forge.requests[0].expected_old_oid, ZERO_OID);
}

#[test]
fn reserved_retry_restart_reuses_reservation_without_incrementing() {
    let mut store = Store::active(reserved());
    let mut forge = Forge::scripted([Ok(None), Ok(Some("b".repeat(40)))]);
    assert_eq!(
        run(&mut store, &mut forge),
        Ok(RestartReconcileOutcome::Adopted)
    );
    store
        .claim
        .expect("adopted claim")
        .validate()
        .expect("terminal validates");
    assert_eq!(
        store
            .transitions
            .iter()
            .map(|transition| transition.to)
            .collect::<Vec<_>>(),
        [
            EffectRecoveryDisposition::ReadbackUnknown,
            EffectRecoveryDisposition::Adopted
        ]
    );
    assert_eq!(forge.requests.len(), 1);
}

#[test]
fn first_readback_failure_is_unknown_without_a_push() {
    let mut store = Store::active(claimed());
    let mut forge = Forge::scripted([Err(EffectsError::Io("read failure".into()))]);
    assert_eq!(
        run(&mut store, &mut forge),
        Ok(RestartReconcileOutcome::ReadbackUnknown)
    );
    assert_eq!(
        store.transitions[0].to,
        EffectRecoveryDisposition::ReadbackUnknown
    );
    assert!(forge.requests.is_empty());
}

#[test]
fn second_readback_failure_and_spent_absence_quarantine_without_push() {
    let mut unavailable = Store::active(unknown(0));
    let mut unavailable_forge = Forge::scripted([Err(EffectsError::Io("read failure".into()))]);
    assert_eq!(
        run(&mut unavailable, &mut unavailable_forge),
        Ok(RestartReconcileOutcome::Quarantined)
    );
    unavailable
        .claim
        .expect("quarantined claim")
        .validate()
        .expect("terminal validates");
    assert_eq!(
        unavailable.transitions[0].containment_reason,
        Some(EffectRecoveryContainmentReason::ReadbackUnavailable)
    );
    assert!(unavailable_forge.requests.is_empty());

    let mut spent = Store::active(unknown(1));
    let mut spent_forge = Forge::scripted([Ok(None)]);
    assert_eq!(
        run(&mut spent, &mut spent_forge),
        Ok(RestartReconcileOutcome::Quarantined)
    );
    spent
        .claim
        .expect("quarantined claim")
        .validate()
        .expect("terminal validates");
    assert_eq!(
        spent.transitions[0].containment_reason,
        Some(EffectRecoveryContainmentReason::RetrySpentAfterAbsence)
    );
    assert!(spent_forge.requests.is_empty());
}

#[test]
fn stale_owner_refusal_performs_zero_forge_operations() {
    let mut store = Store::active(claimed());
    store.stale = true;
    let mut forge = Forge::scripted([]);
    assert!(run(&mut store, &mut forge).is_err());
    assert!(forge.requests.is_empty());
    assert!(forge.reads.borrow().is_empty());
    assert_eq!(forge.descriptor_calls.get(), 0);
}

#[test]
fn non_local_or_unready_forge_refuses_before_readback_or_transition() {
    for descriptor in [
        ForgeDescriptor {
            provider: "other".into(),
            authenticated: true,
            can_push_candidate_ref: true,
            notes: "wrong provider".into(),
        },
        ForgeDescriptor {
            provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
            authenticated: false,
            can_push_candidate_ref: true,
            notes: "unauthenticated".into(),
        },
        ForgeDescriptor {
            provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
            authenticated: true,
            can_push_candidate_ref: false,
            notes: "incapable".into(),
        },
    ] {
        let mut store = Store::active(claimed());
        let mut forge = Forge::scripted([]);
        forge.descriptor = descriptor;
        assert!(run(&mut store, &mut forge).is_err());
        assert!(forge.reads.borrow().is_empty());
        assert!(forge.requests.is_empty());
        assert!(store.transitions.is_empty());
        assert_eq!(forge.descriptor_calls.get(), 1);
    }
}

#[test]
fn superseded_reserved_claim_refuses_before_push() {
    let mut store = Store::active(reserved());
    let mut replacement = reserved();
    replacement.claim_id = format!("ecl_{}", "d".repeat(64));
    replacement.claim_generation = 2;
    replacement.validate().expect("replacement shape");
    store.recheck = Some(replacement);
    let mut forge = Forge::scripted([Ok(None)]);
    assert!(run(&mut store, &mut forge).is_err());
    assert!(forge.requests.is_empty());
    assert_eq!(forge.descriptor_calls.get(), 1);
}

#[test]
fn rejected_push_is_unknown_until_a_fresh_readback_orphans() {
    let mut store = Store::active(reserved());
    let mut rejected = Forge::scripted([Ok(None)]);
    rejected.pushes = VecDeque::from([Err(EffectsError::PushRejected {
        ref_name: claimed().intent.target_identity,
        observed: Some("c".repeat(40)),
    })]);
    assert_eq!(
        run(&mut store, &mut rejected),
        Ok(RestartReconcileOutcome::ReadbackUnknown)
    );
    assert_eq!(
        store.claim.as_ref().expect("unknown").disposition,
        EffectRecoveryDisposition::ReadbackUnknown
    );

    let mut readback = Forge::scripted([Ok(Some("c".repeat(40)))]);
    assert_eq!(
        run(&mut store, &mut readback),
        Ok(RestartReconcileOutcome::OrphanedRemote)
    );
    store
        .claim
        .expect("orphaned claim")
        .validate()
        .expect("terminal validates");
    assert!(readback.requests.is_empty());
}
