//! Invariants A1–A7, W1–W3, and observation honesty.

use bullet_domain::{
    reject_worktree, AttemptId, AttemptState, AuthorityToken, Digest, DomainError, MissionId,
    MissionState, Observation, WorkPackageState,
};
use proptest::prelude::*;

fn token(attempt: &AttemptId, fence: u64) -> AuthorityToken {
    AuthorityToken {
        organization_id: bullet_domain::OrganizationId::from_seed("org"),
        repository_id: bullet_domain::RepositoryId::from_seed("repo"),
        mission_id: MissionId::from_seed("mission"),
        acceptance_contract_id: bullet_domain::AcceptanceContractId::from_seed("acc"),
        plan_revision_id: bullet_domain::PlanRevisionId::from_seed("plan"),
        graph_sequence: 1,
        work_package_id: bullet_domain::WorkPackageId::from_seed("wp"),
        selection_group_id: bullet_domain::SelectionGroupId::from_seed("sel"),
        variant_id: bullet_domain::VariantId::from_seed("var"),
        attempt_id: attempt.clone(),
        attempt_fence: fence,
        runner_id: bullet_domain::RunnerId::from_seed("runner"),
        runner_epoch: 1,
        workspace_id: bullet_domain::WorkspaceId::from_seed("ws"),
        workspace_nonce: [7; 32],
        scope_revision: 1,
        context_revision: 1,
        config_snapshot_hash: Digest::of(b"cfg"),
        policy_snapshot_hash: Digest::of(b"pol"),
        routing_policy_hash: Digest::of(b"route"),
        credential_profile_id: None,
        credential_generation: None,
    }
}

#[test]
fn mission_ids_are_deterministic_and_prefixed() {
    let a = MissionId::from_seed("demo");
    let b = MissionId::from_seed("demo");
    assert_eq!(a, b);
    assert!(a.as_str().starts_with("mis_"));
    assert!(MissionId::parse("nope").is_err());
}

#[test]
fn stale_token_cannot_authorize() {
    let live = AttemptId::from_seed("live");
    let stale = AttemptId::from_seed("stale");
    let tok = token(&live, 3);
    assert!(tok.verify(&live, 3).is_ok());
    assert!(matches!(
        tok.verify(&stale, 3),
        Err(DomainError::StaleAuthority(_))
    ));
    assert!(matches!(
        tok.verify(&live, 4),
        Err(DomainError::StaleAuthority(_))
    ));
}

#[test]
fn stale_attempt_cannot_mutate() {
    assert!(!AttemptState::Stale.may_mutate());
    assert!(AttemptState::Executing.may_mutate());
    assert!(AttemptState::Executing
        .transition(AttemptState::Stale)
        .is_ok());
    assert!(AttemptState::Stale
        .transition(AttemptState::Executing)
        .is_err());
}

#[test]
fn work_package_does_not_complete_from_running() {
    assert!(WorkPackageState::Running
        .transition(WorkPackageState::Survived)
        .is_err());
    assert!(WorkPackageState::Verified
        .transition(WorkPackageState::Integrated)
        .is_ok());
}

#[test]
fn unknown_never_permits_destruction() {
    let unknown: Observation<String> = Observation::Unknown {
        source: "tmux".into(),
        reason: "read failed".into(),
    };
    assert!(!unknown.permits_destruction());
    assert_eq!(unknown.kind_name(), "unknown");
    assert!(unknown.render().starts_with("unknown"));
    let value = Observation::value("ok".to_string());
    assert!(value.permits_destruction());
}

#[test]
fn unknown_worktree_is_rejected() {
    assert!(reject_worktree(Some(true)));
    assert!(!reject_worktree(Some(false)));
    assert!(reject_worktree(None));
}

#[test]
fn mission_rejects_illegal_edges() {
    assert!(MissionState::Draft
        .transition(MissionState::Survived)
        .is_err());
    assert_eq!(
        MissionState::Draft
            .transition(MissionState::Admitted)
            .unwrap(),
        MissionState::Admitted
    );
}

proptest! {
    #[test]
    fn fence_mismatch_is_always_stale(fence in 1u64..10_000, other in 1u64..10_000) {
        prop_assume!(fence != other);
        let attempt = AttemptId::from_seed("prop");
        let tok = token(&attempt, fence);
        prop_assert!(tok.verify(&attempt, other).is_err());
    }

    #[test]
    fn digest_is_stable(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(Digest::of(&bytes), Digest::of(&bytes));
    }
}
