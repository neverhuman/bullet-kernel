//! Invariants A1–A7, W1–W3, and observation honesty.

use bullet_domain::{
    default_catalog, reject_worktree, AttemptId, AttemptState, AuthorityToken, CommandPhase,
    Digest, DomainError, MissionId, MissionState, Observation, WorkPackageState,
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
fn superseded_attempt_cannot_mutate() {
    assert!(!AttemptState::Superseded.may_mutate());
    assert!(!AttemptState::Crashed.may_mutate());
    assert!(!AttemptState::Succeeded.may_mutate());
    assert!(AttemptState::Running.may_mutate());
    assert!(AttemptState::Running
        .transition(AttemptState::Superseded)
        .is_ok());
    assert!(AttemptState::Superseded
        .transition(AttemptState::Running)
        .is_err());
    assert!(AttemptState::Crashed
        .transition(AttemptState::Running)
        .is_err());
}

#[test]
fn attempt_follows_spec_main_path() {
    let mut state = AttemptState::Created;
    for next in [
        AttemptState::Starting,
        AttemptState::Running,
        AttemptState::Paused,
        AttemptState::Running,
        AttemptState::Checkpointing,
        AttemptState::Preparing,
        AttemptState::Succeeded,
    ] {
        state = state.transition(next).expect("legal edge");
    }
    assert_eq!(state, AttemptState::Succeeded);
    assert!(state.transition(AttemptState::Running).is_err());
}

#[test]
fn work_package_does_not_complete_from_executing() {
    assert!(WorkPackageState::Executing
        .transition(WorkPackageState::Survived)
        .is_err());
    assert!(WorkPackageState::Executing
        .transition(WorkPackageState::Integrated)
        .is_err());
    let mut state = WorkPackageState::Ready;
    for next in [
        WorkPackageState::Leased,
        WorkPackageState::Executing,
        WorkPackageState::Prepared,
        WorkPackageState::Verifying,
        WorkPackageState::Verified,
        WorkPackageState::Reviewing,
        WorkPackageState::IntegrationReady,
        WorkPackageState::Integrating,
        WorkPackageState::Integrated,
        WorkPackageState::Observing,
        WorkPackageState::Survived,
    ] {
        state = state.transition(next).expect("legal edge");
    }
    assert_eq!(state, WorkPackageState::Survived);
}

#[test]
fn lease_release_requeues_work_package() {
    assert_eq!(
        WorkPackageState::Leased
            .transition(WorkPackageState::Ready)
            .expect("release"),
        WorkPackageState::Ready
    );
    assert_eq!(
        WorkPackageState::Executing
            .transition(WorkPackageState::Ready)
            .expect("expiry"),
        WorkPackageState::Ready
    );
}

#[test]
fn state_labels_parse_round_trip_and_fail_closed() {
    for state in [
        AttemptState::Created,
        AttemptState::Starting,
        AttemptState::Running,
        AttemptState::Paused,
        AttemptState::Checkpointing,
        AttemptState::Preparing,
        AttemptState::Succeeded,
        AttemptState::Superseded,
        AttemptState::Failed,
        AttemptState::Crashed,
        AttemptState::Cancelled,
        AttemptState::Quarantined,
    ] {
        assert_eq!(AttemptState::parse(state.as_str()).expect("round"), state);
    }
    assert!(matches!(
        AttemptState::parse("finished"),
        Err(DomainError::UnknownState(_))
    ));
    for phase in [
        CommandPhase::Pending,
        CommandPhase::Applied,
        CommandPhase::Verified,
        CommandPhase::Unknown,
    ] {
        assert_eq!(CommandPhase::parse(phase.as_str()).expect("round"), phase);
    }
    assert!(matches!(
        CommandPhase::parse("done"),
        Err(DomainError::UnknownState(_))
    ));
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
fn behavior_catalog_uses_spec_rule_ids() {
    let ids: Vec<String> = default_catalog().into_iter().map(|r| r.id).collect();
    assert_eq!(ids, ["GT001", "CL001", "CP001", "CL002", "FS001"]);
    assert!(default_catalog().iter().all(|rule| rule.fail_closed));
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

#[test]
fn reason_codes_are_stable() {
    assert_eq!(
        DomainError::StaleAuthority("x".into()).reason_code(),
        "STALE_AUTHORITY"
    );
    assert_eq!(DomainError::Fence("x".into()).reason_code(), "FENCE_REUSE");
    assert_eq!(
        DomainError::UnknownState("x".into()).reason_code(),
        "UNKNOWN_STATE"
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
