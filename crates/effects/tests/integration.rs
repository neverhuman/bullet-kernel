//! ForgeIntegration honesty: Unprobed never authorizes; GitLab refuses;
//! Jeryu merge-group is Unsupported; GitHub merge-group is opaque.

use bullet_effects_core::{
    require_probed, Capability, ForgeEffects, ForgeIntegration, GitHubForge, GitLabForge,
    JeryuForge, JERYU_BASE_URL,
};

#[test]
fn unprobed_never_authorizes() {
    assert!(!Capability::Unprobed.authorizes());
    assert!(!Capability::Unsupported.authorizes());
    assert!(Capability::Supported.authorizes());
    assert!(Capability::SupportedWithLimitations("note").authorizes());
    assert_eq!(
        require_probed(Capability::Unprobed, "push")
            .expect_err("unprobed")
            .reason_code(),
        "CAPABILITY_UNPROBED"
    );
}

#[test]
fn gitlab_refuses_every_integration_operation() {
    let forge = GitLabForge::quarantined();
    assert_eq!(forge.descriptor().provider, "gitlab");
    assert!(!forge.integration_descriptor().exact_oid_cas.authorizes());
    assert_eq!(
        forge
            .read_protection("refs/heads/main")
            .expect_err("gitlab")
            .reason_code(),
        "UNSUPPORTED_BY_ADAPTER"
    );
}

#[test]
fn jeryu_names_merge_queue_unsupported_and_stays_quarantined() {
    let mut forge = JeryuForge::quarantined(JERYU_BASE_URL);
    assert_eq!(
        forge.integration_descriptor().merge_group,
        Capability::Unsupported
    );
    assert_eq!(
        forge
            .publish_check(&bullet_effects_core::CheckPublication {
                sha: "a".repeat(40),
                name: "Bullet Farm / Proof Complete".into(),
                proof_root: "prf".into(),
            })
            .expect_err("quarantine")
            .reason_code(),
        "LIVE_ADMISSION_UNAVAILABLE"
    );
    assert_eq!(
        forge
            .merge_group_subject(&bullet_effects_core::IntegrationSubject {
                id: "1".into(),
                base: "main".into(),
                head: "a".repeat(40),
                target: "refs/heads/main".into(),
            })
            .expect_err("no queue")
            .reason_code(),
        "UNSUPPORTED_BY_ADAPTER"
    );
}

#[test]
fn github_merge_group_is_opaque_until_live_admission() {
    let forge = GitHubForge::quarantined();
    assert!(matches!(
        forge.integration_descriptor().exact_oid_cas,
        Capability::SupportedWithLimitations(_)
    ));
    assert_eq!(
        forge
            .merge_group_subject(&bullet_effects_core::IntegrationSubject {
                id: "1".into(),
                base: "main".into(),
                head: "a".repeat(40),
                target: "refs/heads/main".into(),
            })
            .expect_err("opaque")
            .reason_code(),
        "MERGE_GROUP_OPAQUE"
    );
}
