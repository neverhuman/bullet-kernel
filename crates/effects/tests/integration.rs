//! ForgeIntegration honesty: Unprobed never authorizes; GitLab refuses;
//! Jeryu merge-group is Unsupported; GitHub merge-group is opaque.

mod support;

use bullet_effects_core::{
    require_probed, Capability, CheckPublication, EffectsError, ForgeEffects, ForgeIntegration,
    GitHubForge, GitLabForge, GitLabProfile, IntegrationSubject, IntegrationSubjectRequest,
    JeryuForge, LocalBareForge, ProtectedIntegrationRequest, PushRequest, JERYU_BASE_URL, ZERO_OID,
};
use support::{git_out, repos, Repos};

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
    assert_eq!(
        require_probed(Capability::Unsupported, "push")
            .expect_err("unsupported")
            .reason_code(),
        "UNSUPPORTED_BY_ADAPTER"
    );
}

#[test]
fn gitlab_refuses_every_integration_operation() {
    let forge = GitLabForge::quarantined();
    assert_eq!(forge.descriptor().provider, "gitlab");
    assert_eq!(forge.profile(), GitLabProfile::GitlabCom);
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
fn gitlab_com_and_self_managed_refusals_are_not_substitutable() {
    let com = GitLabForge::gitlab_com();
    let managed = GitLabForge::self_managed();
    assert_ne!(com.profile(), managed.profile());
    let com_err = com
        .read_protection("refs/heads/main")
        .expect_err("com")
        .to_string();
    let managed_err = managed
        .read_protection("refs/heads/main")
        .expect_err("self-managed")
        .to_string();
    assert!(com_err.contains("gitlab-adapter-v1"), "{com_err}");
    assert!(
        managed_err.contains("gitlab-self-managed-v1"),
        "{managed_err}"
    );
    assert_ne!(com_err, managed_err);
}

#[test]
fn jeryu_names_merge_queue_unsupported_and_stays_quarantined() {
    let mut forge = JeryuForge::quarantined(JERYU_BASE_URL);
    assert_eq!(
        forge.integration_descriptor().exact_oid_cas,
        Capability::Unprobed
    );
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
fn github_capabilities_are_unprobed_and_merge_group_is_opaque() {
    let forge = GitHubForge::quarantined();
    assert_eq!(
        forge.integration_descriptor(),
        bullet_effects_core::IntegrationDescriptor::unprobed()
    );
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

const TARGET: &str = "refs/heads/main";
const CHECK_NAME: &str = "Bullet Farm / Proof Complete";
const PROOF_ROOT: &str = "prf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn local_forge() -> (Repos, LocalBareForge) {
    let repos = repos();
    let mut forge = LocalBareForge::init(&repos.bare).expect("bare");
    let bare = repos.bare.to_str().expect("bare utf8");
    let base_refspec = format!("{}:{TARGET}", repos.base);
    git_out(&repos.workspace, &["push", "-q", bare, &base_refspec]);
    forge
        .push_candidate_ref(&PushRequest {
            workspace_repo: repos.workspace.clone(),
            ref_name: "refs/heads/bullet/candidate/can_local".into(),
            expected_old_oid: ZERO_OID.into(),
            new_oid: repos.head.clone(),
        })
        .expect("candidate delivery");
    (repos, forge)
}

fn subject(repos: &Repos, forge: &mut LocalBareForge) -> IntegrationSubject {
    forge
        .ensure_integration_subject(&IntegrationSubjectRequest {
            base: repos.base.clone(),
            head: repos.head.clone(),
            target: TARGET.into(),
        })
        .expect("subject")
}

fn integration_request(subject: IntegrationSubject) -> ProtectedIntegrationRequest {
    ProtectedIntegrationRequest {
        expected_old_oid: subject.base.clone(),
        subject,
        check_name: CHECK_NAME.into(),
        proof_root: PROOF_ROOT.into(),
    }
}

#[test]
fn local_check_and_protection_are_exact_and_restart_safe() {
    let (repos, mut forge) = local_forge();
    let descriptor = forge.integration_descriptor();
    assert!(descriptor.exact_oid_cas.authorizes());
    assert!(descriptor.protected_refs.authorizes());
    assert!(descriptor.check_runs.authorizes());
    assert_eq!(descriptor.merge_group, Capability::Unsupported);

    let protection = forge
        .protect_target(TARGET, PROOF_ROOT)
        .expect("protection");
    assert_eq!(
        forge
            .protect_target(TARGET, PROOF_ROOT)
            .expect("protection replay"),
        protection
    );
    assert_eq!(
        forge
            .protect_target(TARGET, "prf_other")
            .expect_err("protection rebind")
            .reason_code(),
        "PROTECTION_MISMATCH"
    );
    let publication = CheckPublication {
        sha: repos.head.clone(),
        name: CHECK_NAME.into(),
        proof_root: PROOF_ROOT.into(),
    };
    let check = forge.publish_check(&publication).expect("check");
    assert_eq!(
        forge.publish_check(&publication).expect("check replay"),
        check
    );
    let mut rebound = publication.clone();
    rebound.proof_root = "prf_other".into();
    assert_eq!(
        forge
            .publish_check(&rebound)
            .expect_err("check rebind")
            .reason_code(),
        "CHECK_SUBJECT_MISMATCH"
    );
    assert!(forge
        .read_check(&"f".repeat(40), CHECK_NAME)
        .expect("authoritative absence")
        .is_none());

    let reopened = LocalBareForge::open(&repos.bare).expect("reopen");
    assert_eq!(reopened.read_protection(TARGET).expect("read"), protection);
    assert_eq!(
        reopened
            .read_check(&repos.head, CHECK_NAME)
            .expect("read check"),
        Some(check)
    );
}

#[test]
fn local_subject_is_exact_idempotent_and_restart_safe() {
    let (repos, mut forge) = local_forge();
    let exact = subject(&repos, &mut forge);
    assert!(exact.id.starts_with("ins_"));
    assert_eq!(exact.id.len(), 68);
    assert_eq!(subject(&repos, &mut forge), exact);

    let mut reopened = LocalBareForge::open(&repos.bare).expect("reopen");
    assert_eq!(subject(&repos, &mut reopened), exact);
    let mut forged = exact.clone();
    forged.id = format!("ins_{}", "0".repeat(64));
    assert_eq!(
        reopened
            .integrate_protected(&integration_request(forged))
            .expect_err("forged subject")
            .reason_code(),
        "INTEGRATION_SUBJECT_MISMATCH"
    );

    let subject_path = repos
        .bare
        .join("bullet-effects-v1/subjects")
        .join(format!("{}.json", exact.id));
    let mut rebound = exact.clone();
    rebound.target = "refs/heads/other".into();
    std::fs::write(
        subject_path,
        serde_json::to_vec(&rebound).expect("subject json"),
    )
    .expect("tamper subject");
    assert_eq!(
        reopened
            .ensure_integration_subject(&IntegrationSubjectRequest {
                base: repos.base.clone(),
                head: repos.head.clone(),
                target: TARGET.into(),
            })
            .expect_err("subject rebind")
            .reason_code(),
        "INTEGRATION_SUBJECT_MISMATCH"
    );
}

#[test]
fn local_protected_integration_refuses_absent_check_wrong_proof_and_stale_target() {
    let (repos, mut forge) = local_forge();
    let exact = subject(&repos, &mut forge);
    forge
        .protect_target(TARGET, PROOF_ROOT)
        .expect("protection");
    let request = integration_request(exact.clone());
    assert_eq!(
        forge
            .integrate_protected(&request)
            .expect_err("absent check")
            .reason_code(),
        "CHECK_SUBJECT_MISMATCH"
    );
    forge
        .publish_check(&CheckPublication {
            sha: repos.head.clone(),
            name: CHECK_NAME.into(),
            proof_root: PROOF_ROOT.into(),
        })
        .expect("check");
    let mut wrong_proof = request.clone();
    wrong_proof.proof_root = "prf_other".into();
    assert_eq!(
        forge
            .integrate_protected(&wrong_proof)
            .expect_err("wrong proof")
            .reason_code(),
        "PROTECTION_MISMATCH"
    );
    git_out(&repos.bare, &["update-ref", "-d", TARGET, &repos.base]);
    assert_eq!(
        forge
            .integrate_protected(&request)
            .expect_err("stale target")
            .reason_code(),
        "INTEGRATION_PRECONDITION_FAILED"
    );
    git_out(&repos.bare, &["update-ref", TARGET, &repos.base, ZERO_OID]);
    git_out(
        &repos.bare,
        &["update-ref", TARGET, &repos.head, &repos.base],
    );
    assert_eq!(
        forge
            .integrate_protected(&request)
            .expect_err("head moved without receipt")
            .reason_code(),
        "ORPHANED_REMOTE"
    );
}

#[test]
fn local_integration_replays_after_restart_and_detects_third_party_drift() {
    let (repos, mut forge) = local_forge();
    let exact = subject(&repos, &mut forge);
    forge
        .protect_target(TARGET, PROOF_ROOT)
        .expect("protection");
    forge
        .publish_check(&CheckPublication {
            sha: repos.head.clone(),
            name: CHECK_NAME.into(),
            proof_root: PROOF_ROOT.into(),
        })
        .expect("check");
    let request = integration_request(exact.clone());
    let receipt = forge.integrate_protected(&request).expect("integration");
    assert_eq!(receipt.subject_id, exact.id);
    assert_eq!(receipt.previous_oid, repos.base);
    assert_eq!(receipt.integrated_oid, repos.head);
    assert_eq!(
        forge.read_target(TARGET).expect("target"),
        Some(repos.head.clone())
    );
    assert_eq!(
        forge.integrate_protected(&request).expect("replay"),
        receipt
    );

    let mut reopened = LocalBareForge::open(&repos.bare).expect("reopen");
    assert_eq!(
        reopened
            .integrate_protected(&request)
            .expect("restart replay"),
        receipt
    );
    git_out(
        &repos.bare,
        &["update-ref", TARGET, &repos.base, &repos.head],
    );
    assert_eq!(
        reopened
            .integrate_protected(&request)
            .expect_err("third-party drift")
            .reason_code(),
        "ORPHANED_REMOTE"
    );
    assert_eq!(
        reopened.read_target(TARGET).expect("drift readback"),
        Some(repos.base)
    );
}

#[test]
fn local_target_readback_distinguishes_absence_from_a_broken_ref() {
    let (repos, forge) = local_forge();
    git_out(&repos.bare, &["update-ref", "-d", TARGET, &repos.base]);
    assert_eq!(
        forge.read_target(TARGET).expect("authoritative absence"),
        None
    );

    std::fs::write(repos.bare.join(TARGET), b"not-an-object-id\n").expect("write broken ref");
    assert_eq!(
        forge
            .read_target(TARGET)
            .expect_err("broken ref must not become absence")
            .reason_code(),
        "TARGET_READBACK_UNAVAILABLE"
    );
}

#[test]
fn local_state_refuses_noncanonical_files_and_symlink_categories() {
    let (repos, mut forge) = local_forge();
    forge
        .protect_target(TARGET, PROOF_ROOT)
        .expect("protection");
    let protection_dir = repos.bare.join("bullet-effects-v1/protections");
    let state_file = std::fs::read_dir(&protection_dir)
        .expect("protection directory")
        .next()
        .expect("protection entry")
        .expect("entry")
        .path();
    let mut bytes = std::fs::read(&state_file).expect("state bytes");
    bytes.push(b'\n');
    std::fs::write(&state_file, bytes).expect("noncanonical tamper");
    assert_eq!(
        forge
            .read_protection(TARGET)
            .expect_err("noncanonical state")
            .reason_code(),
        "DURABLE_QUEUE_INVALID"
    );

    let (other, _forge) = local_forge();
    let checks = other.bare.join("bullet-effects-v1/checks");
    std::fs::remove_dir(&checks).expect("remove empty checks");
    std::os::unix::fs::symlink("protections", &checks).expect("symlink category");
    assert_eq!(
        LocalBareForge::open(&other.bare)
            .expect_err("symlink category")
            .reason_code(),
        "DURABLE_QUEUE_INVALID"
    );
}

#[test]
fn local_integration_reason_codes_are_stable() {
    assert_eq!(
        EffectsError::IntegrationSubjectMismatch("x".into()).reason_code(),
        "INTEGRATION_SUBJECT_MISMATCH"
    );
    assert_eq!(
        EffectsError::IntegrationPreconditionFailed("x".into()).reason_code(),
        "INTEGRATION_PRECONDITION_FAILED"
    );
    assert_eq!(
        EffectsError::OrphanedRemote("x".into()).reason_code(),
        "ORPHANED_REMOTE"
    );
}
