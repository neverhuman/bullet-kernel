//! Jeryu remains mechanically quarantined throughout Wave 0.

use bullet_effects_core::{ForgeEffects, JeryuForge, PushRequest, JERYU_BASE_URL};

fn push_request() -> PushRequest {
    PushRequest {
        workspace_repo: std::path::PathBuf::from("/nonexistent"),
        ref_name: "refs/heads/bullet/candidate/x".into(),
        expected_old_oid: "0".repeat(40),
        new_oid: "b".repeat(40),
    }
}

#[test]
fn credential_and_network_admission_are_unavailable() {
    let mut forge = JeryuForge::quarantined(JERYU_BASE_URL);
    let descriptor = forge.descriptor();
    assert!(!descriptor.authenticated);
    assert!(!descriptor.can_push_candidate_ref);
    let err = forge
        .push_candidate_ref(&push_request())
        .expect_err("refused");
    assert_eq!(err.reason_code(), "LIVE_ADMISSION_UNAVAILABLE");
    let err = forge
        .read_ref("refs/heads/bullet/candidate/x")
        .expect_err("refused");
    assert_eq!(err.reason_code(), "LIVE_ADMISSION_UNAVAILABLE");
    // Namespace guard fires even before the auth refusal.
    let err = forge.read_ref("refs/heads/main").expect_err("denied");
    assert_eq!(err.reason_code(), "REF_DENIED");
}
