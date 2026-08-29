//! Purpose-signed local integration observations preserve negative truth.

mod support;

use bullet_domain::CandidateId;
use bullet_effects_core::{
    canonical_observation_bytes, decode_and_verify_fixture_observation, CheckPublication,
    FixtureObserverSigningKey, FixtureObserverVerificationKey, ForgeEffects, ForgeIntegration,
    IntegrationSubjectRequest, LocalBareForge, ObservationError, ObservationInputV1,
    ObservationOutcomeV1, ObservationSubjectV1, ProtectedIntegrationRequest, PushRequest, ZERO_OID,
};
use bullet_harness_core::launch_grant::canonical_json;
use serde_json::{json, Value};
use support::{git_out, repos, Repos};

const TARGET: &str = "refs/heads/main";
const CHECK_NAME: &str = "Bullet Farm / Proof Complete";
const PROOF_ROOT: &str = "prf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROOF_BUNDLE: &str = "prb_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OBSERVED_AT: u64 = 10_000;
const WINDOW: u64 = 60_000;

struct IntegratedFixture {
    repos: Repos,
    forge: LocalBareForge,
    subject: ObservationSubjectV1,
}

fn integrated_fixture() -> IntegratedFixture {
    let repos = repos();
    let mut forge = LocalBareForge::init(&repos.bare).expect("bare");
    let bare = repos.bare.to_str().expect("bare utf8");
    git_out(
        &repos.workspace,
        &["push", "-q", bare, &format!("{}:{TARGET}", repos.base)],
    );
    forge
        .push_candidate_ref(&PushRequest {
            workspace_repo: repos.workspace.clone(),
            ref_name: "refs/heads/bullet/candidate/can_observation".into(),
            expected_old_oid: ZERO_OID.into(),
            new_oid: repos.head.clone(),
        })
        .expect("candidate delivery");
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
    let integration = forge
        .ensure_integration_subject(&IntegrationSubjectRequest {
            base: repos.base.clone(),
            head: repos.head.clone(),
            target: TARGET.into(),
        })
        .expect("subject");
    let receipt = forge
        .integrate_protected(&ProtectedIntegrationRequest {
            expected_old_oid: repos.base.clone(),
            subject: integration,
            check_name: CHECK_NAME.into(),
            proof_root: PROOF_ROOT.into(),
        })
        .expect("integration");
    let subject = ObservationSubjectV1::from_integration(
        CandidateId::from_seed("observation-candidate"),
        PROOF_BUNDLE,
        PROOF_ROOT,
        &receipt,
    )
    .expect("observation subject");
    IntegratedFixture {
        repos,
        forge,
        subject,
    }
}

fn signer() -> FixtureObserverSigningKey {
    FixtureObserverSigningKey::generate("bullet-observer", "observer-fixture-1").expect("signer")
}

fn observe(
    fixture: &IntegratedFixture,
    signer: &FixtureObserverSigningKey,
) -> bullet_effects_core::SignedObservationV1 {
    signer
        .observe(
            &fixture.forge,
            ObservationInputV1 {
                subject: fixture.subject.clone(),
                freshness_window_ms: WINDOW,
            },
            OBSERVED_AT,
        )
        .expect("observe")
}

#[test]
fn matched_readback_is_exact_signed_and_reconstructable_from_public_key() {
    let fixture = integrated_fixture();
    let signer = signer();
    let signed = observe(&fixture, &signer);
    assert_eq!(signed.record.outcome, ObservationOutcomeV1::Matched);
    assert_eq!(signed.record.observed_oid, Some(fixture.repos.head.clone()));
    assert!(signed.record.integration_survived);
    assert_eq!(signed.record.signing_trust, "FIXTURE_KEY_ONLY");
    assert!(!signed.record.independent_evidence_eligible);
    assert!(!signed.record.transaction_gate_eligible);
    assert!(!signed.record.release_gate_eligible);

    let key = signer.verification_key();
    let reconstructed = FixtureObserverVerificationKey::from_public_hex(
        "bullet-observer",
        "observer-fixture-1",
        key.public_hex(),
    )
    .expect("public reconstruction");
    let bytes = canonical_observation_bytes(&signed).expect("canonical");
    assert_eq!(
        decode_and_verify_fixture_observation(
            &bytes,
            &reconstructed,
            &fixture.subject,
            OBSERVED_AT + 1,
        )
        .expect("authenticate"),
        signed
    );
}

#[test]
fn wrong_key_and_record_tamper_never_authenticate() {
    let fixture = integrated_fixture();
    let signer = signer();
    let signed = observe(&fixture, &signer);
    let same_identity_wrong_key =
        FixtureObserverSigningKey::generate("bullet-observer", "observer-fixture-1")
            .expect("wrong signer");
    assert_eq!(
        same_identity_wrong_key
            .verification_key()
            .verify(&signed, &fixture.subject, OBSERVED_AT + 1)
            .expect_err("wrong key"),
        ObservationError::SignatureInvalid
    );

    let mut tampered = signed;
    tampered.record.integration_survived = false;
    assert_eq!(
        signer
            .verification_key()
            .verify(&tampered, &fixture.subject, OBSERVED_AT + 1)
            .expect_err("tamper"),
        ObservationError::SignatureInvalid
    );
}

#[test]
fn noncanonical_and_recursive_unknown_fields_are_refused() {
    let fixture = integrated_fixture();
    let signer = signer();
    let signed = observe(&fixture, &signer);
    let key = signer.verification_key();
    let mut noncanonical = canonical_observation_bytes(&signed).expect("canonical");
    noncanonical.push(b'\n');
    assert_eq!(
        decode_and_verify_fixture_observation(
            &noncanonical,
            &key,
            &fixture.subject,
            OBSERVED_AT + 1,
        )
        .expect_err("noncanonical")
        .reason_code(),
        "SIGNED_OBSERVATION_RECORD_INVALID"
    );

    for path in ["outer", "nested"] {
        let mut value = serde_json::to_value(&signed).expect("json");
        if path == "outer" {
            value["unknown"] = json!(true);
        } else {
            value["record"]["subject"]["unknown"] = json!(true);
        }
        let bytes = canonical_json(&value).expect("hostile canonical JSON");
        assert_eq!(
            decode_and_verify_fixture_observation(&bytes, &key, &fixture.subject, OBSERVED_AT + 1,)
                .expect_err(path)
                .reason_code(),
            "SIGNED_OBSERVATION_RECORD_INVALID"
        );
    }
}

#[test]
fn wrong_subject_and_stale_time_are_typed_refusals() {
    let fixture = integrated_fixture();
    let signer = signer();
    let signed = observe(&fixture, &signer);
    let key = signer.verification_key();
    let mut wrong = fixture.subject.clone();
    wrong.candidate_id = CandidateId::from_seed("different-candidate");
    assert_eq!(
        key.verify(&signed, &wrong, OBSERVED_AT + 1)
            .expect_err("wrong subject")
            .reason_code(),
        "SIGNED_OBSERVATION_SUBJECT_MISMATCH"
    );
    assert_eq!(
        key.verify(&signed, &fixture.subject, OBSERVED_AT + WINDOW)
            .expect_err("stale")
            .reason_code(),
        "SIGNED_OBSERVATION_TIME_INVALID"
    );
}

#[test]
fn mismatched_target_is_authenticated_non_green_truth() {
    let fixture = integrated_fixture();
    git_out(
        &fixture.repos.bare,
        &[
            "update-ref",
            TARGET,
            &fixture.repos.base,
            &fixture.repos.head,
        ],
    );
    let signer = signer();
    let signed = observe(&fixture, &signer);
    assert_eq!(signed.record.outcome, ObservationOutcomeV1::Mismatched);
    assert_eq!(signed.record.observed_oid, Some(fixture.repos.base.clone()));
    assert!(!signed.record.integration_survived);
    signer
        .verification_key()
        .verify(&signed, &fixture.subject, OBSERVED_AT + 1)
        .expect("authenticated negative");
    let mut painted = signed;
    painted.record.outcome = ObservationOutcomeV1::Matched;
    painted.record.observed_oid = Some(fixture.repos.head.clone());
    painted.record.readback_reason_code = None;
    painted.record.integration_survived = true;
    assert_eq!(
        signer
            .verification_key()
            .verify(&painted, &fixture.subject, OBSERVED_AT + 1)
            .expect_err("negative repaint")
            .reason_code(),
        "SIGNED_OBSERVATION_SIGNATURE_INVALID"
    );
}

#[test]
fn absent_target_is_authenticated_non_green_truth() {
    let fixture = integrated_fixture();
    git_out(
        &fixture.repos.bare,
        &["update-ref", "-d", TARGET, &fixture.repos.head],
    );
    let signer = signer();
    let signed = observe(&fixture, &signer);
    assert_eq!(signed.record.outcome, ObservationOutcomeV1::Absent);
    assert_eq!(
        signed.record.readback_reason_code.as_deref(),
        Some("TARGET_ABSENT")
    );
    assert!(!signed.record.integration_survived);
    signer
        .verification_key()
        .verify(&signed, &fixture.subject, OBSERVED_AT + 1)
        .expect("authenticated absence");
}

#[test]
fn readback_error_is_signed_unknown_and_never_green() {
    let fixture = integrated_fixture();
    std::fs::write(
        fixture.repos.bare.join("refs/heads/main"),
        b"not-an-object-id\n",
    )
    .expect("corrupt target readback");
    let signer = signer();
    let signed = observe(&fixture, &signer);
    assert_eq!(signed.record.outcome, ObservationOutcomeV1::Unknown);
    assert_eq!(
        signed.record.readback_reason_code.as_deref(),
        Some("TARGET_READBACK_UNAVAILABLE")
    );
    assert!(!signed.record.integration_survived);
    signer
        .verification_key()
        .verify(&signed, &fixture.subject, OBSERVED_AT + 1)
        .expect("authenticated unknown");
}

#[test]
fn invalid_exact_binding_refuses_before_observation() {
    let fixture = integrated_fixture();
    let signer = signer();
    let mut invalid = fixture.subject.clone();
    invalid.check_proof_root = format!("prf_{}", "c".repeat(64));
    assert_eq!(
        signer
            .observe(
                &fixture.forge,
                ObservationInputV1 {
                    subject: invalid,
                    freshness_window_ms: WINDOW,
                },
                OBSERVED_AT,
            )
            .expect_err("wrong proof binding")
            .reason_code(),
        "SIGNED_OBSERVATION_RECORD_INVALID"
    );
}

#[test]
fn error_reason_codes_are_stable() {
    let cases: Vec<(ObservationError, &str)> = vec![
        (
            ObservationError::InvalidRecord("x".into()),
            "SIGNED_OBSERVATION_RECORD_INVALID",
        ),
        (
            ObservationError::SignatureInvalid,
            "SIGNED_OBSERVATION_SIGNATURE_INVALID",
        ),
        (
            ObservationError::SigningKeyMismatch,
            "SIGNED_OBSERVATION_KEY_MISMATCH",
        ),
        (
            ObservationError::SubjectMismatch,
            "SIGNED_OBSERVATION_SUBJECT_MISMATCH",
        ),
        (
            ObservationError::ObservationTimeInvalid,
            "SIGNED_OBSERVATION_TIME_INVALID",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.reason_code(), code);
    }
}

#[test]
fn signed_wire_has_no_caller_outcome_field() {
    let input = ObservationInputV1 {
        subject: integrated_fixture().subject,
        freshness_window_ms: WINDOW,
    };
    let Value::Object(fields) = serde_json::to_value(input).expect("input JSON") else {
        panic!("input must be an object")
    };
    assert_eq!(fields.len(), 2);
    assert!(fields.contains_key("freshness_window_ms"));
    assert!(fields.contains_key("subject"));
    assert!(!fields.contains_key("outcome"));
}
