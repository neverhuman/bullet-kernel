//! Table-driven mutation of every lease-transport subject field: shape
//! violations refuse before signing and name the field; bound-subject
//! deviations refuse at verification with the field named and never consume
//! the nonce; every subject field is inside the canonical signed claims.

use bullet_harness_core::launch_grant::{MemoryNonceLedger, MAX_SAFE_INTEGER};
use bullet_harness_core::lease_transport::{
    nonce_binding, verify_lease_permit, LeaseIncarnationClaims, LeaseSubjectClaims,
    LeaseTransportClaims, LeaseTransportError, LeaseTransportExpectation, LeaseTransportOperation,
    LeaseTransportSigningKey, LEASE_TRANSPORT_AUDIENCE, LEASE_TRANSPORT_SCHEMA_VERSION,
};

const NOW: u64 = 1_700_000_000_000;

fn signer() -> LeaseTransportSigningKey {
    LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap()
}

fn incarnation() -> LeaseIncarnationClaims {
    LeaseIncarnationClaims {
        variant_id: format!("var_{}", "1".repeat(64)),
        attempt_id: format!("atm_{}", "2".repeat(64)),
        fence: 3,
        scope_revision: 1,
        context_revision: 1,
    }
}

fn subject(operation: LeaseTransportOperation) -> LeaseSubjectClaims {
    LeaseSubjectClaims {
        workspace_id: format!("wsp_{}", "4".repeat(64)),
        workspace_generation: 1,
        workspace_nonce_digest: "5".repeat(64),
        scope_digest: "6".repeat(64),
        policy_generation: 1,
        freeze_generation: 0,
        graph_revision: 1,
        routing_generation: 1,
        authority_epoch: 1,
        incarnation: operation.binds_incarnation().then(incarnation),
    }
}

fn claims(
    key: &LeaseTransportSigningKey,
    operation: LeaseTransportOperation,
) -> LeaseTransportClaims {
    LeaseTransportClaims {
        schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
        permit_id: "a".repeat(64),
        audience: LEASE_TRANSPORT_AUDIENCE.to_string(),
        operation,
        issuer: key.issuer().to_string(),
        key_id: key.key_id().to_string(),
        issued_at_unix_ms: NOW,
        not_before_unix_ms: NOW,
        expires_at_unix_ms: NOW + 15_000,
        permit_nonce: "b".repeat(64),
        request_digest: "c".repeat(64),
        runner_id: format!("run_{}", "7".repeat(64)),
        runner_epoch: 1,
        authority_epoch: 1,
        work_package_id: format!("wpk_{}", "8".repeat(64)),
        idempotency_digest: "d".repeat(64),
        subject: subject(operation),
    }
}

fn expectation(claims: &LeaseTransportClaims) -> LeaseTransportExpectation {
    LeaseTransportExpectation {
        operation: claims.operation,
        request_digest: claims.request_digest.clone(),
        runner_id: claims.runner_id.clone(),
        runner_epoch: claims.runner_epoch,
        authority_epoch: claims.authority_epoch,
        work_package_id: claims.work_package_id.clone(),
        idempotency_digest: claims.idempotency_digest.clone(),
        subject: claims.subject.clone(),
        now_unix_ms: NOW,
    }
}

fn ledger_for(claims: &LeaseTransportClaims) -> MemoryNonceLedger {
    let mut ledger = MemoryNonceLedger::new();
    let binding = nonce_binding(
        claims.operation,
        &claims.runner_id,
        &claims.idempotency_digest,
    );
    assert!(ledger.register(&claims.permit_nonce, &binding, claims.expires_at_unix_ms));
    ledger
}

fn inc(claims: &mut LeaseTransportClaims) -> &mut LeaseIncarnationClaims {
    claims.subject.incarnation.as_mut().unwrap()
}

fn inc_expected(expected: &mut LeaseTransportExpectation) -> &mut LeaseIncarnationClaims {
    expected.subject.incarnation.as_mut().unwrap()
}

type ClaimMutation = fn(&mut LeaseTransportClaims);
type ExpectationMutation = fn(&mut LeaseTransportExpectation);

#[test]
fn mutation_grant_and_settlement_readback_permits_bind_the_full_subject() {
    let key = signer();
    let verify = key.verification_key().unwrap();
    for operation in [
        LeaseTransportOperation::Advance,
        LeaseTransportOperation::Acquire,
        LeaseTransportOperation::SettlementReadback,
    ] {
        let claims = claims(&key, operation);
        let permit = key.sign(&claims).unwrap();
        assert_eq!(verify.authenticate(&permit).unwrap(), claims);
        let mut nonces = ledger_for(&claims);
        let verified =
            verify_lease_permit(&permit, &verify, &expectation(&claims), &mut nonces).unwrap();
        assert_eq!(verified.claims().subject, claims.subject);
        assert!(nonces.is_consumed(&claims.permit_nonce));
    }
}

#[test]
fn every_subject_shape_violation_refuses_before_signing_and_names_the_field() {
    let key = signer();
    let cases: [(&str, ClaimMutation); 19] = [
        ("subject.fence", |c| inc(c).fence = 0),
        ("subject.fence", |c| inc(c).fence = MAX_SAFE_INTEGER + 1),
        ("subject.incarnation is required", |c| {
            c.subject.incarnation = None;
        }),
        ("subject.incarnation must be absent", |c| {
            c.operation = LeaseTransportOperation::Acquire;
        }),
        ("subject.workspace_generation", |c| {
            c.subject.workspace_generation = 0;
        }),
        ("subject.workspace_generation", |c| {
            c.subject.workspace_generation = MAX_SAFE_INTEGER + 1;
        }),
        ("subject.policy_generation", |c| {
            c.subject.policy_generation = 0;
        }),
        ("subject.freeze_generation", |c| {
            c.subject.freeze_generation = MAX_SAFE_INTEGER + 1;
        }),
        ("subject.scope_digest", |c| {
            c.subject.scope_digest = "6".repeat(63) + "G";
        }),
        ("subject.workspace_nonce_digest", |c| {
            c.subject.workspace_nonce_digest.truncate(63);
        }),
        ("subject.workspace_id", |c| c.subject.workspace_id.clear()),
        ("subject.workspace_id", |c| {
            c.subject.workspace_id = "wsp ".repeat(40);
        }),
        ("subject.variant_id", |c| inc(c).variant_id.clear()),
        ("subject.attempt_id", |c| {
            inc(c).attempt_id = "atm one".into()
        }),
        ("subject.scope_revision", |c| inc(c).scope_revision = 0),
        ("subject.context_revision", |c| inc(c).context_revision = 0),
        ("subject.graph_revision", |c| c.subject.graph_revision = 0),
        ("subject.routing_generation", |c| {
            c.subject.routing_generation = MAX_SAFE_INTEGER + 1;
        }),
        ("subject.authority_epoch", |c| c.subject.authority_epoch = 0),
    ];
    for (field, mutate) in cases {
        let mut hostile = claims(&key, LeaseTransportOperation::Advance);
        mutate(&mut hostile);
        let signed = key.sign(&hostile).unwrap_err();
        assert_eq!(signed.reason_code(), "LEASE_TRANSPORT_INVALID", "{field}");
        assert!(signed.to_string().contains(field), "{field}: {signed}");
        assert_eq!(hostile.digest().unwrap_err(), signed, "{field}");
    }
    let mut epoch = claims(&key, LeaseTransportOperation::Advance);
    epoch.authority_epoch = 0;
    let error = key.sign(&epoch).unwrap_err();
    assert!(error.to_string().contains("authority_epoch"), "{error}");
    epoch.authority_epoch = 2;
    let skew = key.sign(&epoch).unwrap_err();
    let text = skew.to_string();
    assert!(
        text.contains("authority_epoch must equal subject.authority_epoch"),
        "{skew}"
    );
}

#[test]
fn every_bound_subject_deviation_refuses_at_verification_and_keeps_the_nonce() {
    let key = signer();
    let verify = key.verification_key().unwrap();
    let cases: [(&str, ExpectationMutation); 21] = [
        ("request_digest", |e| e.request_digest = "e".repeat(64)),
        ("runner_id", |e| e.runner_id = "run_other".into()),
        ("runner_epoch", |e| e.runner_epoch += 1),
        ("authority_epoch", |e| e.authority_epoch += 1),
        ("work_package_id", |e| {
            e.work_package_id = "wpk_other".into()
        }),
        ("idempotency_digest", |e| {
            e.idempotency_digest = "f".repeat(64)
        }),
        ("workspace_id", |e| {
            e.subject.workspace_id = "wsp_other".into()
        }),
        ("workspace_generation", |e| {
            e.subject.workspace_generation += 1
        }),
        ("workspace_nonce_digest", |e| {
            e.subject.workspace_nonce_digest = "9".repeat(64);
        }),
        ("scope_digest", |e| e.subject.scope_digest = "0".repeat(64)),
        ("policy_generation", |e| e.subject.policy_generation += 1),
        ("freeze_generation", |e| e.subject.freeze_generation += 1),
        ("graph_revision", |e| e.subject.graph_revision += 1),
        ("routing_generation", |e| e.subject.routing_generation += 1),
        ("subject.authority_epoch", |e| {
            e.subject.authority_epoch += 1
        }),
        ("variant_id", |e| {
            inc_expected(e).variant_id = "var_other".into()
        }),
        ("attempt_id", |e| {
            inc_expected(e).attempt_id = "atm_other".into()
        }),
        ("fence", |e| inc_expected(e).fence += 1),
        ("scope_revision", |e| inc_expected(e).scope_revision += 1),
        ("context_revision", |e| {
            inc_expected(e).context_revision += 1
        }),
        ("incarnation", |e| e.subject.incarnation = None),
    ];
    let claims = claims(&key, LeaseTransportOperation::Advance);
    let permit = key.sign(&claims).unwrap();
    for (field, mutate) in cases {
        let mut expected = expectation(&claims);
        mutate(&mut expected);
        let mut nonces = ledger_for(&claims);
        let error = verify_lease_permit(&permit, &verify, &expected, &mut nonces).unwrap_err();
        assert_eq!(
            error,
            LeaseTransportError::SubjectMismatch { field },
            "{field}"
        );
        assert_eq!(error.reason_code(), "LEASE_TRANSPORT_SUBJECT_MISMATCH");
        assert!(!nonces.is_consumed(&claims.permit_nonce), "{field}");
    }
    let mut nonces = ledger_for(&claims);
    drop(verify_lease_permit(&permit, &verify, &expectation(&claims), &mut nonces).unwrap());
    assert!(nonces.is_consumed(&claims.permit_nonce));
}

#[test]
fn every_subject_field_is_inside_the_canonical_signed_claims() {
    let key = signer();
    let verify = key.verification_key().unwrap();
    let baseline = claims(&key, LeaseTransportOperation::Advance);
    let digest = baseline.digest().unwrap();
    let permit = key.sign(&baseline).unwrap();
    let cases: [(&str, ClaimMutation); 14] = [
        ("workspace_id", |c| {
            c.subject.workspace_id = "wsp_other".into()
        }),
        ("workspace_generation", |c| {
            c.subject.workspace_generation = 2
        }),
        ("workspace_nonce_digest", |c| {
            c.subject.workspace_nonce_digest = "9".repeat(64);
        }),
        ("scope_digest", |c| c.subject.scope_digest = "0".repeat(64)),
        ("policy_generation", |c| c.subject.policy_generation = 2),
        ("freeze_generation", |c| c.subject.freeze_generation = 1),
        ("variant_id", |c| inc(c).variant_id = "var_other".into()),
        ("attempt_id", |c| inc(c).attempt_id = "atm_other".into()),
        ("fence", |c| inc(c).fence = 4),
        ("scope_revision", |c| inc(c).scope_revision = 2),
        ("context_revision", |c| inc(c).context_revision = 2),
        ("graph_revision", |c| c.subject.graph_revision = 2),
        ("routing_generation", |c| c.subject.routing_generation = 2),
        ("authority_epoch", |c| {
            c.authority_epoch = 2;
            c.subject.authority_epoch = 2;
        }),
    ];
    for (field, mutate) in cases {
        let mut variant = baseline.clone();
        mutate(&mut variant);
        assert_ne!(variant.digest().unwrap(), digest, "{field}");
        let resigned = key.sign(&variant).unwrap();
        assert_ne!(resigned.paseto, permit.paseto, "{field}");
        assert_eq!(verify.authenticate(&resigned).unwrap(), variant, "{field}");
        assert_eq!(verify.authenticate(&permit).unwrap(), baseline, "{field}");
    }
}

#[test]
fn a_permit_from_another_key_with_the_same_labels_is_refused() {
    let key = signer();
    let forger = signer();
    let verify = key.verification_key().unwrap();
    let claims = claims(&forger, LeaseTransportOperation::Advance);
    let forged = forger.sign(&claims).unwrap();
    let mut nonces = ledger_for(&claims);
    let error =
        verify_lease_permit(&forged, &verify, &expectation(&claims), &mut nonces).unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_INVALID");
    assert!(!nonces.is_consumed(&claims.permit_nonce));
}

#[test]
fn grant_class_permits_bind_the_workspace_and_refuse_a_fenced_incarnation() {
    let key = signer();
    let verify = key.verification_key().unwrap();
    let claims = claims(&key, LeaseTransportOperation::Readback);
    assert!(claims.subject.incarnation.is_none());
    let permit = key.sign(&claims).unwrap();
    let mut expected = expectation(&claims);
    expected.subject.incarnation = Some(incarnation());
    let mut nonces = ledger_for(&claims);
    let error = verify_lease_permit(&permit, &verify, &expected, &mut nonces).unwrap_err();
    assert_eq!(
        error,
        LeaseTransportError::SubjectMismatch {
            field: "incarnation"
        }
    );
    assert!(!nonces.is_consumed(&claims.permit_nonce));
    let mut fenced = claims.clone();
    fenced.subject.incarnation = Some(incarnation());
    let refused = key.sign(&fenced).unwrap_err();
    assert!(
        refused.to_string().contains("must be absent for readback"),
        "{refused}"
    );
}

#[test]
fn the_outer_authority_epoch_is_derived_from_the_subject() {
    let key = signer();
    let verify = key.verification_key().unwrap();
    let claims = claims(&key, LeaseTransportOperation::Advance);
    let mut inconsistent = expectation(&claims);
    inconsistent.authority_epoch = 7;
    let (permit_id, nonce) = ("a".repeat(64), "b".repeat(64));
    let minted = inconsistent.claims("kernel-local", "lease-1", permit_id, nonce, 15_000);
    assert_eq!(minted.authority_epoch, 1);
    assert_eq!(minted, claims);
    let permit = key.sign(&minted).unwrap();
    let mut nonces = ledger_for(&claims);
    let error = verify_lease_permit(&permit, &verify, &inconsistent, &mut nonces).unwrap_err();
    assert_eq!(
        error,
        LeaseTransportError::SubjectMismatch {
            field: "authority_epoch"
        }
    );
    assert!(!nonces.is_consumed(&claims.permit_nonce));
    let mut skewed = claims.clone();
    skewed.authority_epoch = 2;
    let refused = key.sign(&skewed).unwrap_err();
    assert_eq!(refused.reason_code(), "LEASE_TRANSPORT_INVALID");
    assert!(
        refused
            .to_string()
            .contains("must equal subject.authority_epoch"),
        "{refused}"
    );
    assert_eq!(skewed.digest().unwrap_err(), refused);
}
