//! Attestor credential, request-validation, and separation-of-duty negatives.

#![cfg(unix)]

use bullet_effects_core::{
    attestor_push, broker_attest, validate_attestation_request, AttestorCredential,
    CheckPublication,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn sha() -> String {
    "a".repeat(40)
}

fn publication() -> CheckPublication {
    CheckPublication {
        sha: sha(),
        name: "gate.v1".into(),
        proof_root: "root-1".into(),
    }
}

fn credential(dir: &std::path::Path) -> AttestorCredential {
    let path = dir.join("attestor.key");
    fs::write(&path, "attestor-1\n").expect("write");
    let mut permissions = fs::metadata(&path).expect("meta").permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&path, permissions).expect("mode");
    AttestorCredential::load(&path).expect("load")
}

#[test]
fn world_readable_credential_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("open.key");
    fs::write(&path, "attestor-1\n").expect("write");
    let mut permissions = fs::metadata(&path).expect("meta").permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&path, permissions).expect("mode");
    let error = AttestorCredential::load(&path).expect_err("open");
    assert_eq!(error.reason_code(), "FORGE_UNAUTHENTICATED");

    let symlink = dir.path().join("linked.key");
    std::os::unix::fs::symlink(&path, &symlink).expect("symlink");
    assert_eq!(
        AttestorCredential::load(&symlink)
            .expect_err("symlink")
            .reason_code(),
        "FORGE_UNAUTHENTICATED"
    );
}

#[test]
fn exact_sha_mismatch_is_check_subject_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cred = credential(dir.path());
    let error =
        validate_attestation_request(&cred, &publication(), &"b".repeat(40)).expect_err("mismatch");
    assert_eq!(error.reason_code(), "CHECK_SUBJECT_MISMATCH");

    let mut malformed = publication();
    malformed.sha = "not-an-oid".into();
    assert_eq!(
        validate_attestation_request(&cred, &malformed, &sha())
            .expect_err("malformed SHA")
            .reason_code(),
        "BAD_OID"
    );
}

#[test]
fn exact_sha_validation_is_not_attestation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cred = credential(dir.path());
    assert_eq!(cred.key_id(), "attestor-1");
    validate_attestation_request(&cred, &publication(), &sha()).expect("validate exact subject");
}

#[test]
fn attestor_cannot_push() {
    assert_eq!(
        attestor_push().expect_err("push").reason_code(),
        "UNSUPPORTED_BY_ADAPTER"
    );
}

#[test]
fn broker_cannot_attest() {
    assert_eq!(
        broker_attest().expect_err("broker").reason_code(),
        "UNSUPPORTED_BY_ADAPTER"
    );
}
