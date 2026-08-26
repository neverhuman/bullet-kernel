//! Saga admission: no grant and unavailable authority cannot PASS.

use bullet_runner_core::saga::{require_saga_admission, stages, SagaStage};

#[test]
fn stages_are_acquire_through_exact_candidate() {
    assert_eq!(stages()[0], SagaStage::Acquire);
    assert_eq!(stages()[7], SagaStage::ExactCandidate);
}

#[test]
fn missing_grant_is_lease_refused() {
    let error = require_saga_admission(false, true).expect_err("grant");
    assert_eq!(error.reason_code(), "LEASE_REFUSED");
}

#[test]
fn unavailable_authority_is_typed() {
    let error = require_saga_admission(true, false).expect_err("gitd");
    assert_eq!(error.reason_code(), "AUTHORITY_CONTRACT_UNAVAILABLE");
}
