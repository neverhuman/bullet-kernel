//! The lease check must run inside reserve and settle, and a spent permit
//! cannot be reused. SignedMutationPermitV1 is minted from that reservation
//! and required at first use. This is not a TRANSACTION_PROOF.

use bullet_application::authority::ActiveLeaseSubject;
use bullet_application::mutation_reservation::mutation_permit::{
    consume_signed_permit, mint_signed_permit, MutationPermitBinding,
};
use bullet_application::mutation_reservation::{
    LeaseGate, MutationReservationStore, MutationReserveRequest,
};
use bullet_application::store::LedgerError;
use bullet_domain::{
    AttemptId, Digest, RepositoryId, RunnerId, VariantId, WorkPackageId, WorkspaceId,
};
use bullet_harness_core::MutationPermitSigningKey;
use std::cell::Cell;
use std::rc::Rc;

struct RecordingGate {
    checks: Rc<Cell<usize>>,
    refuse: bool,
}

impl LeaseGate for RecordingGate {
    fn check_active_lease(&mut self, _subject: &ActiveLeaseSubject) -> Result<(), LedgerError> {
        self.checks.set(self.checks.get() + 1);
        if self.refuse {
            return Err(LedgerError::Store("lease not active".into()));
        }
        Ok(())
    }
}

fn subject() -> ActiveLeaseSubject {
    ActiveLeaseSubject {
        variant_id: VariantId::from_seed("reservation-variant"),
        attempt_id: AttemptId::from_seed("reservation-attempt"),
        work_package_id: WorkPackageId::from_seed("reservation-package"),
        fence: 1,
        runner_id: RunnerId::from_seed("reservation-runner"),
        runner_epoch: 1,
        workspace_id: WorkspaceId::from_seed("reservation-workspace"),
        workspace_nonce: [3u8; 32],
        scope_revision: 1,
        context_revision: 1,
    }
}

fn request() -> MutationReserveRequest {
    MutationReserveRequest {
        mutation_id: format!("mut_{}", Digest::of(b"reservation-mutation").to_hex()),
        operation: "apply-patch".into(),
        request_digest: "aa".repeat(32),
    }
}

fn binding() -> MutationPermitBinding {
    MutationPermitBinding {
        repository_id: RepositoryId::from_seed("permit-repo").to_string(),
        workspace_generation: 1,
        authority_epoch: 1,
        freeze_generation: 0,
        authority_envelope_digest: Digest::of(b"authority-envelope").to_hex(),
        authority_token_nonce: Digest::of(b"authority-nonce").to_hex(),
    }
}

fn signer() -> MutationPermitSigningKey {
    MutationPermitSigningKey::generate("bullet-kernel-local", "mutation-permit-test-1")
        .expect("permit key")
}

#[test]
fn reserve_repeats_the_lease_check_inside_the_write() {
    let checks = Rc::new(Cell::new(0));
    let mut store = MutationReservationStore::new(RecordingGate {
        checks: Rc::clone(&checks),
        refuse: false,
    });
    let request = request();
    let reservation = store.reserve(&subject(), &request).expect("reserve");
    assert_eq!(reservation.mutation_id, request.mutation_id);
    assert_eq!(checks.get(), 1);
    let key = signer();
    let mut legacy = reservation.clone();
    legacy.operation = "apply_change".into();
    let legacy_error = mint_signed_permit(&key, &subject(), &legacy, &binding(), 1_800_000_000_000)
        .expect_err("legacy operation label");
    assert_eq!(legacy_error.reason_code(), "INVALID_MUTATION_PERMIT");
    let signed = mint_signed_permit(
        &key,
        &subject(),
        &reservation,
        &binding(),
        1_800_000_000_000,
    )
    .expect("mint");
    assert_eq!(signed.schema_version, "v1alpha1");
    assert!(signed.paseto.starts_with("v4.public."));
    let claims = consume_signed_permit(
        &mut store,
        &key.verification_key().expect("verify key"),
        Some(&signed),
        &subject(),
        &reservation,
        &binding(),
        1_800_000_000_000,
    )
    .expect("first use");
    assert_eq!(claims.mutation_id, reservation.mutation_id);
    assert_eq!(checks.get(), 2);
    assert!(store.is_settled(&request.mutation_id));
}

#[test]
fn refused_lease_creates_no_permit() {
    let mut store = MutationReservationStore::new(RecordingGate {
        checks: Rc::new(Cell::new(0)),
        refuse: true,
    });
    let request = request();
    let err = store.reserve(&subject(), &request).expect_err("refused");
    assert_eq!(err.reason_code(), "LEASE_GATE_REFUSED");
    assert!(!store.is_settled(&request.mutation_id));
    let missing = consume_signed_permit(
        &mut store,
        &signer().verification_key().expect("verify key"),
        None,
        &subject(),
        &bullet_application::mutation_reservation::OneUsePermit {
            reservation_id: format!("rsv_{}", Digest::of(b"missing").to_hex()),
            mutation_id: request.mutation_id.clone(),
            operation: request.operation.clone(),
            request_digest: request.request_digest.clone(),
        },
        &binding(),
        1_800_000_000_000,
    )
    .expect_err("missing signed permit");
    assert_eq!(missing.reason_code(), "MUTATION_PERMIT_MISSING");
}

#[test]
fn spent_permit_cannot_settle_twice() {
    let mut store = MutationReservationStore::new(RecordingGate {
        checks: Rc::new(Cell::new(0)),
        refuse: false,
    });
    let reservation = store.reserve(&subject(), &request()).expect("reserve");
    let key = signer();
    let signed = mint_signed_permit(
        &key,
        &subject(),
        &reservation,
        &binding(),
        1_800_000_000_000,
    )
    .expect("mint");
    consume_signed_permit(
        &mut store,
        &key.verification_key().expect("verify key"),
        Some(&signed),
        &subject(),
        &reservation,
        &binding(),
        1_800_000_000_000,
    )
    .expect("first consume");
    let replay = consume_signed_permit(
        &mut store,
        &key.verification_key().expect("verify key"),
        Some(&signed),
        &subject(),
        &reservation,
        &binding(),
        1_800_000_000_000,
    )
    .expect_err("replay");
    assert_eq!(replay.reason_code(), "PERMIT_ALREADY_SPENT");
    let expired = consume_signed_permit(
        &mut store,
        &key.verification_key().expect("verify key"),
        Some(&signed),
        &subject(),
        &reservation,
        &binding(),
        1_800_000_001_000,
    )
    .expect_err("expired");
    assert_eq!(expired.reason_code(), "MUTATION_PERMIT_EXPIRED");
}
