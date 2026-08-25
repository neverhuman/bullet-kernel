//! The lease check must run inside reserve and settle, and a spent permit
//! cannot be reused. This is not a TRANSACTION_PROOF.

use bullet_application::authority::ActiveLeaseSubject;
use bullet_application::mutation_reservation::{
    LeaseGate, MutationReservationStore, MutationReserveRequest, ReservationError,
};
use bullet_application::store::LedgerError;
use bullet_domain::{AttemptId, RunnerId, VariantId, WorkPackageId, WorkspaceId};
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
        mutation_id: "mut_demo".into(),
        operation: "apply_change".into(),
        request_digest: "aa".repeat(32),
    }
}

#[test]
fn reserve_repeats_the_lease_check_inside_the_write() {
    let checks = Rc::new(Cell::new(0));
    let mut store = MutationReservationStore::new(RecordingGate {
        checks: Rc::clone(&checks),
        refuse: false,
    });
    let permit = store.reserve(&subject(), &request()).expect("reserve");
    assert_eq!(permit.mutation_id, "mut_demo");
    assert_eq!(checks.get(), 1);
    store.settle(&permit, &subject()).expect("settle");
    assert_eq!(checks.get(), 2);
    assert!(store.is_settled("mut_demo"));
}

#[test]
fn refused_lease_creates_no_permit() {
    let mut store = MutationReservationStore::new(RecordingGate {
        checks: Rc::new(Cell::new(0)),
        refuse: true,
    });
    let err = store.reserve(&subject(), &request()).expect_err("refused");
    assert_eq!(err.reason_code(), "LEASE_GATE_REFUSED");
    assert!(!store.is_settled("mut_demo"));
}

#[test]
fn spent_permit_cannot_settle_twice() {
    let mut store = MutationReservationStore::new(RecordingGate {
        checks: Rc::new(Cell::new(0)),
        refuse: false,
    });
    let permit = store.reserve(&subject(), &request()).expect("reserve");
    store.settle(&permit, &subject()).expect("first settle");
    let err = store
        .settle(&permit, &subject())
        .expect_err("second settle");
    assert_eq!(err, ReservationError::AlreadySpent(permit.reservation_id));
}
