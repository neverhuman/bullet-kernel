//! Mutation permits are minted only from an active lease and are one-use.

use bullet_application::mutation_permit::{
    consume_permit, mint_from_active_lease, MutationPermitError,
};
use bullet_application::mutation_reservation::OneUsePermit;
use bullet_application::nonce_ledger::{IssuedNonce, MemoryNonceLedger};

fn permit() -> OneUsePermit {
    OneUsePermit {
        reservation_id: "rsv_1".into(),
        mutation_id: "mut_1".into(),
        operation: "apply_change".into(),
        request_digest: "a".repeat(64),
    }
}

fn nonce() -> IssuedNonce {
    IssuedNonce::validated(&"b".repeat(64), &"c".repeat(64)).expect("nonce")
}

#[test]
fn mint_refuses_without_an_active_lease() {
    let mut ledger = MemoryNonceLedger::new();
    let error = mint_from_active_lease(&mut ledger, false, &permit(), &nonce()).expect_err("lease");
    assert_eq!(error, MutationPermitError::NoActiveLease);
    assert_eq!(error.reason_code(), "MUTATION_PERMIT_NO_ACTIVE_LEASE");
}

#[test]
fn mint_then_consume_refuses_replay() {
    let mut ledger = MemoryNonceLedger::new();
    let minted = mint_from_active_lease(&mut ledger, true, &permit(), &nonce()).expect("mint");
    assert_eq!(minted.mutation_id, "mut_1");
    consume_permit(&mut ledger, &nonce()).expect("consume");
    assert_eq!(
        consume_permit(&mut ledger, &nonce())
            .expect_err("replay")
            .reason_code(),
        "NONCE_CONSUMED"
    );
}
