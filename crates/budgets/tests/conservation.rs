//! Reservation/settlement conservation and unknown-liability retention.

use bullet_budgets::{BudgetError, BudgetLedger};
use proptest::prelude::*;

#[test]
fn reserve_then_exact_settle_conserves() {
    let opening = 100;
    let mut ledger = BudgetLedger::new(opening, 7);
    ledger.reserve("r1", 40).expect("reserve");
    assert_eq!(ledger.remaining(), 60);
    assert_eq!(ledger.reserved(), 40);
    ledger.settle("r1", 40).expect("settle");
    assert!(ledger.conserved(opening));
    assert_eq!(ledger.unknown_liability(), 7);
    assert_eq!(
        ledger
            .unknown_as_headroom()
            .expect_err("unknown")
            .reason_code(),
        "BUDGET_UNKNOWN_NOT_HEADROOM"
    );
}

#[test]
fn underspend_returns_to_remaining() {
    let mut ledger = BudgetLedger::new(50, 0);
    ledger.reserve("r1", 20).expect("reserve");
    ledger.settle("r1", 5).expect("settle");
    assert_eq!(ledger.remaining(), 45);
    assert!(ledger.conserved(50));
}

#[test]
fn overspend_is_unknown_liability_not_headroom() {
    let mut ledger = BudgetLedger::new(10, 0);
    ledger.reserve("r1", 10).expect("reserve");
    ledger.settle("r1", 15).expect("settle");
    assert_eq!(ledger.remaining(), 0);
    assert_eq!(ledger.unknown_liability(), 5);
    assert_eq!(
        ledger.unknown_as_headroom().unwrap_err(),
        BudgetError::UnknownIsNotHeadroom
    );
}

#[test]
fn reserve_beyond_remaining_is_refused() {
    let mut ledger = BudgetLedger::new(3, 100);
    assert_eq!(
        ledger.reserve("r1", 4).expect_err("over").reason_code(),
        "BUDGET_INSUFFICIENT"
    );
}

proptest! {
    #[test]
    fn conservation_holds_for_any_reserve_and_underspend(
        opening in 1u64..64,
        reserved in 0u64..64,
        actual in 0u64..64,
    ) {
        let reserved = reserved.min(opening);
        let actual = actual.min(reserved);
        let mut ledger = BudgetLedger::new(opening, 0);
        if reserved > 0 {
            ledger.reserve("r", reserved).expect("reserve");
            ledger.settle("r", actual).expect("settle");
        }
        prop_assert!(ledger.conserved(opening));
    }
}
