//! Reservation/settlement conservation and unknown-liability retention.

#[allow(dead_code)]
mod support;

use bullet_budgets::{
    BudgetError, BudgetLedger, Dimension, DimensionError, ForecastOutcome, ReservationVector,
    ReserveClass, Usage, UsageVector,
};
use proptest::prelude::*;
use support::PolicyLedger;

fn uniform(units: u64) -> ReservationVector {
    ReservationVector::from_fn(|_| units)
}

fn only(dimension: Dimension, units: u64) -> ReservationVector {
    ReservationVector::ZERO.with(dimension, units)
}

#[test]
fn reserve_then_exact_settle_conserves() {
    let opening = 100;
    let mut ledger = BudgetLedger::new(opening, 7);
    ledger.reserve("r1", 40).expect("reserve");
    assert_eq!(ledger.remaining(), 60);
    assert_eq!(ledger.reserved(), 40);
    ledger.settle("r1", 40).expect("settle");
    assert!(ledger.conserved());
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
    assert!(ledger.conserved());
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

    let mut overflow = BudgetLedger::new(1, u64::MAX);
    overflow.reserve("overflow", 1).expect("reserve");
    assert_eq!(
        overflow
            .settle("overflow", 2)
            .expect_err("overflow")
            .reason_code(),
        "BUDGET_ARITHMETIC_OVERFLOW"
    );
    assert_eq!(overflow.reserved(), 1, "failed settlement is atomic");
    assert_eq!(overflow.unknown_liability(), u64::MAX);
}

#[test]
fn reserve_beyond_remaining_is_refused() {
    let mut ledger = BudgetLedger::new(3, 100);
    assert_eq!(
        ledger.reserve("r1", 4).expect_err("over").reason_code(),
        "BUDGET_INSUFFICIENT"
    );
    assert_eq!(
        ledger.reserve("", 1).expect_err("empty").reason_code(),
        "BUDGET_RESERVATION_INVALID"
    );
    assert_eq!(
        ledger.reserve("zero", 0).expect_err("zero").reason_code(),
        "BUDGET_RESERVATION_INVALID"
    );
    ledger.reserve("unique", 1).expect("first");
    assert_eq!(
        ledger
            .reserve("unique", 1)
            .expect_err("duplicate")
            .reason_code(),
        "BUDGET_RESERVATION_DUPLICATE"
    );
    ledger.settle("unique", 1).expect("settle");
    assert_eq!(
        ledger
            .reserve("unique", 1)
            .expect_err("lifetime duplicate")
            .reason_code(),
        "BUDGET_RESERVATION_DUPLICATE"
    );
}

#[test]
fn unknown_usage_stays_reserved_and_never_becomes_headroom() {
    let mut ledger = PolicyLedger::new(uniform(20), ReservationVector::ZERO);
    ledger
        .reserve("r", ReserveClass::Incident, only(Dimension::Token, 15))
        .expect("reserve");
    let usage = UsageVector::known(&ReservationVector::ZERO).with_unknown(Dimension::Token);
    let record = ledger.settle("r", &usage).expect("settle");
    assert!(record.is_forecast_error_event());
    let token = ledger.state(Dimension::Token);
    assert_eq!(
        (token.remaining, token.reserved, token.retained),
        (5, 0, 15)
    );
    assert_eq!(ledger.headroom().get(Dimension::Token), 5);
    assert_eq!(token.unknown_liability(), Some(15));
    assert_eq!(
        ledger
            .unknown_as_headroom(Dimension::Token)
            .expect_err("retained")
            .reason_code(),
        "BUDGET_UNKNOWN_NOT_HEADROOM"
    );
    assert_eq!(ledger.unknown_as_headroom(Dimension::Cost), Ok(0));
    assert!(!ledger.state(Dimension::Cost).has_unknown_liability());
    assert_eq!(
        ledger
            .reserve("again", ReserveClass::Incident, only(Dimension::Token, 6))
            .expect_err("retained is not headroom"),
        DimensionError::Exhausted {
            dimension: Dimension::Token,
            requested: 6,
            remaining: 5,
        }
    );
    ledger
        .reserve("fits", ReserveClass::Incident, only(Dimension::Token, 5))
        .expect("remaining is headroom");
    ledger.release("fits").expect("release");
    assert_eq!(ledger.state(Dimension::Token).retained, 15);
    assert!(ledger.conserved());

    let mut overflow = PolicyLedger::new(uniform(1), only(Dimension::Cost, u64::MAX));
    overflow
        .reserve("o", ReserveClass::Incident, only(Dimension::Cost, 1))
        .expect("reserve");
    let before = overflow.clone();
    assert_eq!(
        overflow
            .settle("o", &UsageVector::known(&only(Dimension::Cost, 2)))
            .expect_err("overrun overflow"),
        DimensionError::ArithmeticOverflow(Dimension::Cost)
    );
    assert_eq!(overflow, before, "failed settlement is atomic");
    assert_eq!(
        overflow.unknown_as_headroom(Dimension::Cost).unwrap_err(),
        DimensionError::UnknownIsNotHeadroom(Dimension::Cost)
    );
}

#[test]
fn release_returns_every_unit_without_a_forecast_record() {
    let mut ledger = PolicyLedger::new(uniform(30), ReservationVector::ZERO);
    let forecast = only(Dimension::Cpu, 7).with(Dimension::VerifierBacklog, 3);
    ledger
        .reserve("r", ReserveClass::Benchmark, forecast)
        .expect("reserve");
    assert_eq!(ledger.state(Dimension::VerifierBacklog).remaining, 27);
    assert_eq!(ledger.release("r").expect("release"), forecast);
    for dimension in Dimension::ALL {
        let state = ledger.state(dimension);
        assert_eq!((state.remaining, state.reserved, state.settled), (30, 0, 0));
    }
    assert!(ledger.conserved());
    assert_eq!(ledger.release("r").unwrap_err(), DimensionError::NotFound);
}

#[test]
fn unforecast_usage_is_typed_liability_not_silence() {
    let mut ledger = PolicyLedger::new(uniform(10), ReservationVector::ZERO);
    ledger
        .reserve("r", ReserveClass::Incident, only(Dimension::Token, 4))
        .expect("reserve");
    let usage = UsageVector::known(&only(Dimension::Token, 4))
        .with_unknown(Dimension::Egress)
        .with_known(Dimension::Disk, 3);
    let before = ledger.clone();
    let record = ledger.settle("r", &usage).expect("settle");
    assert_eq!(
        record.errors.len(),
        3,
        "known zero on unforecast dimensions is no row"
    );
    assert_eq!(
        record.row(Dimension::Token).expect("row").outcome,
        ForecastOutcome::Exact
    );
    let egress = record.row(Dimension::Egress).expect("row");
    assert_eq!(
        (egress.forecast, egress.usage, egress.outcome),
        (0, Usage::Unknown, ForecastOutcome::UnforecastUnknown)
    );
    let disk = record.row(Dimension::Disk).expect("row");
    assert_eq!(
        (disk.forecast, disk.outcome),
        (0, ForecastOutcome::UnforecastOverrun { overrun: 3 })
    );
    assert_eq!(
        record.unforecast_unknown().collect::<Vec<_>>(),
        [Dimension::Egress]
    );
    assert!(record.is_forecast_error_event());
    assert!(ledger.conserved());

    let egress = ledger.state(Dimension::Egress);
    assert_eq!(
        (
            egress.remaining,
            egress.retained,
            egress.overrun,
            egress.unknown_events
        ),
        (10, 0, 0, 1)
    );
    assert!(egress.has_unknown_liability());
    assert_eq!(
        ledger.unknown_as_headroom(Dimension::Egress).unwrap_err(),
        DimensionError::UnknownIsNotHeadroom(Dimension::Egress)
    );
    let disk = ledger.state(Dimension::Disk);
    assert_eq!(
        (disk.remaining, disk.overrun, disk.unknown_liability()),
        (10, 3, Some(3))
    );
    assert_eq!(
        ledger
            .unknown_as_headroom(Dimension::Disk)
            .unwrap_err()
            .reason_code(),
        "BUDGET_UNKNOWN_NOT_HEADROOM"
    );
    assert_eq!(
        ledger.state(Dimension::Memory),
        before.state(Dimension::Memory)
    );
    assert_eq!(ledger.unknown_as_headroom(Dimension::Memory), Ok(0));

    ledger
        .reserve("r2", ReserveClass::Incident, only(Dimension::Token, 1))
        .expect("reserve");
    let usage = UsageVector::known(&only(Dimension::Token, 1)).with_unknown(Dimension::Egress);
    ledger.settle("r2", &usage).expect("settle");
    assert_eq!(
        ledger.state(Dimension::Egress).unknown_events,
        2,
        "events accumulate"
    );
    assert!(ledger.conserved());
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
        prop_assert!(ledger.conserved());
    }

    /// The single-dimension ledger and the vector ledger's `token` pot must tell
    /// the same story for the same reserve/settle sequence (the vector ledger
    /// under `incident` has no floor, matching the older ledger).
    #[test]
    fn single_dimension_ledger_agrees_with_vector_ledger_on_token(
        opening in 0u64..64,
        steps in prop::collection::vec((1u64..32, prop::option::of(0u64..48)), 1..16),
    ) {
        let token = |units| ReservationVector::ZERO.with(Dimension::Token, units);
        let mut single = BudgetLedger::new(opening, 0);
        let mut vector = PolicyLedger::new(token(opening), ReservationVector::ZERO);
        for (index, (amount, actual)) in steps.into_iter().enumerate() {
            let id = format!("r{index}");
            let one = single.reserve(&id, amount);
            let many = vector.reserve(&id, ReserveClass::Incident, token(amount));
            prop_assert_eq!(one.is_ok(), many.is_ok());
            if let (Some(actual), Ok(_)) = (actual, one) {
                single.settle(&id, actual).expect("single settle");
                vector
                    .settle(&id, &UsageVector::UNKNOWN.with_known(Dimension::Token, actual))
                    .expect("vector settle");
            }
            let state = vector.state(Dimension::Token);
            prop_assert_eq!(single.remaining(), state.remaining);
            prop_assert_eq!(single.reserved(), state.reserved);
            prop_assert_eq!(single.unknown_liability(), state.overrun);
            prop_assert!(single.conserved() && vector.conserved());
        }
    }
}
