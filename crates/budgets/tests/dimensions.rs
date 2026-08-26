//! Multi-dimension reservation: atomic reserve with typed exhaustion, settle
//! outcomes, unknown-usage retention, reserve-class floors, and random
//! interleavings.

mod support;

use bullet_budgets::{
    Dimension, DimensionError, ForecastOutcome, ReservationVector, ReserveClass, Usage,
    UsageVector, DIMENSION_COUNT,
};
use proptest::prelude::*;
use std::collections::BTreeSet;
use support::{assert_policy_validation_refusals, policy, PolicyLedger};

fn uniform(units: u64) -> ReservationVector {
    ReservationVector::from_fn(|_| units)
}

fn only(dimension: Dimension, units: u64) -> ReservationVector {
    ReservationVector::ZERO.with(dimension, units)
}

fn code<T: std::fmt::Debug>(result: Result<T, DimensionError>) -> &'static str {
    result.expect_err("refused").reason_code()
}

#[test]
fn dimensions_are_the_eighteen_roadmap_names_in_order() {
    let expected: Vec<&str> = "token cost call wall-time concurrency provider-quota invocation \
         cpu memory pids disk egress output artifact verifier-backlog effect probe cas-liability"
        .split(' ')
        .collect();
    assert_eq!(DIMENSION_COUNT, 18);
    assert_eq!(expected.len(), DIMENSION_COUNT);
    for (index, dimension) in Dimension::ALL.into_iter().enumerate() {
        assert_eq!(dimension.index(), index);
        assert_eq!(dimension.name(), expected[index]);
        assert_eq!(dimension.to_string(), expected[index]);
        let json = serde_json::to_string(&dimension).expect("serialize");
        assert_eq!(json, format!("\"{}\"", expected[index]), "serde name drift");
    }
    let unique: BTreeSet<&str> = Dimension::ALL.iter().map(|d| d.name()).collect();
    assert_eq!(unique.len(), DIMENSION_COUNT);
    assert!(ReservationVector::ZERO.is_zero());
    assert_eq!(uniform(3).nonzero().count(), DIMENSION_COUNT);
    assert_eq!(only(Dimension::Pids, 9).nonzero().count(), 1);
}

#[test]
fn reserve_is_all_or_nothing_and_names_first_exhausted_dimension() {
    let opening = uniform(100)
        .with(Dimension::Memory, 10)
        .with(Dimension::Probe, 10);
    let mut ledger = PolicyLedger::new(opening, ReservationVector::ZERO);
    let before = ledger.clone();
    let request = only(Dimension::Token, 50)
        .with(Dimension::Memory, 11)
        .with(Dimension::Probe, 11);
    let err = ledger
        .reserve("r1", ReserveClass::Incident, request)
        .expect_err("memory short");
    assert_eq!(
        err,
        DimensionError::Exhausted {
            dimension: Dimension::Memory,
            requested: 11,
            remaining: 10,
        }
    );
    assert_eq!(err.reason_code(), "BUDGET_DIMENSION_EXHAUSTED");
    assert_eq!(err.dimension(), Some(Dimension::Memory));
    assert_eq!(ledger, before, "token must not be partially taken");
    assert_eq!(ledger.state(Dimension::Token).remaining, 100);
    assert!(ledger.open().next().is_none());

    let request = request.with(Dimension::Memory, 10);
    let err = ledger
        .reserve("r1", ReserveClass::Incident, request)
        .expect_err("probe short");
    assert_eq!(err.dimension(), Some(Dimension::Probe));
    assert_eq!(ledger, before);

    let row = ledger
        .reserve(
            "r1",
            ReserveClass::Incident,
            request.with(Dimension::Probe, 10),
        )
        .expect("refusals did not consume the id");
    assert_eq!(row.class, ReserveClass::Incident);
    assert_eq!(ledger.state(Dimension::Token).reserved, 50);
    assert_eq!(ledger.state(Dimension::Memory).remaining, 0);
    assert_eq!(ledger.open().count(), 1);
    assert!(ledger.conserved());
}

#[test]
fn invalid_duplicate_and_not_found_refusals() {
    assert_policy_validation_refusals();
    let mut ledger = PolicyLedger::new(uniform(10), ReservationVector::ZERO);
    let one = only(Dimension::Call, 1);
    assert_eq!(
        code(ledger.reserve("", ReserveClass::Normal, one)),
        "BUDGET_RESERVATION_INVALID"
    );
    assert_eq!(
        code(ledger.reserve("zero", ReserveClass::Normal, ReservationVector::ZERO)),
        "BUDGET_RESERVATION_INVALID"
    );
    ledger
        .reserve("r", ReserveClass::Normal, one)
        .expect("first");
    assert_eq!(
        code(ledger.reserve("r", ReserveClass::Normal, one)),
        "BUDGET_RESERVATION_DUPLICATE"
    );
    ledger.release("r").expect("release");
    assert_eq!(
        code(ledger.reserve("r", ReserveClass::Normal, one)),
        "BUDGET_RESERVATION_DUPLICATE"
    );
    assert_eq!(
        code(ledger.settle("r", &UsageVector::UNKNOWN)),
        "BUDGET_RESERVATION_NOT_FOUND"
    );
    assert_eq!(
        ledger.release("missing").unwrap_err(),
        DimensionError::NotFound
    );
}

#[test]
fn settle_records_exact_under_over_and_unknown_per_dimension() {
    let mut ledger = PolicyLedger::new(uniform(100), ReservationVector::ZERO);
    let forecast = only(Dimension::Token, 10)
        .with(Dimension::Cost, 10)
        .with(Dimension::Egress, 10)
        .with(Dimension::Effect, 10);
    let reservation = ledger
        .reserve("r", ReserveClass::Normal, forecast)
        .expect("reserve");
    assert_eq!(&reservation.policy, ledger.admitted_policy().subject());
    let usage = UsageVector::UNKNOWN
        .with_known(Dimension::Token, 10)
        .with_known(Dimension::Cost, 4)
        .with_known(Dimension::Egress, 17)
        .with_known(Dimension::Probe, 3);
    let wrong_generation = policy(2);
    let before = ledger.clone();
    assert_eq!(
        code(ledger.settle_with_policy("r", &usage, Some(&wrong_generation))),
        "BUDGET_POLICY_GENERATION_MISMATCH"
    );
    assert_eq!(ledger, before, "wrong-generation settlement is atomic");
    let record = ledger.settle("r", &usage).expect("settle");
    assert_eq!(record.id, "r");
    assert_eq!(record.class, ReserveClass::Normal);
    assert_eq!(&record.policy, ledger.admitted_policy().subject());
    assert_eq!(record.forecast, forecast);
    assert_eq!(record.usage, usage);
    assert_eq!(
        record.errors.len(),
        18,
        "four forecast, one unforecast use, thirteen unforecast unknowns"
    );
    assert_eq!(record.unforecast_unknown().count(), 13);
    let outcome = |dimension| record.row(dimension).expect("row").outcome;
    assert_eq!(outcome(Dimension::Token), ForecastOutcome::Exact);
    assert_eq!(
        outcome(Dimension::Cost),
        ForecastOutcome::Under { residual: 6 }
    );
    assert_eq!(
        outcome(Dimension::Egress),
        ForecastOutcome::Over { overrun: 7 }
    );
    assert_eq!(
        outcome(Dimension::Effect),
        ForecastOutcome::Unknown { retained: 10 }
    );
    assert_eq!(
        outcome(Dimension::Probe),
        ForecastOutcome::UnforecastOverrun { overrun: 3 }
    );
    assert_eq!(record.row(Dimension::Probe).expect("row").forecast, 0);
    assert_eq!(
        record.row(Dimension::Effect).expect("row").usage,
        Usage::Unknown
    );
    assert_eq!(
        record.row(Dimension::Memory).expect("row").outcome,
        ForecastOutcome::UnforecastUnknown
    );
    assert_eq!(ledger.state(Dimension::Memory).unknown_events, 1);
    assert!(ledger.state(Dimension::Memory).has_unknown_liability());
    assert!(record.is_forecast_error_event());

    let token = ledger.state(Dimension::Token);
    assert_eq!(
        (token.remaining, token.settled, token.reserved),
        (90, 10, 0)
    );
    let cost = ledger.state(Dimension::Cost);
    assert_eq!((cost.remaining, cost.settled), (96, 4));
    let egress = ledger.state(Dimension::Egress);
    assert_eq!(
        (egress.remaining, egress.settled, egress.overrun),
        (90, 10, 7)
    );
    let effect = ledger.state(Dimension::Effect);
    assert_eq!(
        (effect.remaining, effect.retained, effect.reserved),
        (90, 10, 0)
    );
    let probe = ledger.state(Dimension::Probe);
    assert_eq!((probe.remaining, probe.overrun), (100, 3));
    assert!(ledger.conserved());
    assert!(ledger.open().next().is_none());

    ledger
        .reserve("exact", ReserveClass::Normal, only(Dimension::Disk, 5))
        .expect("reserve");
    let record = ledger
        .settle("exact", &UsageVector::known(&only(Dimension::Disk, 5)))
        .expect("settle");
    assert!(!record.is_forecast_error_event());
    assert_eq!(record.errors.len(), 1);
}

#[test]
fn a_class_cannot_spend_below_its_floor_but_emergency_classes_can() {
    let mut ledger = PolicyLedger::new(only(Dimension::Token, 100), ReservationVector::ZERO);
    ledger.assert_reserve_policy_refusals();
    let before = ledger.clone();
    let err = ledger
        .reserve("s0", ReserveClass::Speculative, only(Dimension::Token, 51))
        .expect_err("floor");
    assert_eq!(
        err,
        DimensionError::BelowFloor {
            dimension: Dimension::Token,
            class: ReserveClass::Speculative,
            floor: 50,
            remaining: 100,
            requested: 51,
        }
    );
    assert_eq!(err.reason_code(), "BUDGET_CLASS_FLOOR");
    assert_eq!(err.dimension(), Some(Dimension::Token));
    assert_eq!(ledger, before);

    let mut step = |id: &str, class: ReserveClass, units: u64| {
        ledger
            .reserve(id, class, only(Dimension::Token, units))
            .map(|_| ledger.state(Dimension::Token).remaining)
    };
    assert_eq!(step("s1", ReserveClass::Speculative, 50), Ok(50));
    assert!(matches!(
        step("n0", ReserveClass::Normal, 31),
        Err(DimensionError::BelowFloor { floor: 20, .. })
    ));
    assert_eq!(step("n1", ReserveClass::Normal, 30), Ok(20));
    assert!(matches!(
        step("i0", ReserveClass::IntegrationRepair, 11),
        Err(DimensionError::BelowFloor { floor: 10, .. })
    ));
    assert_eq!(step("i1", ReserveClass::IntegrationRepair, 10), Ok(10));
    assert!(matches!(
        step("h0", ReserveClass::HumanInteractive, 1),
        Err(DimensionError::BelowFloor { floor: 15, .. })
    ));
    assert_eq!(step("c1", ReserveClass::Critical, 5), Ok(5));
    assert!(matches!(
        step("c2", ReserveClass::Critical, 1),
        Err(DimensionError::BelowFloor { floor: 5, .. })
    ));
    assert_eq!(step("sec", ReserveClass::Security, 3), Ok(2));
    assert_eq!(step("inc", ReserveClass::Incident, 2), Ok(0));
    assert!(matches!(
        step("inc2", ReserveClass::Incident, 1),
        Err(DimensionError::Exhausted { remaining: 0, .. })
    ));
    assert!(ledger.conserved());

    ledger.release("s1").expect("release speculative");
    assert_eq!(ledger.state(Dimension::Token).remaining, 50);
    assert!(matches!(
        ledger.reserve("s2", ReserveClass::Speculative, only(Dimension::Token, 1)),
        Err(DimensionError::BelowFloor { floor: 50, .. })
    ));
    assert!(matches!(
        ledger.reserve(
            "big",
            ReserveClass::Speculative,
            only(Dimension::Token, 200)
        ),
        Err(DimensionError::Exhausted { .. })
    ));
}

#[test]
fn speculative_work_cannot_consume_critical_reserve() {
    let mut ledger = PolicyLedger::new(uniform(100), ReservationVector::ZERO);
    ledger
        .reserve("spec", ReserveClass::Speculative, uniform(50))
        .expect("speculative to its floor");
    ledger
        .reserve("crit", ReserveClass::Critical, uniform(45))
        .expect("critical digs into reserve");
    for dimension in Dimension::ALL {
        assert_eq!(ledger.state(dimension).remaining, 5);
        let err = ledger
            .reserve("spec2", ReserveClass::Speculative, only(dimension, 1))
            .expect_err("speculative cannot touch critical reserve");
        assert_eq!(err.reason_code(), "BUDGET_CLASS_FLOOR");
        assert_eq!(err.dimension(), Some(dimension));
    }
    ledger
        .settle("crit", &UsageVector::UNKNOWN)
        .expect("unknown");
    for dimension in Dimension::ALL {
        assert_eq!(ledger.state(dimension).retained, 45);
        assert!(ledger.unknown_as_headroom(dimension).is_err());
    }
}

fn vector(max: u64) -> impl Strategy<Value = ReservationVector> {
    prop::collection::vec(0..max, DIMENSION_COUNT)
        .prop_map(|units| ReservationVector::from_fn(|d| units[d.index()]))
}

fn class() -> impl Strategy<Value = ReserveClass> {
    (0..ReserveClass::LADDER.len()).prop_map(|rank| ReserveClass::LADDER[rank])
}

fn usage() -> impl Strategy<Value = UsageVector> {
    prop::collection::vec(prop::option::of(0u64..12), DIMENSION_COUNT).prop_map(|observed| {
        Dimension::ALL
            .into_iter()
            .fold(UsageVector::UNKNOWN, |usage, d| match observed[d.index()] {
                Some(units) => usage.with_known(d, units),
                None => usage.with_unknown(d),
            })
    })
}

#[derive(Clone, Debug)]
enum Op {
    Reserve(usize, ReserveClass, ReservationVector),
    Settle(usize, UsageVector),
    Release(usize),
}

const SLOTS: usize = 6;

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..SLOTS, class(), vector(8)).prop_map(|(s, c, v)| Op::Reserve(s, c, v)),
        (0..SLOTS, usage()).prop_map(|(s, u)| Op::Settle(s, u)),
        (0..SLOTS).prop_map(Op::Release),
    ]
}

proptest! {
    #[test]
    fn conservation_holds_across_random_interleavings(
        opening in vector(40),
        ops in prop::collection::vec(op(), 1..48),
    ) {
        let mut ledger = PolicyLedger::new(opening, ReservationVector::ZERO);
        let mut slots: Vec<Option<String>> = vec![None; SLOTS];
        for (seq, op) in ops.into_iter().enumerate() {
            let before = ledger.clone();
            let outcome = match op {
                Op::Reserve(slot, class, forecast) => {
                    let id = format!("s{slot}-{seq}");
                    let result = ledger.reserve(&id, class, forecast).map(|_| ());
                    if result.is_ok() {
                        slots[slot] = Some(id);
                    }
                    result
                }
                Op::Settle(slot, usage) => {
                    let id = slots[slot].take().unwrap_or_else(|| "missing".into());
                    ledger.settle(&id, &usage).map(|_| ())
                }
                Op::Release(slot) => {
                    let id = slots[slot].take().unwrap_or_else(|| "missing".into());
                    ledger.release(&id).map(|_| ())
                }
            };
            if outcome.is_err() {
                prop_assert_eq!(&ledger, &before, "refusal must change nothing");
            }
            prop_assert!(ledger.conserved());
            for d in Dimension::ALL {
                let (now, was) = (ledger.state(d), before.state(d));
                prop_assert!(now.remaining <= now.opening);
                prop_assert!(now.retained >= was.retained, "retained never returns");
                prop_assert!(now.settled >= was.settled);
                prop_assert!(now.unknown_events >= was.unknown_events, "events never vanish");
                prop_assert_eq!(ledger.headroom().get(d), now.remaining);
            }
        }
    }

    #[test]
    fn exhaustion_names_the_first_short_dimension(opening in vector(8), request in vector(10)) {
        let expected = Dimension::ALL
            .into_iter()
            .find(|d| request.get(*d) > opening.get(*d));
        let mut ledger = PolicyLedger::new(opening, ReservationVector::ZERO);
        let before = ledger.clone();
        let result = ledger.reserve("r", ReserveClass::Incident, request);
        match (expected, result) {
            (Some(d), Err(DimensionError::Exhausted { dimension, requested, remaining })) => {
                prop_assert_eq!(dimension, d);
                prop_assert_eq!(requested, request.get(d));
                prop_assert_eq!(remaining, opening.get(d));
                prop_assert_eq!(&ledger, &before);
            }
            (None, Ok(_)) => {
                prop_assert!(!request.is_zero());
                for d in Dimension::ALL {
                    prop_assert_eq!(ledger.state(d).reserved, request.get(d));
                }
                prop_assert!(ledger.conserved());
            }
            (None, Err(DimensionError::Invalid(_))) => prop_assert!(request.is_zero()),
            (expected, result) => prop_assert!(false, "{expected:?} vs {result:?}"),
        }
    }

    #[test]
    fn non_emergency_classes_never_cross_the_emergency_floor(
        opening in vector(64),
        ops in prop::collection::vec((3..ReserveClass::LADDER.len(), vector(16)), 1..32),
    ) {
        let mut ledger = PolicyLedger::new(opening, ReservationVector::ZERO);
        for (seq, (rank, forecast)) in ops.into_iter().enumerate() {
            let class = ReserveClass::LADDER[rank];
            prop_assert!(!ledger.admitted_policy().may_spend_emergency_reserve(class));
            let before = ledger.clone();
            match ledger.reserve(format!("r{seq}"), class, forecast) {
                Ok(_) => {}
                Err(DimensionError::BelowFloor { dimension, floor, remaining, requested, .. }) => {
                    prop_assert_eq!(&ledger, &before);
                    prop_assert!(requested <= remaining && remaining - requested < floor);
                    prop_assert_eq!(floor, ledger.admitted_policy().floor_units(class, opening.get(dimension)));
                }
                Err(DimensionError::Exhausted { .. } | DimensionError::Invalid(_)) => {
                    prop_assert_eq!(&ledger, &before);
                }
                Err(other) => prop_assert!(false, "unexpected {other:?}"),
            }
            for d in Dimension::ALL {
                prop_assert!(
                    ledger.state(d).remaining >= ledger.admitted_policy().emergency_floor_units(opening.get(d)),
                    "{class} crossed the emergency floor on {d}"
                );
            }
        }
        let headroom = ledger.headroom();
        if !headroom.is_zero() {
            ledger
                .reserve("incident", ReserveClass::Incident, headroom)
                .expect("incident may drain the emergency reserve");
            prop_assert!(ledger.headroom().is_zero());
        }
    }
}
