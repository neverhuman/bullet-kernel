use bullet_budgets::{
    BudgetPolicyError, BudgetPolicySnapshot, Dimension, DimensionError, ReservationVector,
    ReserveClass, ReserveClassFloor, SettlementRecord, UsageVector, VectorLedger,
    VectorReservation,
};
use std::ops::{Deref, DerefMut};

const FIXTURE_FLOORS: [u16; ReserveClass::LADDER.len()] = [0, 2, 5, 10, 15, 20, 40, 50];

pub fn policy(generation: u64) -> BudgetPolicySnapshot {
    policy_with_floors(generation, FIXTURE_FLOORS)
}

pub fn policy_with_floors(
    generation: u64,
    floors: [u16; ReserveClass::LADDER.len()],
) -> BudgetPolicySnapshot {
    BudgetPolicySnapshot::try_new(
        "test-only:budget-policy-fixture",
        generation,
        ReserveClass::LADDER
            .into_iter()
            .zip(floors)
            .map(|(class, floor_percent)| ReserveClassFloor {
                class,
                floor_percent,
            }),
    )
    .expect("valid test-only policy")
}

fn rules(floors: [u16; ReserveClass::LADDER.len()]) -> Vec<ReserveClassFloor> {
    ReserveClass::LADDER
        .into_iter()
        .zip(floors)
        .map(|(class, floor_percent)| ReserveClassFloor {
            class,
            floor_percent,
        })
        .collect()
}

pub fn assert_policy_validation_refusals() {
    let code = |result: Result<BudgetPolicySnapshot, BudgetPolicyError>| {
        result.expect_err("policy must refuse").reason_code()
    };
    let mut missing = rules(FIXTURE_FLOORS);
    assert_eq!(
        code(BudgetPolicySnapshot::try_new("", 1, rules(FIXTURE_FLOORS))),
        "BUDGET_POLICY_SUBJECT_INVALID"
    );
    assert_eq!(
        code(BudgetPolicySnapshot::try_new(
            "not canonical",
            1,
            rules(FIXTURE_FLOORS)
        )),
        "BUDGET_POLICY_SUBJECT_INVALID"
    );
    assert_eq!(
        code(BudgetPolicySnapshot::try_new(
            "fixture",
            0,
            rules(FIXTURE_FLOORS)
        )),
        "BUDGET_POLICY_SUBJECT_INVALID"
    );
    assert_eq!(
        code(BudgetPolicySnapshot::try_new(
            "fixture",
            u64::MAX,
            rules(FIXTURE_FLOORS)
        )),
        "BUDGET_POLICY_SUBJECT_INVALID"
    );
    missing.pop();
    assert_eq!(
        code(BudgetPolicySnapshot::try_new("fixture", 1, missing)),
        "BUDGET_POLICY_CLASS_MISSING"
    );
    let mut duplicate = rules(FIXTURE_FLOORS);
    duplicate.push(duplicate[0]);
    assert_eq!(
        code(BudgetPolicySnapshot::try_new("fixture", 1, duplicate)),
        "BUDGET_POLICY_CLASS_DUPLICATE"
    );
    let mut out_of_range = FIXTURE_FLOORS;
    out_of_range[ReserveClass::Speculative.rank()] = 101;
    assert_eq!(
        code(BudgetPolicySnapshot::try_new(
            "fixture",
            1,
            rules(out_of_range)
        )),
        "BUDGET_POLICY_FLOOR_OUT_OF_RANGE"
    );
    let mut non_monotone = FIXTURE_FLOORS;
    non_monotone[ReserveClass::Normal.rank()] = 15;
    assert_eq!(
        code(BudgetPolicySnapshot::try_new(
            "fixture",
            1,
            rules(non_monotone)
        )),
        "BUDGET_POLICY_FLOOR_NON_MONOTONE"
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyLedger {
    policy: BudgetPolicySnapshot,
    ledger: VectorLedger,
}

impl PolicyLedger {
    pub fn new(opening: ReservationVector, unknown: ReservationVector) -> Self {
        Self::with_generation(opening, unknown, 1)
    }

    pub fn with_generation(
        opening: ReservationVector,
        unknown: ReservationVector,
        generation: u64,
    ) -> Self {
        let policy = policy(generation);
        let ledger = VectorLedger::new(opening, unknown, policy.clone());
        Self { policy, ledger }
    }

    pub fn admitted_policy(&self) -> &BudgetPolicySnapshot {
        &self.policy
    }

    pub fn reserve(
        &mut self,
        id: impl Into<String>,
        class: ReserveClass,
        forecast: ReservationVector,
    ) -> Result<VectorReservation, DimensionError> {
        self.ledger.reserve(id, class, forecast, Some(&self.policy))
    }

    pub fn reserve_with_policy(
        &mut self,
        id: impl Into<String>,
        class: ReserveClass,
        forecast: ReservationVector,
        policy: Option<&BudgetPolicySnapshot>,
    ) -> Result<VectorReservation, DimensionError> {
        self.ledger.reserve(id, class, forecast, policy)
    }

    pub fn settle(
        &mut self,
        id: &str,
        usage: &UsageVector,
    ) -> Result<SettlementRecord, DimensionError> {
        self.ledger.settle(id, usage, Some(&self.policy))
    }

    pub fn settle_with_policy(
        &mut self,
        id: &str,
        usage: &UsageVector,
        policy: Option<&BudgetPolicySnapshot>,
    ) -> Result<SettlementRecord, DimensionError> {
        self.ledger.settle(id, usage, policy)
    }

    pub fn assert_reserve_policy_refusals(&mut self) {
        // Leaves 15/100: admitted Normal floor 20 refuses it, while the hostile
        // floor 12 would admit it if snapshot substitution were possible.
        let request = ReservationVector::ZERO.with(Dimension::Token, 85);
        let lowered = policy_with_floors(1, [0, 1, 3, 7, 11, 12, 30, 45]);
        assert_ne!(
            lowered.subject().policy_id(),
            self.policy.subject().policy_id(),
            "lower floors must change policy identity"
        );
        let before = self.clone();
        assert_eq!(
            self.reserve_with_policy("missing-policy", ReserveClass::Normal, request, None)
                .unwrap_err()
                .reason_code(),
            "BUDGET_POLICY_MISSING"
        );
        assert_eq!(
            self.reserve_with_policy(
                "lowered-floor",
                ReserveClass::Normal,
                request,
                Some(&lowered)
            )
            .unwrap_err()
            .reason_code(),
            "BUDGET_POLICY_SNAPSHOT_MISMATCH"
        );
        let other_source = BudgetPolicySnapshot::try_new(
            "test-only:other-policy-source",
            1,
            rules(FIXTURE_FLOORS),
        )
        .expect("valid other source");
        assert_eq!(
            self.reserve_with_policy(
                "wrong-provenance",
                ReserveClass::Normal,
                request,
                Some(&other_source),
            )
            .unwrap_err()
            .reason_code(),
            "BUDGET_POLICY_SNAPSHOT_MISMATCH"
        );
        let next = policy(2);
        assert_eq!(
            self.reserve_with_policy("new-generation", ReserveClass::Normal, request, Some(&next))
                .unwrap_err()
                .reason_code(),
            "BUDGET_POLICY_GENERATION_MISMATCH"
        );
        assert!(matches!(
            self.reserve("admitted-floor", ReserveClass::Normal, request),
            Err(DimensionError::BelowFloor { floor: 20, .. })
        ));
        assert_eq!(self, &before, "policy refusals must be atomic");
    }
}

impl Deref for PolicyLedger {
    type Target = VectorLedger;

    fn deref(&self) -> &Self::Target {
        &self.ledger
    }
}

impl DerefMut for PolicyLedger {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ledger
    }
}
