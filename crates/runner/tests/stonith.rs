//! A7 STONITH inequality (WI-34): the runner's monotonic self-kill deadline
//! fires strictly before the server lease expiry for every admissible TTL, the
//! remaining grace is strictly inside the TTL, and the one configuration that
//! breaks the inequality — a zero TTL — is refused by the lease validator, by
//! the heartbeat supervisor, and by the policy validator (the hub-mirrored
//! `UNSAFE_POLICY` reason).

use bullet_application::policy_snapshot::{
    self_kill_grace_precedes_expiry, validate_policy, LoadedPolicy, STONITH_REASON,
};
use bullet_application::records::{validate_lease_ttl, MAX_LEASE_TTL_SECONDS};
use bullet_application::{materialize_plan, LeaseService, MemoryLedger, PlanInput};
use bullet_domain::schema_bundle::PolicySnapshotV1;
use bullet_domain::{AttemptId, RunnerId, TaskClass, VariantId};
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical};
use bullet_runner_core::lease::HeartbeatCall;
use bullet_runner_core::{
    start_heartbeat, Clock, DirectLeaseClient, HeartbeatConfig, ManualClock, RunnerError,
    SelfKillDeadline,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const COMMITTED_POLICY: &[u8] =
    include_bytes!("../../application/tests/fixtures/policy-v1alpha1.json");

fn committed_policy() -> PolicySnapshotV1 {
    decode_canonical(COMMITTED_POLICY).expect("committed policy decodes")
}

/// The server-side lease window of a real single-transaction acquisition.
fn server_window(ttl_seconds: i64) -> Duration {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(
        &mut ledger,
        &format!("stonith-{ttl_seconds}"),
        &PlanInput {
            title: "stonith".into(),
            objective: "lease window".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("plan");
    let (_, _, grant) = LeaseService::acquire(&mut ledger, &graph, 0, "stonith", ttl_seconds)
        .expect("lease acquisition");
    assert_eq!(grant.lease.ttl_seconds, ttl_seconds);
    let issued =
        chrono::DateTime::parse_from_rfc3339(&grant.lease.heartbeat_at).expect("heartbeat_at");
    let expires =
        chrono::DateTime::parse_from_rfc3339(&grant.lease.expires_at).expect("expires_at");
    (expires - issued).to_std().expect("expiry after issue")
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).expect("millisecond range")
}

#[test]
fn policy_maximum_and_lease_validator_agree_and_satisfy_the_inequality() {
    let policy = committed_policy();
    validate_policy(&policy).expect("committed policy validates");
    let maximum = policy.budget_policy.maximum_lease_ttl_seconds;
    assert_eq!(maximum, 15, "the frozen policy maximum is 15 s");
    assert_eq!(
        i64::try_from(maximum).expect("fits"),
        MAX_LEASE_TTL_SECONDS,
        "policy maximum and lease validator maximum are one number"
    );
    assert!(self_kill_grace_precedes_expiry(maximum));
}

#[test]
fn runner_deadline_precedes_server_expiry_for_every_admitted_ttl() {
    for ttl_seconds in 1..=MAX_LEASE_TTL_SECONDS {
        validate_lease_ttl(ttl_seconds).expect("admitted TTL");
        let ttl_u64 = u64::try_from(ttl_seconds).expect("positive");
        let ttl = Duration::from_secs(ttl_u64);
        let expiry = server_window(ttl_seconds);
        assert_eq!(
            expiry, ttl,
            "{ttl_seconds}s: server expiry is exactly the admitted TTL"
        );

        let clock = ManualClock::new();
        let deadline = SelfKillDeadline::new(clock.now(), ttl);
        let budget = deadline.budget();
        assert_eq!(
            budget,
            ttl / 5 * 4,
            "{ttl_seconds}s: budget is 4/5 of the TTL"
        );
        assert!(
            budget < expiry,
            "{ttl_seconds}s: runner deadline {budget:?} must be strictly earlier than expiry {expiry:?}"
        );
        let grace = expiry - budget;
        assert!(
            !grace.is_zero() && grace < expiry,
            "{ttl_seconds}s: grace {grace:?} must be strictly inside the TTL"
        );
        assert!(self_kill_grace_precedes_expiry(ttl_u64));

        // On the mocked clock the deadline fires at exactly the budget, which
        // is strictly before the expiry instant.
        clock.set_ms(millis(budget) - 1);
        assert!(!deadline.expired(clock.now()));
        clock.set_ms(millis(budget));
        assert!(deadline.expired(clock.now()));
        assert!(millis(budget) < millis(expiry));
    }
}

#[tokio::test]
async fn zero_ttl_is_the_violating_configuration_and_is_refused_everywhere() {
    // Runner arithmetic: grace == budget == TTL == 0, so the local deadline is
    // not strictly earlier than the expiry — it coincides with issuance.
    let issued = Duration::from_millis(5);
    let deadline = SelfKillDeadline::new(issued, Duration::ZERO);
    assert_eq!(deadline.budget(), Duration::ZERO);
    assert!(
        deadline.expired(issued),
        "a zero TTL makes the deadline coincide with the expiry"
    );
    assert!(!self_kill_grace_precedes_expiry(0));
    assert!(self_kill_grace_precedes_expiry(1));

    // The lease validator refuses the TTL outright.
    assert_eq!(
        validate_lease_ttl(0).unwrap_err().reason_code(),
        "INVALID_LEASE_TTL"
    );

    // The heartbeat supervisor refuses before spawning anything.
    let ledger = Arc::new(Mutex::new(MemoryLedger::new()));
    let client = Arc::new(DirectLeaseClient::new(ledger));
    let call = HeartbeatCall {
        variant_id: VariantId::from_seed("stonith"),
        attempt_id: AttemptId::from_seed("stonith"),
        fence: 1,
        runner_id: RunnerId::from_seed("stonith"),
        runner_epoch: 1,
        workspace_nonce: [0u8; 32],
        ttl_seconds: 0,
    };
    let refusal = start_heartbeat(
        client,
        call,
        HeartbeatConfig::default(),
        Arc::new(ManualClock::new()),
    )
    .err()
    .expect("zero TTL heartbeat refused");
    match refusal {
        RunnerError::Lease { code, .. } => assert_eq!(code, "INVALID_LEASE_TTL"),
        other => panic!("unexpected refusal: {other:?}"),
    }

    // The policy validator refuses the violating maximum with the hub reason,
    // structurally and through the byte loader alike.
    let mut policy = committed_policy();
    policy.budget_policy.maximum_lease_ttl_seconds = 0;
    let structural = validate_policy(&policy).unwrap_err();
    assert_eq!(structural.reason_code(), "POLICY_INVALID");
    assert!(
        structural
            .to_string()
            .ends_with(&format!("UNSAFE_POLICY: {STONITH_REASON}")),
        "{structural}"
    );
    let bytes = canonical_json(&policy).expect("canonical bytes");
    let loaded = LoadedPolicy::from_bytes(&bytes).unwrap_err();
    assert_eq!(loaded.to_string(), structural.to_string());

    // Above the maximum stays the generic conservatism refusal: the STONITH
    // rule is checked after the conservatism set, never instead of it.
    let mut high = committed_policy();
    high.budget_policy.maximum_lease_ttl_seconds = 16;
    let high_refusal = validate_policy(&high).unwrap_err();
    assert!(
        high_refusal.to_string().contains("UNSAFE_POLICY: v1alpha1"),
        "{high_refusal}"
    );
}
