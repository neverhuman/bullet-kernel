//! ZERO_TESTS / INFRA_ERROR / TIMED_OUT never become PASS.

use bullet_domain::GateOutcome;
use bullet_verifier_core::aggregate::{aggregate, any_pass, executable_digest, OracleClass};
use bullet_verifier_core::gate::GateRun;

fn run(outcome: GateOutcome, reason: Option<&str>) -> GateRun {
    GateRun {
        outcome,
        reason: reason.map(str::to_string),
        detail: None,
        exit_code: None,
    }
}

#[test]
fn executable_digest_is_stable() {
    let first = executable_digest(&["/usr/bin/grep".into(), "-qx".into()]);
    let second = executable_digest(&["/usr/bin/grep".into(), "-qx".into()]);
    assert_eq!(first, second);
}

#[test]
fn zero_tests_infra_and_timeout_never_pass() {
    let zero = run(GateOutcome::Pass, Some("ZERO_TESTS"));
    let infra = run(GateOutcome::InfraError, None);
    let timeout = run(GateOutcome::TimedOut, None);
    let argv: Vec<String> = vec!["/bin/true".into()];
    let aggregated = aggregate(&[
        (
            "ZERO_TESTS",
            argv.as_slice(),
            &zero,
            OracleClass::Independent,
        ),
        ("ok", argv.as_slice(), &infra, OracleClass::Independent),
        ("ok", argv.as_slice(), &timeout, OracleClass::Independent),
    ]);
    assert!(!any_pass(&aggregated));
    assert_eq!(aggregated[0].outcome, GateOutcome::NotRun);
    assert_eq!(aggregated[1].outcome, GateOutcome::InfraError);
    assert_eq!(aggregated[2].outcome, GateOutcome::TimedOut);
}

#[test]
fn oracle_modifying_diff_is_classified() {
    let pass = run(GateOutcome::Pass, None);
    let argv: Vec<String> = vec!["/bin/true".into()];
    let aggregated = aggregate(&[(
        "ok",
        argv.as_slice(),
        &pass,
        OracleClass::OracleModifyingDiff,
    )]);
    assert_eq!(aggregated[0].oracle_class, OracleClass::OracleModifyingDiff);
}
