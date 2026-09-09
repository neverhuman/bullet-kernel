//! ZERO_TESTS / INFRA_ERROR / TIMED_OUT never become PASS.

use bullet_domain::{Digest, GateOutcome};
use bullet_verifier_core::aggregate::{aggregate, catalog_argv_digest, OracleClass};
use bullet_verifier_core::gate::GateRun;

fn run(outcome: GateOutcome, reason: Option<&str>) -> GateRun {
    GateRun {
        outcome,
        reason: reason.map(str::to_string),
        detail: None,
        exit_code: None,
    }
}

fn executable_bytes(seed: &str) -> Digest {
    Digest::of(seed.as_bytes())
}

#[test]
fn catalog_argv_digest_is_framed_and_stable() {
    let first = catalog_argv_digest(&["/usr/bin/grep".into(), "-qx".into()]);
    let second = catalog_argv_digest(&["/usr/bin/grep".into(), "-qx".into()]);
    assert_eq!(first, second);
    assert_ne!(
        catalog_argv_digest(&["a\0b".into()]),
        catalog_argv_digest(&["a".into(), "b".into()]),
        "embedded NUL cannot alias an argument boundary"
    );
    assert_ne!(
        catalog_argv_digest(&[]),
        catalog_argv_digest(&[String::new()]),
        "empty argv cannot alias one empty argument"
    );
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
            executable_bytes("zero-tool"),
            &zero,
            OracleClass::Independent,
        ),
        (
            "ok",
            argv.as_slice(),
            executable_bytes("infra-tool"),
            &infra,
            OracleClass::Independent,
        ),
        (
            "ok",
            argv.as_slice(),
            executable_bytes("timeout-tool"),
            &timeout,
            OracleClass::Independent,
        ),
    ])
    .expect("aggregate nonempty gates");
    assert_eq!(
        aggregate(&[]).expect_err("empty gate set").reason_code(),
        "BAD_INPUT"
    );
    assert_eq!(aggregated[0].outcome(), GateOutcome::NotRun);
    assert_eq!(aggregated[1].outcome(), GateOutcome::InfraError);
    assert_eq!(aggregated[2].outcome(), GateOutcome::TimedOut);
}

#[test]
fn oracle_modifying_diff_is_classified() {
    let pass = run(GateOutcome::Pass, None);
    let argv: Vec<String> = vec!["/bin/true".into()];
    let aggregated = aggregate(&[(
        "ok",
        argv.as_slice(),
        executable_bytes("oracle-tool"),
        &pass,
        OracleClass::OracleModifyingDiff,
    )])
    .expect("aggregate oracle-modifying gate");
    assert_eq!(
        aggregated[0].oracle_class(),
        OracleClass::OracleModifyingDiff
    );
    assert_eq!(aggregated[0].outcome(), GateOutcome::Invalidated);

    let independent = aggregate(&[
        (
            "ok",
            argv.as_slice(),
            executable_bytes("tool-v1"),
            &pass,
            OracleClass::Independent,
        ),
        (
            "ok",
            argv.as_slice(),
            executable_bytes("tool-v2"),
            &pass,
            OracleClass::Independent,
        ),
    ])
    .expect("aggregate independent gates");
    assert!(independent.iter().all(|gate| {
        gate.outcome() == GateOutcome::Pass && gate.oracle_class() == OracleClass::Independent
    }));
    assert_eq!(
        independent[0].catalog_argv_digest(),
        independent[1].catalog_argv_digest(),
        "catalog argv is the same"
    );
    assert_ne!(
        independent[0].executable_bytes_digest(),
        independent[1].executable_bytes_digest(),
        "different executable bytes remain distinct subjects"
    );
    let fail = run(GateOutcome::Fail, None);
    let mixed = aggregate(&[
        (
            "ok",
            argv.as_slice(),
            executable_bytes("pass-tool"),
            &pass,
            OracleClass::Independent,
        ),
        (
            "failed",
            argv.as_slice(),
            executable_bytes("fail-tool"),
            &fail,
            OracleClass::Independent,
        ),
    ])
    .expect("aggregate mixed gates");
    assert_eq!(mixed[0].outcome(), GateOutcome::Pass);
    assert_eq!(mixed[1].outcome(), GateOutcome::Fail);
}
