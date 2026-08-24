//! Exhaustive legal-edge table for the spec section 23.1 effect machine.

use bullet_application::EffectState;

use EffectState::*;

const LEGAL: [(EffectState, EffectState); 18] = [
    (Proposed, Authorized),
    (Proposed, Failed),
    (Authorized, Failed),
    (Authorized, Dispatching),
    (Dispatching, ReceiptPending),
    (Dispatching, OutcomeUnknown),
    (Dispatching, Quarantined),
    (ReceiptPending, OutcomeUnknown),
    (ReceiptPending, Verified),
    (ReceiptPending, Quarantined),
    (OutcomeUnknown, Verified),
    (OutcomeUnknown, Dispatching),
    (OutcomeUnknown, OrphanedRemote),
    (OutcomeUnknown, Quarantined),
    (Verified, Committed),
    (Quarantined, CompensationPending),
    (CompensationPending, Compensating),
    (Compensating, Compensated),
];

#[test]
fn every_edge_outside_the_table_is_a_typed_refusal() {
    for from in EffectState::all() {
        for to in EffectState::all() {
            let legal = LEGAL.contains(&(from, to));
            match from.transition(to) {
                Ok(next) => {
                    assert!(legal, "{:?} -> {:?} succeeded but is not legal", from, to);
                    assert_eq!(next, to);
                }
                Err(err) => {
                    assert!(!legal, "{:?} -> {:?} refused but is legal: {err}", from, to);
                    assert_eq!(err.reason_code(), "INVALID_TRANSITION");
                }
            }
        }
    }
}

#[test]
fn self_loops_are_illegal() {
    for state in EffectState::all() {
        assert!(state.transition(state).is_err(), "{state:?} self-loop");
    }
}

#[test]
fn wire_names_round_trip() {
    for state in EffectState::all() {
        assert_eq!(EffectState::parse(state.as_str()).expect("parse"), state);
        let json = serde_json::to_string(&state).expect("encode");
        assert_eq!(json, format!("\"{}\"", state.as_str()));
    }
    assert_eq!(
        EffectState::parse("VERIFIED?")
            .expect_err("bad")
            .reason_code(),
        "UNKNOWN_STATE"
    );
}

#[test]
fn classification_flags_are_honest() {
    assert!(OutcomeUnknown.needs_reconcile());
    assert!(!Verified.needs_reconcile());
    for state in [Dispatching, ReceiptPending, OutcomeUnknown] {
        assert!(state.is_unresolved(), "{state:?}");
    }
    for state in [Committed, Failed, Compensated, OrphanedRemote] {
        assert!(state.is_terminal(), "{state:?}");
        assert!(!state.is_unresolved(), "{state:?}");
    }
    assert!(!Quarantined.is_terminal());
    assert!(!Quarantined.is_unresolved());
}
