//! Shared simulation helpers for kernel tests.

pub mod harness_tape;

pub use bullet_adapters::{ProviderSimulator, ScmSimulator};
pub use bullet_application::{run_demo, MemoryLedger};
pub use bullet_harness_core as harness_core;
pub use bullet_harness_sim as harness_sim;
pub use bullet_harness_sim::SimAdapter;
pub use harness_tape::{load_tape, tape_claims_authoritative_done, HarnessTape};

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::Observation;

    #[test]
    fn council_then_demo() {
        let sim = ProviderSimulator;
        assert_eq!(sim.planning_council().len(), 3);
        let mut ledger = MemoryLedger::new();
        let receipt = run_demo(&mut ledger).expect("demo");
        assert!(receipt.stale_refused);
        let lost = ScmSimulator {
            lose_response: true,
        }
        .push_candidate("refs/heads/x");
        assert!(matches!(lost, Observation::Unknown { .. }));
    }

    #[test]
    fn false_done_tape_is_not_authoritative() {
        let tape = load_tape("false-done").expect("tape");
        assert!(!tape.events.is_empty());
        assert!(!tape_claims_authoritative_done(&tape));
    }

    #[test]
    fn unknown_quota_tape_blocks_dispatch() {
        let tape = load_tape("quota-unknown").expect("tape");
        let blocked = tape.events.iter().any(|event| {
            event.get("kind").and_then(serde_json::Value::as_str) == Some("dispatch_blocked")
        });
        assert!(blocked);
    }
}
