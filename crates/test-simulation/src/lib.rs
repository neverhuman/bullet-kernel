//! Shared simulation helpers for kernel tests.

pub use bullet_adapters::{ProviderSimulator, ScmSimulator};
pub use bullet_application::{run_demo, MemoryLedger};

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
}
