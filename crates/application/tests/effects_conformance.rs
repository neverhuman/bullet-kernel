//! Shared effect conformance run against the memory ledger. The SQLite
//! adapter runs the same suite in `bullet-adapters`.

use bullet_application::conformance_effects::check_effects;
use bullet_application::MemoryLedger;

#[test]
fn memory_ledger_passes_effect_conformance() {
    check_effects(MemoryLedger::new).expect("memory ledger effect conformance");
}
