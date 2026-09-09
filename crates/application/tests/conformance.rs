//! Shared ledger conformance run against the memory ledger. The SQLite
//! adapter runs the same suite in `bullet-adapters`.

use bullet_application::conformance::check_all;
use bullet_application::MemoryLedger;

#[test]
fn memory_ledger_passes_shared_conformance() {
    check_all(MemoryLedger::new).expect("memory ledger conformance");
}
