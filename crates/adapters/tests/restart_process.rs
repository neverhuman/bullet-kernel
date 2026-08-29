//! Real process-death coverage for SQLite-owned local-bare recovery.

#[path = "restart_process/assertions.rs"]
mod assertions;
#[path = "restart_process/cases.rs"]
mod cases;
#[path = "restart_process/fixture.rs"]
mod fixture;
#[path = "restart_process/model.rs"]
mod model;
#[path = "restart_process/process.rs"]
mod process;
#[path = "restart_process/snapshot.rs"]
mod snapshot;
#[path = "restart_process/worker.rs"]
mod worker;

#[test]
fn process_restart_fault_matrix_uses_separate_os_processes() {
    cases::run_matrix().expect("six-process recovery matrix");
}

#[test]
fn recovery_worker_process() {
    if let Err(error) = worker::run_from_private_channel() {
        process::write_worker_error(&error);
        panic!("restart worker: {error}");
    }
}
#[path = "restart_process/hostiles.rs"]
mod hostiles;
