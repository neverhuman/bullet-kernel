//! Offline component bridge: durable farmd UDS, product runner, production
//! gitd, a verifier fixture, and LocalBareForge.

mod transaction_offline {
    #[path = "single_candidate_app.rs"]
    pub(super) mod app;
    pub(super) mod artifact_custody;
    pub(super) mod attempt_cleanup;
    pub(super) mod chaos;
    pub(super) mod command_input;
    pub(super) mod dispatch;
    #[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
    pub(super) mod farmd_fixture;
    pub(super) mod forge_chain;
    #[cfg(debug_assertions)]
    pub(super) mod process_observation;
    pub(super) mod runner_probe;
    pub(super) mod scope_admission;
    pub(super) mod signed_observation;
    pub(super) mod signed_verification;
    pub(super) mod sim_provider;
    pub(super) mod support;
    #[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
    pub(super) mod synthetic_selection;
    pub(super) mod verifier_binary;
    pub(super) mod verifier_process;
}

fn main() -> std::process::ExitCode {
    match tokio::runtime::Runtime::new()
        .expect("tokio")
        .block_on(transaction_offline::dispatch::run())
    {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bullet-transaction-offline: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}
