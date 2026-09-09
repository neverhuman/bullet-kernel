//! Offline five-plane transaction-component demo binary.

mod transaction_demo {
    pub(super) mod app;
    pub(super) mod support;
    pub(super) mod verifier_binary;
}

fn main() -> std::process::ExitCode {
    transaction_demo::app::main_entry()
}
