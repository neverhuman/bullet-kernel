//! Offline five-plane transaction-component demo binary.

mod transaction_demo {
    pub(super) mod app;
    pub(super) mod support;
}

fn main() -> std::process::ExitCode {
    transaction_demo::app::main_entry()
}
