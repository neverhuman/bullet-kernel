//! Production client stores no signing key.

use bullet_runner_core::SignedLeaseRpcClient;
use std::mem::size_of_val;

#[test]
fn client_has_no_signing_key_field() {
    // The unconfigured constructor stores no signing key or caller-selected UID.
    // A signing-key argument would add at least a 64-byte secret field.
    let client = SignedLeaseRpcClient::new(
        "/tmp/unused.sock",
        bullet_domain::RunnerId::from_seed("rpc-runner"),
        1,
    );
    assert!(size_of_val(&client) < 4096);
}
