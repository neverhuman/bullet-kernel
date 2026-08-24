//! JeryuForge refuses everything without an operator-authenticated token
//! (ADR 0002) and performs no live calls. The one live probe below is
//! read-only, expects the documented 401, and is ignored by default.

use bullet_effects_core::{
    ForgeEffects, JeryuForge, PushRequest, TokenSource, JERYU_BASE_URL, JERYU_TOKEN_ENV,
};
use std::io::{Read, Write};

fn push_request() -> PushRequest {
    PushRequest {
        workspace_repo: std::path::PathBuf::from("/nonexistent"),
        ref_name: "refs/heads/bullet/candidate/x".into(),
        expected_old_oid: "0".repeat(40),
        new_oid: "b".repeat(40),
    }
}

/// One test covers all three probe scenarios sequentially because they
/// mutate process environment variables.
#[test]
fn token_probe_and_typed_refusals() {
    let home = tempfile::tempdir().expect("tempdir");
    let saved_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home.path());
    std::env::remove_var(JERYU_TOKEN_ENV);

    // No token anywhere: unauthenticated, typed refusal, no live call.
    let mut forge = JeryuForge::probe(JERYU_BASE_URL);
    assert_eq!(forge.token_source(), TokenSource::None);
    let descriptor = forge.descriptor();
    assert!(!descriptor.authenticated);
    assert!(!descriptor.can_push_candidate_ref);
    let err = forge
        .push_candidate_ref(&push_request())
        .expect_err("refused");
    assert_eq!(err.reason_code(), "FORGE_UNAUTHENTICATED");
    let err = forge
        .read_ref("refs/heads/bullet/candidate/x")
        .expect_err("refused");
    assert_eq!(err.reason_code(), "FORGE_UNAUTHENTICATED");
    // Namespace guard fires even before the auth refusal.
    let err = forge.read_ref("refs/heads/main").expect_err("denied");
    assert_eq!(err.reason_code(), "REF_DENIED");

    // A gh hosts entry exists, but ADR 0002 records that token as invalid.
    std::fs::create_dir_all(home.path().join(".config/gh")).expect("mkdir");
    std::fs::write(
        home.path().join(".config/gh/hosts.yml"),
        "\"127.0.0.1:8787\":\n    user: jeryu\n    oauth_token: gho_invalid\n",
    )
    .expect("hosts");
    let mut forge = JeryuForge::probe(JERYU_BASE_URL);
    assert_eq!(forge.token_source(), TokenSource::GhHostsInvalid);
    assert!(!forge.descriptor().authenticated);
    let err = forge
        .push_candidate_ref(&push_request())
        .expect_err("refused");
    assert_eq!(err.reason_code(), "FORGE_UNAUTHENTICATED");

    // An operator-supplied token exists, but no capability probe receipt
    // does: mutating methods still refuse with a typed code, no live call.
    std::env::set_var(JERYU_TOKEN_ENV, "operator-token");
    let mut forge = JeryuForge::probe(JERYU_BASE_URL);
    assert_eq!(forge.token_source(), TokenSource::Environment);
    assert!(forge.descriptor().authenticated);
    let err = forge
        .push_candidate_ref(&push_request())
        .expect_err("refused");
    assert_eq!(err.reason_code(), "CAPABILITY_UNPROBED");

    std::env::remove_var(JERYU_TOKEN_ENV);
    match saved_home {
        Some(home) => std::env::set_var("HOME", home),
        None => std::env::remove_var("HOME"),
    }
}

/// Read-only liveness probe of the running forge (expects the documented
/// unauthenticated 401 from ADR 0002). Run explicitly with `-- --ignored`.
#[test]
#[ignore = "touches the live Jeryu forge at 127.0.0.1:8787 (read-only GET)"]
fn live_api_v3_answers_401_without_auth() {
    let addr: std::net::SocketAddr = "127.0.0.1:8787".parse().expect("addr");
    let mut stream = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2))
        .expect("jeryu is running");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("timeout");
    stream
        .write_all(b"GET /api/v3 HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nConnection: close\r\n\r\n")
        .expect("request");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response.lines().next().unwrap_or_default().to_string();
    assert!(status.contains("401"), "expected 401, got: {status}");
}
