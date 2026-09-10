use super::*;
use crate::auth::secret_digest;
use bullet_adapters::SqliteLedger;
use bullet_application::operator_sessions::{
    BootstrapRegistration, OperatorSessionStore, SessionIssue,
};
use futures_util::StreamExt;
use std::{collections::VecDeque, time::Duration};

const ORIGIN: &str = "http://127.0.0.1:7420";
fn issue(store: &mut SqliteLedger, seed: &str, lifetime_seconds: u32) -> (HeaderMap, SessionIssue) {
    let bearer = format!("ses_{}", Digest::of(seed.as_bytes()).to_hex());
    let bootstrap_digest = Digest::of(format!("bootstrap:{seed}").as_bytes());
    store
        .register_operator_bootstrap(&BootstrapRegistration {
            digest: bootstrap_digest,
            proposed_operator_id: format!("opr_{}", Digest::of(b"operator").to_hex()),
            origin: ORIGIN.into(),
            lifetime_seconds: 600,
        })
        .unwrap();
    let request = SessionIssue {
        bootstrap_digest,
        session_id: format!("sid_{}", Digest::of(seed.as_bytes()).to_hex()),
        bearer_digest: secret_digest("session", &bearer),
        csrf_digest: Digest::of(seed.as_bytes()),
        origin: ORIGIN.into(),
        lifetime_seconds,
    };
    store.exchange_operator_bootstrap(&request).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("bullet_session={bearer}").parse().unwrap(),
    );
    (headers, request)
}
fn private_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().unwrap()
}
fn buffered() -> VecDeque<bullet_application::LedgerEvent> {
    VecDeque::from([bullet_application::LedgerEvent {
        seq: 1,
        at: "2026-09-10T00:00:00Z".into(),
        kind: "private".into(),
        body: "private event".into(),
        event_id: None,
        stream_id: None,
        sequence: Some(1),
        causation_id: None,
        correlation_id: None,
        authority_token_hash: None,
    }])
}

#[tokio::test]
async fn event_stream_stops_before_buffered_events_after_expiry_or_revocation() {
    let directory = private_directory();
    let path = directory.path().join("auth.sqlite");
    let mut independent = SqliteLedger::open(&path).unwrap();
    for expires in [false, true] {
        let (headers, request) = issue(
            &mut independent,
            if expires { "expired" } else { "revoked" },
            if expires { 2 } else { 600 },
        );
        // Reopening the daemon retains a permit for a persisted session.
        let (_, state) = crate::api::daemon(&path, None, ORIGIN.into(), None).unwrap();
        let permit = ReadPermit::issue(&*state.auth.lock().await, &headers)
            .unwrap_or_else(|_| panic!("persisted session"));
        if expires {
            tokio::time::sleep(Duration::from_millis(2100)).await;
        } else {
            independent
                .revoke_operator_session(request.bearer_digest, request.csrf_digest, ORIGIN)
                .unwrap();
        }
        assert!(!permit.is_current(&*state.auth.lock().await));
        let stream = crate::api::event_stream(state, 0, buffered(), permit);
        futures_util::pin_mut!(stream);
        assert!(
            stream.next().await.is_none(),
            "buffered private events cannot escape lost authority"
        );
    }
}

#[tokio::test]
async fn idle_stream_observes_external_revocation_without_revoking_another_client() {
    let directory = private_directory();
    let path = directory.path().join("auth.sqlite");
    let mut independent = SqliteLedger::open(&path).unwrap();
    let (first, request) = issue(&mut independent, "first", 600);
    let (_, state) = crate::api::daemon(&path, None, ORIGIN.into(), None).unwrap();
    let permit = ReadPermit::issue(&*state.auth.lock().await, &first)
        .unwrap_or_else(|_| panic!("persisted session"));
    let (second, _) = issue(&mut independent, "second", 600);
    assert!(
        permit.is_current(&*state.auth.lock().await),
        "new client does not replace first client"
    );
    let second_permit = ReadPermit::issue(&*state.auth.lock().await, &second)
        .unwrap_or_else(|_| panic!("second client"));
    let stream = crate::api::event_stream(state.clone(), 0, VecDeque::new(), permit);
    futures_util::pin_mut!(stream);
    let next = stream.next();
    futures_util::pin_mut!(next);
    assert!(futures_util::poll!(&mut next).is_pending());
    independent
        .revoke_operator_session(request.bearer_digest, request.csrf_digest, ORIGIN)
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), next)
        .await
        .expect("idle recheck")
        .is_none());
    assert!(second_permit.is_current(&*state.auth.lock().await));
}
