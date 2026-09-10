//! Raw command admission rejects ambiguous JSON before durable mutation.
#[path = "support/command_http.rs"]
mod http;
mod support;
use bullet_adapters::SqliteLedger;
use bullet_application::Ledger;
use http::*;
use serde_json::json;

#[tokio::test]
async fn duplicate_decoded_keys_are_refused_before_admission_at_every_depth() {
    let directory = support::private_tempdir();
    let path = directory.path().join("commands.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Origin", ORIGIN),
        ("Cookie", cookie.as_str()),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let observer = SqliteLedger::open(&path).unwrap();
    let original = (
        observer.list_events().unwrap(),
        observer.outbox_all().unwrap(),
    );
    for raw in [
        r#"{"idempotency_key":"ambiguous","kind":"run_demo","kind":"run_coding","payload":{}}"#,
        r#"{"idempotency_key":"ambiguous","kind":"run_demo","payload":{"scope":1,"scope":2}}"#,
        r#"{"idempotency_key":"ambiguous","kind":"run_demo","payload":{"scope":1,"\u0073cope":2}}"#,
        r#"{"idempotency_key":"ambiguous","kind":"run_demo","payload":{"tasks":[{"base":"one","base":"two"}]}}"#,
        r#"{"idempotency_key":"ambiguous","kind":"run_demo","payload":{},"extra":true}"#,
        r#"{"idempotency_key":"ambiguous","kind":"run_demo","payload":{}} {}"#,
    ] {
        // Authentication remains the first disclosed refusal even for bad JSON.
        assert_eq!(
            status(&request(server.addr, "POST", "/api/v1/commands", &[], raw).await),
            403
        );
        let refused = request(server.addr, "POST", "/api/v1/commands", &headers, raw).await;
        assert_eq!(status(&refused), 400, "{raw}: {refused}");
        assert_eq!(body(&refused)["code"], "INVALID_JSON");
        assert!(observer.get_command("ambiguous").unwrap().is_none());
        assert_eq!(
            (
                observer.list_events().unwrap(),
                observer.outbox_all().unwrap()
            ),
            original
        );
    }
    // Refusal neither consumes the key nor weakens exact replay after a valid POST.
    let mut valid: serde_json::Value = serde_json::from_str(&envelope("ambiguous")).unwrap();
    valid["payload"] = json!({"scope":["src/a.rs"],"criteria":{"done":true}});
    let valid = valid.to_string();
    let accepted = request(server.addr, "POST", "/api/v1/commands", &headers, &valid).await;
    assert_eq!(status(&accepted), 202);
    let replay = request(server.addr, "POST", "/api/v1/commands", &headers, &valid).await;
    assert_eq!(status(&replay), 202);
    assert_eq!(body(&replay), body(&accepted));
    assert_eq!(observer.outbox_all().unwrap().len(), original.1.len() + 1);
    let page = check_snapshot(
        &request(
            server.addr,
            "GET",
            "/api/v1/commands",
            &[("Cookie", &cookie)],
            "",
        )
        .await,
    );
    assert_eq!(page["data"]["commands"], json!([body(&accepted)]));
    server.stop().await;
}
