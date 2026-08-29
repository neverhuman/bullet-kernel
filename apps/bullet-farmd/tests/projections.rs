//! Spec section 25 projection routes against a served socket and a temp
//! database: empty sets are zero rows at a watermark, seeded rows are the
//! durable rows, every route shares one watermark, and corrupt rows are
//! typed 500 problems rather than shorter lists.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, run_demo, LeaseService, PlanInput};
use bullet_domain::{Digest, TaskClass};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const ROUTES: [&str; 6] = [
    "/api/v1/fleet",
    "/api/v1/sessions",
    "/api/v1/context-lineage",
    "/api/v1/merge-rail",
    "/api/v1/quality-lab",
    "/api/v1/audit",
];

async fn start(db: &Path) -> SocketAddr {
    let app = bullet_farmd::api::router(db).expect("router");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

async fn raw_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .expect("response before timeout")
        .expect("read");
    String::from_utf8_lossy(&buf).to_string()
}

fn status_of(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status line")
}

fn header(response: &str, name: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn body_json(response: &str) -> Value {
    let body = response.split_once("\r\n\r\n").expect("body").1;
    if let Ok(value) = serde_json::from_str(body) {
        return value;
    }
    let unchunked: String = body
        .lines()
        .filter(|line| !line.trim().is_empty() && u64::from_str_radix(line.trim(), 16).is_err())
        .collect();
    serde_json::from_str(&unchunked).expect("json body")
}

/// Assert the standard envelope, the header/body watermark agreement, and
/// return `(data, as_of_sequence)`.
async fn snapshot(addr: SocketAddr, path: &str) -> (Value, u64) {
    let response = raw_get(addr, path).await;
    assert_eq!(status_of(&response), 200, "{path}: {response}");
    let snapshot = body_json(&response);
    let mut keys: Vec<_> = snapshot
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["as_of_sequence", "data", "observed_at", "source"]);
    assert_eq!(snapshot["source"], "bullet-kernel/sqlite-ledger");
    chrono::DateTime::parse_from_rfc3339(snapshot["observed_at"].as_str().expect("observed_at"))
        .expect("RFC 3339 observed_at");
    let as_of = snapshot["as_of_sequence"].as_u64().expect("watermark");
    assert_eq!(
        header(&response, "x-bullet-as-of-sequence").as_deref(),
        Some(as_of.to_string().as_str()),
        "{path}: header and body watermark must agree"
    );
    (snapshot["data"].clone(), as_of)
}

fn labels(rows: &Value) -> Vec<(String, u64)> {
    rows.as_array()
        .expect("label rows")
        .iter()
        .map(|row| {
            (
                row["label"].as_str().expect("label").to_string(),
                row["count"].as_u64().expect("count"),
            )
        })
        .collect()
}

fn insert_events(db: &Path, count: u64) {
    drop(SqliteLedger::open(db).expect("initialize ledger"));
    let mut connection = Connection::open(db).expect("raw open");
    let transaction = connection.transaction().expect("transaction");
    for sequence in 1..=count {
        let kind = "fixture";
        let body = sequence.to_string();
        let id = Digest::of(format!("evt:{sequence}:{kind}:{body}").as_bytes()).to_hex();
        transaction
            .execute(
                "INSERT INTO events (seq, kind, body, at, event_id, sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?1)",
                params![sequence, kind, body, "2026-01-01T00:00:00.000Z", id],
            )
            .expect("fixture event");
    }
    transaction.commit().expect("commit fixtures");
}

#[tokio::test]
async fn empty_database_projects_zero_rows_at_watermark_zero_on_every_route() {
    let dir = support::private_tempdir();
    let addr = start(&dir.path().join("ledger.sqlite")).await;
    let (fleet, as_of) = snapshot(addr, "/api/v1/fleet").await;
    assert_eq!(as_of, 0);
    assert_eq!(fleet["leases"], Value::Array(vec![]));
    assert_eq!(fleet["ready_queue"], Value::Array(vec![]));
    chrono::DateTime::parse_from_rfc3339(fleet["authority_time"].as_str().expect("clock"))
        .expect("store clock is RFC 3339");

    let (sessions, as_of) = snapshot(addr, "/api/v1/sessions").await;
    assert_eq!(as_of, 0);
    assert_eq!(sessions["attempts"], Value::Array(vec![]));
    let states = labels(&sessions["state_counts"]);
    assert_eq!(states.len(), 12);
    assert!(states.iter().all(|(_, count)| *count == 0));
    assert!(states.iter().any(|(label, _)| label == "crashed"));

    let (context, as_of) = snapshot(addr, "/api/v1/context-lineage").await;
    assert_eq!(as_of, 0);
    assert_eq!(context["capsules"], Value::Array(vec![]));

    let (rail, as_of) = snapshot(addr, "/api/v1/merge-rail").await;
    assert_eq!(as_of, 0);
    for field in ["candidates", "effects", "intents", "receipts"] {
        assert_eq!(rail[field], Value::Array(vec![]), "{field}");
    }
    let states = labels(&rail["intent_state_counts"]);
    assert_eq!(states.len(), 13);
    assert!(states
        .iter()
        .any(|(label, count)| label == "OUTCOME_UNKNOWN" && *count == 0));

    let (lab, as_of) = snapshot(addr, "/api/v1/quality-lab").await;
    assert_eq!(as_of, 0);
    assert_eq!(lab["evidence"], Value::Array(vec![]));
    let outcomes = labels(&lab["outcome_counts"]);
    assert_eq!(outcomes.len(), 11);
    assert!(outcomes.iter().any(|(label, _)| label == "UNKNOWN"));

    let (audit, as_of) = snapshot(addr, "/api/v1/audit").await;
    assert_eq!(as_of, 0);
    assert_eq!(audit["latest_sequence"], 0);
    assert_eq!(audit["tail_window"], 64);
    assert_eq!(audit["events"], Value::Array(vec![]));
}

#[tokio::test]
async fn seeded_demo_projects_durable_rows_under_one_shared_watermark() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    let receipt = {
        let mut ledger = SqliteLedger::open(&db).expect("ledger");
        serde_json::to_value(run_demo(&mut ledger).expect("demo")).expect("receipt")
    };
    let addr = start(&db).await;
    let mut watermarks = Vec::new();
    for route in ROUTES {
        watermarks.push(snapshot(addr, route).await.1);
    }
    assert!(watermarks[0] > 0);
    assert!(watermarks.iter().all(|w| *w == watermarks[0]));

    let (rail, _) = snapshot(addr, "/api/v1/merge-rail").await;
    let candidates = rail["candidates"].as_array().expect("candidates");
    assert!(candidates.is_empty());
    assert_eq!(receipt["candidate_head"], "NOT_PRODUCED");
    assert_eq!(rail["effects"], Value::Array(vec![]));
    assert_eq!(rail["intents"], Value::Array(vec![]));

    let (lab, _) = snapshot(addr, "/api/v1/quality-lab").await;
    let evidence = lab["evidence"].as_array().expect("evidence");
    assert!(evidence.is_empty());
    assert_eq!(receipt["evidence_result"], "NOT_RUN");

    let (sessions, _) = snapshot(addr, "/api/v1/sessions").await;
    let attempts = sessions["attempts"].as_array().expect("attempts");
    assert!(attempts.len() >= 2);
    assert!(attempts.iter().all(|row| row["lease"] == "none"));
    assert!(attempts.iter().any(|row| row["state"] == "superseded"));
    assert!(attempts
        .iter()
        .all(|row| row["mission_id"] == receipt["mission_id"]));
    let total: u64 = labels(&sessions["state_counts"])
        .iter()
        .map(|(_, count)| count)
        .sum();
    assert_eq!(total, attempts.len() as u64);

    let (context, _) = snapshot(addr, "/api/v1/context-lineage").await;
    let capsules = context["capsules"].as_array().expect("context capsules");
    assert_eq!(capsules.len(), 2);
    for capsule in capsules {
        assert_eq!(capsule["revision"], 1);
        assert_eq!(capsule["parent_id"], Value::Null);
        assert_eq!(capsule["compression"], "none");
        assert_eq!(capsule["dropped_decision_digests"], Value::Array(vec![]));
        assert_eq!(capsule["content_digest"].as_str().map(str::len), Some(64));
    }

    let (audit, as_of) = snapshot(addr, "/api/v1/audit").await;
    let events = audit["events"].as_array().expect("events");
    assert_eq!(audit["latest_sequence"], as_of);
    assert_eq!(
        events.last().map(|e| e["seq"].clone()),
        Some(Value::from(as_of))
    );
    assert!(events
        .iter()
        .any(|e| e["kind"] == "demo_stale_authority_refused"));
    assert!(events.iter().all(|e| {
        !matches!(
            e["kind"].as_str(),
            Some("candidate_prepared" | "evidence_attached" | "effect_receipt")
        )
    }));
    assert!(events
        .iter()
        .all(|e| e["id"].as_str().is_some_and(|id| id.len() == 64)));
}

#[tokio::test]
async fn fleet_and_sessions_project_a_live_lease_from_the_database_clock() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    let (graph, attempt) = {
        let mut ledger = SqliteLedger::open(&db).expect("ledger");
        let graph = materialize_plan(
            &mut ledger,
            "route-lease",
            &PlanInput {
                title: "fleet".into(),
                objective: "project the lease".into(),
                packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
            },
            "2026-08-25T00:00:00.000Z",
        )
        .expect("materialize");
        let (attempt, _, _) =
            LeaseService::acquire(&mut ledger, &graph, 0, "route-a", 15).expect("acquire");
        (graph, attempt)
    };
    let addr = start(&db).await;
    let (fleet, _) = snapshot(addr, "/api/v1/fleet").await;
    let leases = fleet["leases"].as_array().expect("leases");
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0]["attempt_id"], attempt.id.to_string());
    assert_eq!(leases[0]["liveness"], "live");
    assert_eq!(leases[0]["attempt_state"], "starting");
    assert_eq!(leases[0]["ttl_seconds"], 15);
    assert_eq!(leases[0]["mission_id"], graph.mission.id.to_string());
    assert_eq!(fleet["ready_queue"], Value::Array(vec![]));

    let (sessions, _) = snapshot(addr, "/api/v1/sessions").await;
    let rows = sessions["attempts"].as_array().expect("attempts");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["lease"], "held");
    assert!(rows[0]["leased_at"].is_string());
    assert_eq!(rows[0]["last_lease_event"]["kind"], "attempt_leased");
}

#[tokio::test]
async fn corrupt_rows_are_typed_500_problems_not_shorter_lists() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    {
        let mut ledger = SqliteLedger::open(&db).expect("ledger");
        run_demo(&mut ledger).expect("demo");
    }
    let addr = start(&db).await;
    let raw = Connection::open(&db).expect("raw");
    raw.execute(
        "UPDATE context_capsules SET content_digest = ?1",
        params!["a".repeat(64)],
    )
    .expect("corrupt context capsule");
    let response = raw_get(addr, "/api/v1/context-lineage").await;
    assert_eq!(status_of(&response), 500);
    assert_eq!(body_json(&response)["code"], "STORE_FAILURE");
    let response = raw_get(addr, "/api/v1/quality-lab").await;
    assert_eq!(status_of(&response), 200, "unrelated routes stay readable");

    raw.execute(
        "INSERT INTO candidates (id, body) VALUES ('can_corrupt', 'not json')",
        [],
    )
    .expect("corrupt candidate");
    let response = raw_get(addr, "/api/v1/merge-rail").await;
    assert_eq!(status_of(&response), 500);
    assert_eq!(body_json(&response)["code"], "STORE_FAILURE");
    assert!(!response.contains("expected value"), "parser detail leaked");

    raw.execute("UPDATE events SET event_id = 'bad' WHERE seq = 1", [])
        .expect("corrupt event");
    let response = raw_get(addr, "/api/v1/audit").await;
    assert_eq!(status_of(&response), 500);
    assert_eq!(body_json(&response)["code"], "STORE_FAILURE");
    let response = raw_get(addr, "/api/v1/quality-lab").await;
    assert_eq!(status_of(&response), 200, "unrelated routes stay readable");
}

#[tokio::test]
async fn audit_tail_is_bounded_to_the_newest_sixty_four_events() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    insert_events(&db, 100);
    let addr = start(&db).await;
    let (audit, as_of) = snapshot(addr, "/api/v1/audit").await;
    assert_eq!(as_of, 100);
    assert_eq!(audit["latest_sequence"], 100);
    let events = audit["events"].as_array().expect("events");
    assert_eq!(events.len(), 64);
    assert_eq!(events[0]["seq"], 37);
    assert_eq!(events[63]["seq"], 100);
    Connection::open(&db)
        .expect("raw")
        .execute("DELETE FROM events WHERE seq = 70", [])
        .expect("gap");
    let response = raw_get(addr, "/api/v1/audit").await;
    assert_eq!(
        status_of(&response),
        500,
        "a gap in the tail is not a shorter list"
    );
}
