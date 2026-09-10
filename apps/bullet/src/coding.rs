//! `bullet coding`: submit and read farmd `run_coding` commands.
//!
//! Same envelope as Portal Control Tower. Never constructs a simulator.
//! `stop` is typed unimplemented until farmd exposes durable cancel.

mod args;
mod credentials;
mod discovery;
mod harness;
pub(crate) mod http;
mod journal;
mod render;

pub(crate) use args::CodingCommands;
use credentials::Session;
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const CSRF_HEADER: &str = "X-Bullet-CSRF";

pub(crate) fn run(command: CodingCommands) -> ExitCode {
    match command {
        CodingCommands::Stop => {
            eprintln!("bullet: STOP_UNIMPLEMENTED: durable coding stop waits for farmd lifecycle admission");
            ExitCode::from(2)
        }
        CodingCommands::HarnessCheck { json } => print_harness(json),
        CodingCommands::List {
            connection,
            after,
            limit,
            json,
        } => match connection
            .load()
            .and_then(|session| discovery::list(&session, after, limit))
        {
            Ok(page) => {
                discovery::print(&page, json);
                ExitCode::SUCCESS
            }
            Err(error) => fail(error),
        },
        CodingCommands::Submit {
            connection,
            account,
            provider,
            model,
            expected_revision,
            idempotency_key,
            json,
        } => {
            let result = connection.load().and_then(|session| {
                submit(
                    &session,
                    SubmitRequest {
                        account: &account,
                        provider: &provider,
                        model: &model,
                        expected_revision,
                        idempotency_key: idempotency_key.as_deref(),
                    },
                )
            });
            print_command(result, json)
        }
        CodingCommands::Status {
            connection,
            id,
            json,
        } => print_command(
            connection.load().and_then(|session| status(&session, &id)),
            json,
        ),
        CodingCommands::Board {
            connection,
            command,
            json,
        } => {
            match connection
                .load()
                .and_then(|session| load_board(&session, command.as_deref()))
            {
                Ok(board) => {
                    print_board(&board, json);
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error),
            }
        }
        CodingCommands::Watch {
            connection,
            command,
            interval_ms,
            json,
        } => {
            let session = match connection.load() {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let interval = match admit_interval(interval_ms) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            loop {
                match load_board(&session, command.as_deref()) {
                    Ok(board) => {
                        if !json && render::color_wanted(false) {
                            print!("{}", render::screen_home(true));
                        }
                        print_board(&board, json);
                    }
                    Err(error) => eprintln!("bullet: {}", crate::client::terminal_text(&error)),
                }
                thread::sleep(Duration::from_millis(interval));
            }
        }
    }
}

fn print_command(result: Result<Value, String>, json: bool) -> ExitCode {
    match result {
        Ok(body) => {
            emit(
                &body.to_string(),
                Some(&render::format_command_card(
                    &body,
                    render::color_wanted(json),
                )),
                json,
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn fail(error: String) -> ExitCode {
    eprintln!("bullet: {}", crate::client::terminal_text(&error));
    ExitCode::FAILURE
}

fn emit(json_body: &str, card: Option<&str>, json_only: bool) {
    if !json_only && std::io::stdout().is_terminal() {
        if let Some(card) = card {
            println!("{card}");
            return;
        }
    }
    print_json(json_body);
}

pub(crate) fn print_json(body: &str) {
    if std::io::stdout().is_terminal() {
        println!("{}", terminal_json(body));
    } else {
        println!("{body}");
    }
}

fn terminal_json(body: &str) -> String {
    body.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                format!("\\u{:04x}", u32::from(c))
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn print_board(board: &render::Board, json_only: bool) {
    if json_only {
        print_json(&board.json().to_string());
        return;
    }
    println!(
        "{}",
        render::format_board(board, render::color_wanted(false))
    );
}

fn print_harness(json_only: bool) -> ExitCode {
    let report = harness::from_env();
    if json_only {
        print_json(&report.json().to_string());
    } else {
        println!(
            "{}",
            render::format_harness(&report, render::color_wanted(false))
        );
    }
    if report.outcome == "BOUND" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

struct SubmitRequest<'a> {
    account: &'a str,
    provider: &'a str,
    model: &'a str,
    expected_revision: u64,
    idempotency_key: Option<&'a str>,
}

fn submit(session: &Session, request: SubmitRequest<'_>) -> Result<Value, String> {
    let (envelope, expected) = journal::prepare(session, &request)?;
    let command_id = expected.id();
    eprintln!(
        "COMMAND_JOURNALED: {command_id}; idempotency_key={}",
        crate::client::terminal_text(&expected.idempotency_key)
    );
    let response = http::request(
        &session.farmd,
        "POST",
        "/api/v1/commands",
        &[
            ("Origin", &session.origin),
            ("Cookie", &session.cookie),
            (CSRF_HEADER, &session.csrf),
        ],
        Some(&envelope),
    )
    .map_err(|error| {
        format!(
            "{error}; reconcile bullet coding status {command_id} using the same state directory"
        )
    })?;
    if response.status != 202 {
        return Err(format!("FARMD_COMMAND_REFUSED: HTTP {}", response.status));
    }
    let body = command_body(response.body)?;
    journal::correlate(&expected, &body)?;
    Ok(body)
}

fn command_body(body: Value) -> Result<Value, String> {
    let command: crate::client::models::CommandStatus = crate::client::decode(&body)?;
    if command.kind.is_empty()
        || (command.status == "PENDING" && !command.result.is_null())
        || (matches!(command.status.as_str(), "APPLIED" | "VERIFIED" | "FAILED")
            && command.result.is_null())
    {
        return Err("FARMD_COMMAND_CONTRADICTORY".into());
    }
    Ok(body)
}

fn status(session: &Session, id: &str) -> Result<Value, String> {
    http::validate_secret(id, "cmd").map_err(|_| "COMMAND_ID_INVALID")?;
    let recorded = journal::reconciliation_request(session, id)?;
    let response = http::request(
        &session.farmd,
        "GET",
        &format!("/api/v1/commands/{id}"),
        &[("Cookie", &session.cookie), ("Origin", &session.origin)],
        None,
    )?;
    if response.status != 200 {
        return Err(format!("FARMD_COMMAND_REFUSED: HTTP {}", response.status));
    }
    let body = command_body(response.body)?;
    if body["id"] != id {
        return Err("FARMD_COMMAND_SUBJECT_MISMATCH".into());
    }
    if let Some(request) = recorded {
        journal::correlate(&request, &body)?;
    }
    Ok(body)
}

#[cfg(unix)]
fn load_board(session: &Session, command_id: Option<&str>) -> Result<render::Board, String> {
    let snapshot = crate::client::operator_snapshot(session)?;
    let wrap = |data: Value| {
        json!({"data":data,"as_of_sequence":snapshot.as_of_sequence,
        "observed_at":snapshot.observed_at,"source":snapshot.source})
    };
    let health = http::request(&session.farmd, "GET", "/health", &[], None).and_then(|r| {
        if r.status != 200 {
            return Err(format!("FARMD_HEALTH_REFUSED: HTTP {}", r.status));
        }
        let _: crate::client::models::Health = crate::client::decode(&r.body)?;
        Ok(r.body)
    });
    Ok(render::Board {
        health,
        fleet: Ok(wrap(
            serde_json::to_value(&snapshot.data.fleet)
                .map_err(|_| "FARMD_MODEL_ENCODING_FAILED")?,
        )),
        sessions: Ok(wrap(
            serde_json::to_value(&snapshot.data.sessions)
                .map_err(|_| "FARMD_MODEL_ENCODING_FAILED")?,
        )),
        outbox: Ok(wrap(
            serde_json::to_value(&snapshot.data.outbox)
                .map_err(|_| "FARMD_MODEL_ENCODING_FAILED")?,
        )),
        command: command_id.map(|id| status(session, id)),
        harness: harness::from_env(),
    })
}

#[cfg(not(unix))]
fn load_board(_session: &Session, _command_id: Option<&str>) -> Result<render::Board, String> {
    Err("AUTH_PRIVATE_STORE_UNSUPPORTED".into())
}

fn admit_interval(interval_ms: u64) -> Result<u64, String> {
    if interval_ms == 0 {
        return Err("WATCH_INTERVAL_INVALID: interval must be >= 1ms".into());
    }
    Ok(interval_ms)
}

fn run_coding_envelope(
    account: &str,
    provider: &str,
    model: &str,
    expected_revision: u64,
) -> Result<Value, String> {
    if account.trim().is_empty() || model.trim().is_empty() {
        return Err("run_coding requires an explicit account id and model".into());
    }
    if provider == "sim" {
        return Err("COMMAND_CODING_SIM_REFUSED: run_coding never selects the simulator".into());
    }
    Ok(json!({
        "idempotency_key": format!("cli_{}", random_hex(16)?),
        "kind": "run_coding",
        "payload": {
            "account_id": account.trim(),
            "provider": provider,
            "model": model.trim(),
            "expected_revision": expected_revision,
            "launch_nonce": random_hex(32)?,
            "quota_reservation": format!("rsv_{}", random_hex(32)?),
            "quota_units": 1,
            "allocated_run": format!("run_{}", random_hex(32)?),
        }
    }))
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut buffer = vec![0_u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut buffer))
        .map_err(|error| format!("operating-system entropy: {error}"))?;
    Ok(buffer.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_matches_portal_run_coding_shape() {
        let value = run_coding_envelope("acct-local", "antigravity", "gemini-2.5", 1).unwrap();
        assert_eq!(value["kind"], "run_coding");
        assert_eq!(value["payload"]["provider"], "antigravity");
        assert_eq!(value["payload"]["account_id"], "acct-local");
        assert_eq!(value["payload"]["quota_units"], 1);
        assert!(value["payload"]["allocated_run"]
            .as_str()
            .unwrap()
            .starts_with("run_"));
        assert!(value["payload"]["quota_reservation"]
            .as_str()
            .unwrap()
            .starts_with("rsv_"));
        let empty = render::Board {
            health: Ok(json!({"status": "ok"})),
            fleet: Ok(json!({
                "data": {"authority_time": "t0", "leases": [], "ready_queue": []},
                "as_of_sequence": 0
            })),
            sessions: Ok(json!({"data": {"attempts": [], "state_counts": []}})),
            outbox: Ok(json!({"data": {"items": []}})),
            command: None,
            harness: harness::inspect(&[]),
        };
        let text = render::format_board(&empty, false);
        assert!(text.contains("HOLD"));
        assert!(text.contains("LIVE"));
        assert!(text.contains("live 0"));
        assert!(text.contains("STOP_UNIMPLEMENTED"));
        assert!(text.contains("empty fleet is zero lease rows"));
        assert!(!text.contains('\u{1b}'));
        assert!(admit_interval(0)
            .unwrap_err()
            .contains("WATCH_INTERVAL_INVALID"));
        assert_eq!(admit_interval(1000).unwrap(), 1000);
    }

    #[test]
    fn simulator_name_is_refused_before_http() {
        let error = run_coding_envelope("acct", "sim", "none", 1).unwrap_err();
        assert!(error.contains("COMMAND_CODING_SIM_REFUSED"));
        let report = harness::inspect(&[]);
        assert_eq!(report.outcome, "UNBOUND");
        assert!(report
            .rows
            .iter()
            .any(|(name, state)| name == "BULLET_HARNESS_HOME" && *state == "ABSENT"));
        let bound = harness::inspect(
            &harness::REQUIRED
                .iter()
                .map(|name| (*name, Some("set".into())))
                .collect::<Vec<_>>(),
        );
        assert_eq!(bound.outcome, "BOUND");
        assert!(!render::color_wanted(true));
    }

    #[test]
    fn loopback_parser_refuses_public_hosts() {
        assert!(http::parse_loopback("http://8.8.8.8:7420").is_err());
        assert!(http::parse_loopback("https://127.0.0.1:7420").is_err());
        assert_eq!(
            http::parse_loopback("http://127.0.0.1:7420").unwrap(),
            ("127.0.0.1".into(), 7420)
        );
    }
}
