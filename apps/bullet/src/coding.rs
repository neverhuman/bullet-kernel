//! `bullet coding`: submit and read farmd `run_coding` commands.
//!
//! Same envelope as Portal Control Tower. Never constructs a simulator.
//! `stop` is typed unimplemented until farmd exposes durable cancel.

mod harness;
mod http;
mod render;

use clap::Subcommand;
use serde_json::{json, Value};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const CSRF_HEADER: &str = "X-Bullet-CSRF";

#[derive(Subcommand)]
pub(crate) enum CodingCommands {
    /// Exchange bootstrap (optional) and POST one `run_coding` envelope.
    Submit {
        /// Loopback farmd base, including scheme.
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        farmd: String,
        /// Exact Origin farmd admitted at launch.
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        origin: String,
        /// One-time `boot_` token printed by farmd. Consumed on first use.
        #[arg(long)]
        bootstrap_token: Option<String>,
        /// Existing `bullet_session=...` cookie pair.
        #[arg(long)]
        session_cookie: Option<String>,
        /// Session-bound CSRF token.
        #[arg(long)]
        csrf: Option<String>,
        /// Caller account token.
        #[arg(long)]
        account: String,
        /// claude, codex, cursor, or antigravity. Never sim.
        #[arg(long, value_parser = ["claude", "codex", "cursor", "antigravity"])]
        provider: String,
        /// Provider-native model id.
        #[arg(long)]
        model: String,
        /// Expected authority revision.
        #[arg(long, default_value_t = 1)]
        expected_revision: u64,
        /// JSON only, even on a TTY.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// GET one durable command subject.
    Status {
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        farmd: String,
        #[arg(long)]
        session_cookie: String,
        /// Exact command id (`cmd_` + 64 hex).
        id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// One-shot farmd projection board. Empty fleet is zero rows, not a green fleet.
    Board {
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        farmd: String,
        #[arg(long)]
        session_cookie: String,
        /// Optional durable command id to include.
        #[arg(long)]
        command: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Poll the same board. Not a coordinator fleet and not session steer.
    Watch {
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        farmd: String,
        #[arg(long)]
        session_cookie: String,
        #[arg(long)]
        command: Option<String>,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Report BULLET_HARNESS_* bind without spawning a provider.
    HarnessCheck {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Durable session stop. Not implemented; do not SIGKILL as success.
    Stop,
}

pub(crate) fn run(command: CodingCommands) -> ExitCode {
    match command {
        CodingCommands::Stop => {
            eprintln!(
                "bullet: STOP_UNIMPLEMENTED: durable coding stop waits for farmd T4a; refusing to SIGKILL"
            );
            ExitCode::from(2)
        }
        CodingCommands::HarnessCheck { json } => print_harness(json),
        CodingCommands::Submit {
            farmd,
            origin,
            bootstrap_token,
            session_cookie,
            csrf,
            account,
            provider,
            model,
            expected_revision,
            json,
        } => match submit(
            &farmd,
            &origin,
            SubmitRequest {
                bootstrap_token: bootstrap_token.as_deref(),
                session_cookie: session_cookie.as_deref(),
                csrf: csrf.as_deref(),
                account: &account,
                provider: &provider,
                model: &model,
                expected_revision,
            },
        ) {
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
        },
        CodingCommands::Status {
            farmd,
            session_cookie,
            id,
            json,
        } => match status(&farmd, &session_cookie, &id) {
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
        },
        CodingCommands::Board {
            farmd,
            session_cookie,
            command,
            json,
        } => match load_board(&farmd, &session_cookie, command.as_deref()) {
            Ok(board) => {
                print_board(&board, json);
                ExitCode::SUCCESS
            }
            Err(error) => fail(error),
        },
        CodingCommands::Watch {
            farmd,
            session_cookie,
            command,
            interval_ms,
            json,
        } => match admit_interval(interval_ms) {
            Ok(interval) => loop {
                match load_board(&farmd, &session_cookie, command.as_deref()) {
                    Ok(board) => {
                        if !json && render::color_wanted(false) {
                            print!("{}", render::screen_home(true));
                        }
                        print_board(&board, json);
                    }
                    Err(error) => eprintln!("bullet: {error}"),
                }
                thread::sleep(Duration::from_millis(interval));
            },
            Err(error) => fail(error),
        },
    }
}

fn fail(error: String) -> ExitCode {
    eprintln!("bullet: {error}");
    ExitCode::FAILURE
}

fn emit(json_body: &str, card: Option<&str>, json_only: bool) {
    if !json_only && render::color_wanted(false) {
        if let Some(card) = card {
            println!("{card}");
        }
    }
    println!("{json_body}");
}

fn print_board(board: &render::Board, json_only: bool) {
    if json_only {
        println!("{}", board.json());
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
        println!("{}", report.json());
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
    bootstrap_token: Option<&'a str>,
    session_cookie: Option<&'a str>,
    csrf: Option<&'a str>,
    account: &'a str,
    provider: &'a str,
    model: &'a str,
    expected_revision: u64,
}

fn submit(farmd: &str, origin: &str, request: SubmitRequest<'_>) -> Result<Value, String> {
    let (cookie, csrf) = match (
        request.session_cookie,
        request.csrf,
        request.bootstrap_token,
    ) {
        (Some(cookie), Some(csrf), _) => (cookie.to_string(), csrf.to_string()),
        (_, _, Some(token)) => http::exchange_bootstrap(farmd, origin, token)?,
        _ => {
            return Err(
                "coding submit requires --bootstrap-token or both --session-cookie and --csrf"
                    .into(),
            )
        }
    };
    let envelope = run_coding_envelope(
        request.account,
        request.provider,
        request.model,
        request.expected_revision,
    )?;
    let response = http::request(
        farmd,
        "POST",
        "/api/v1/commands",
        &[
            ("Origin", origin),
            ("Cookie", &cookie),
            (CSRF_HEADER, &csrf),
        ],
        Some(&envelope),
    )?;
    if response.status != 202 {
        return Err(format!(
            "farmd command admission returned HTTP {}: {}",
            response.status, response.body
        ));
    }
    Ok(response.body)
}

fn status(farmd: &str, session_cookie: &str, id: &str) -> Result<Value, String> {
    let path = format!("/api/v1/commands/{id}");
    let response = http::request(farmd, "GET", &path, &[("Cookie", session_cookie)], None)?;
    if response.status != 200 {
        return Err(format!(
            "farmd command status returned HTTP {}: {}",
            response.status, response.body
        ));
    }
    Ok(response.body)
}

fn read_projection(farmd: &str, cookie: &str, path: &str) -> Result<Value, String> {
    let response = http::request(farmd, "GET", path, &[("Cookie", cookie)], None)?;
    if response.status != 200 {
        return Err(format!(
            "{path} HTTP {}: {}",
            response.status, response.body
        ));
    }
    Ok(response.body)
}

fn load_board(
    farmd: &str,
    session_cookie: &str,
    command_id: Option<&str>,
) -> Result<render::Board, String> {
    let health = match http::request(farmd, "GET", "/health", &[], None) {
        Ok(response) if response.status == 200 => Ok(response.body),
        Ok(response) => Err(format!(
            "/health HTTP {}: {}",
            response.status, response.body
        )),
        Err(error) => Err(error),
    };
    Ok(render::Board {
        health,
        fleet: read_projection(farmd, session_cookie, "/api/v1/fleet"),
        sessions: read_projection(farmd, session_cookie, "/api/v1/sessions"),
        outbox: read_projection(farmd, session_cookie, "/api/v1/outbox"),
        command: command_id.map(|id| status(farmd, session_cookie, id)),
        harness: harness::from_env(),
    })
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
