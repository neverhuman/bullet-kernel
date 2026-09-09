//! `bullet coding`: submit and read farmd `run_coding` commands.
//!
//! Same envelope as Portal Control Tower. Never constructs a simulator.
//! `stop` is typed unimplemented until farmd exposes durable cancel.

use clap::Subcommand;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
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
    },
    /// GET one durable command subject.
    Status {
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        farmd: String,
        #[arg(long)]
        session_cookie: String,
        /// Exact command id (`cmd_` + 64 hex).
        id: String,
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
        } => match submit(
            &farmd,
            &origin,
            bootstrap_token.as_deref(),
            session_cookie.as_deref(),
            csrf.as_deref(),
            &account,
            &provider,
            &model,
            expected_revision,
        ) {
            Ok(body) => {
                println!("{body}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("bullet: {error}");
                ExitCode::FAILURE
            }
        },
        CodingCommands::Status {
            farmd,
            session_cookie,
            id,
        } => match status(&farmd, &session_cookie, &id) {
            Ok(body) => {
                println!("{body}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("bullet: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn submit(
    farmd: &str,
    origin: &str,
    bootstrap_token: Option<&str>,
    session_cookie: Option<&str>,
    csrf: Option<&str>,
    account: &str,
    provider: &str,
    model: &str,
    expected_revision: u64,
) -> Result<String, String> {
    let (cookie, csrf) = match (session_cookie, csrf, bootstrap_token) {
        (Some(cookie), Some(csrf), _) => (cookie.to_string(), csrf.to_string()),
        (_, _, Some(token)) => exchange_bootstrap(farmd, origin, token)?,
        _ => {
            return Err(
                "coding submit requires --bootstrap-token or both --session-cookie and --csrf"
                    .into(),
            )
        }
    };
    let envelope = run_coding_envelope(account, provider, model, expected_revision)?;
    let response = request(
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
    eprintln!("bullet: session_cookie={cookie}");
    eprintln!("bullet: csrf={csrf}");
    Ok(response.body.to_string())
}

fn status(farmd: &str, session_cookie: &str, id: &str) -> Result<String, String> {
    let path = format!("/api/v1/commands/{id}");
    let response = request(farmd, "GET", &path, &[("Cookie", session_cookie)], None)?;
    if response.status != 200 {
        return Err(format!(
            "farmd command status returned HTTP {}: {}",
            response.status, response.body
        ));
    }
    Ok(response.body.to_string())
}

fn exchange_bootstrap(farmd: &str, origin: &str, token: &str) -> Result<(String, String), String> {
    let response = request(
        farmd,
        "POST",
        "/api/v1/auth/bootstrap",
        &[("Origin", origin)],
        Some(&json!({ "bootstrap_token": token })),
    )?;
    if response.status != 200 {
        return Err(format!(
            "farmd bootstrap returned HTTP {}: {}",
            response.status, response.body
        ));
    }
    let csrf = response.body["csrf_token"]
        .as_str()
        .ok_or("farmd bootstrap omitted csrf_token")?
        .to_string();
    let cookie = response
        .set_cookie
        .ok_or("farmd bootstrap omitted Set-Cookie")?
        .split(';')
        .next()
        .unwrap_or_default()
        .to_string();
    if cookie.is_empty() {
        return Err("farmd bootstrap cookie pair was empty".into());
    }
    Ok((cookie, csrf))
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

struct HttpResponse {
    status: u16,
    body: Value,
    set_cookie: Option<String>,
}

fn request(
    farmd: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Result<HttpResponse, String> {
    let (host, port) = parse_loopback(farmd)?;
    let payload = body.map(Value::to_string).unwrap_or_default();
    let mut message = format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if !payload.is_empty() {
        message.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        message.push_str(&format!("{name}: {value}\r\n"));
    }
    message.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    ));
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|error| format!("connect {farmd}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(10))))
        .map_err(|error| format!("farmd socket timeout: {error}"))?;
    stream
        .write_all(message.as_bytes())
        .map_err(|error| format!("write farmd: {error}"))?;
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read farmd: {error}"))?;
    parse_http(&bytes)
}

fn parse_loopback(farmd: &str) -> Result<(String, u16), String> {
    let rest = farmd
        .strip_prefix("http://")
        .ok_or("farmd must be an http:// loopback URL")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .ok_or("farmd URL is missing a host")?;
    let addr: std::net::SocketAddr = authority
        .parse()
        .map_err(|_| "farmd must contain an explicit loopback address and port")?;
    if !addr.ip().is_loopback() {
        return Err("farmd must be loopback".into());
    }
    Ok((addr.ip().to_string(), addr.port()))
}

fn parse_http(bytes: &[u8]) -> Result<HttpResponse, String> {
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or("farmd response omitted the header terminator")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or("farmd response omitted an HTTP status")?;
    let set_cookie = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("set-cookie")
            .then(|| value.trim().to_string())
    });
    let body = decode_body(body);
    Ok(HttpResponse {
        status,
        body,
        set_cookie,
    })
}

fn decode_body(body: &str) -> Value {
    if body.trim().is_empty() {
        return Value::Null;
    }
    if let Ok(value) = serde_json::from_str(body) {
        return value;
    }
    let unchunked: String = body
        .lines()
        .filter(|line| !line.trim().is_empty() && u64::from_str_radix(line.trim(), 16).is_err())
        .collect();
    serde_json::from_str(&unchunked).unwrap_or(Value::Null)
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
    }

    #[test]
    fn simulator_name_is_refused_before_http() {
        let error = run_coding_envelope("acct", "sim", "none", 1).unwrap_err();
        assert!(error.contains("COMMAND_CODING_SIM_REFUSED"));
    }

    #[test]
    fn loopback_parser_refuses_public_hosts() {
        assert!(parse_loopback("http://8.8.8.8:7420").is_err());
        assert!(parse_loopback("https://127.0.0.1:7420").is_err());
        assert_eq!(
            parse_loopback("http://127.0.0.1:7420").unwrap(),
            ("127.0.0.1".into(), 7420)
        );
    }
}
