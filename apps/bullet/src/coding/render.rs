//! High-contrast status paint. Color is additive; every state has a text label.

use serde_json::{json, Value};
use std::io::IsTerminal;

use super::harness::Report;

const GOLD: &str = "\x1b[38;2;255;196;77m";
const GREEN: &str = "\x1b[38;2;61;255;138m";
const RED: &str = "\x1b[38;2;255;107;107m";
const CYAN: &str = "\x1b[38;2;169;199;255m";
const DIM: &str = "\x1b[38;2;157;176;201m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

pub(crate) fn color_wanted(force_plain: bool) -> bool {
    !force_plain && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

pub(crate) fn paint(color: bool, code: &str, text: &str) -> String {
    let text = crate::client::terminal_text(text);
    if color {
        format!("{BOLD}{code}{text}{RESET}")
    } else {
        text
    }
}

pub(crate) fn status_tone(label: &str) -> &'static str {
    match label {
        "ok" | "live" | "BOUND" | "PRESENT" => GREEN,
        "PENDING" | "APPLIED" | "expired" | "HOLD" | "UNBOUND" | "ABSENT" => GOLD,
        _ => RED,
    }
}

pub(super) struct Board {
    pub(super) health: Result<Value, String>,
    pub(super) fleet: Result<Value, String>,
    pub(super) sessions: Result<Value, String>,
    pub(super) outbox: Result<Value, String>,
    pub(super) command: Option<Result<Value, String>>,
    pub(super) harness: Report,
}

impl Board {
    pub(super) fn json(&self) -> Value {
        json!({
            "operating_hold": true,
            "stop": "STOP_UNIMPLEMENTED",
            "health": result_json(&self.health),
            "fleet": result_json(&self.fleet),
            "sessions": result_json(&self.sessions),
            "outbox": result_json(&self.outbox),
            "command": self.command.as_ref().map(result_json),
            "harness": self.harness.json(),
        })
    }
}

fn result_json(result: &Result<Value, String>) -> Value {
    match result {
        Ok(value) => json!({ "ok": value }),
        Err(error) => json!({ "unknown": error }),
    }
}

fn snapshot_data(body: &Value) -> &Value {
    body.get("data").unwrap_or(body)
}

fn count_liveness(fleet: &Value, wanted: &str) -> usize {
    snapshot_data(fleet)["leases"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|row| row["liveness"].as_str() == Some(wanted))
                .count()
        })
        .unwrap_or(0)
}

pub(super) fn format_board(board: &Board, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(paint(color, CYAN, "BULLET FARM"));
    lines.push(format!(
        "  {}  operating hold remains; coord verbs forbidden; live_admission stays false",
        paint(color, status_tone("HOLD"), "HOLD")
    ));
    lines.push(format!(
        "  stop     {}",
        paint(color, status_tone("HOLD"), "STOP_UNIMPLEMENTED (farmd T4a)")
    ));
    match &board.health {
        Ok(body) => {
            let status = body["status"].as_str().unwrap_or("unknown");
            lines.push(format!(
                "  health   {} {}",
                paint(color, status_tone(status), status),
                paint(color, DIM, "(public /health)")
            ));
        }
        Err(error) => lines.push(error_line("health", error, color)),
    }
    match &board.fleet {
        Ok(body) => {
            let data = snapshot_data(body);
            let ready = data["ready_queue"].as_array().map(Vec::len).unwrap_or(0);
            let live = count_liveness(body, "live");
            let expired = count_liveness(body, "expired");
            let unknown = count_liveness(body, "unknown");
            let clock = data["authority_time"].as_str().unwrap_or("absent");
            let seq = body["as_of_sequence"]
                .as_u64()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".into());
            lines.push(format!(
                "  fleet    {} live {} · {} expired {} · {} unknown {} · ready {ready}",
                paint(color, GREEN, "LIVE"),
                live,
                paint(color, GOLD, "EXPIRED"),
                expired,
                paint(color, RED, "UNKNOWN"),
                unknown
            ));
            lines.push(format!(
                "           {}",
                paint(
                    color,
                    DIM,
                    &format!("authority_time {clock} · as_of_sequence {seq}")
                )
            ));
            if live == 0 && expired == 0 && unknown == 0 {
                lines.push(format!(
                    "           {}",
                    paint(
                        color,
                        DIM,
                        "empty fleet is zero lease rows, not a green multi-agent process"
                    )
                ));
            }
        }
        Err(error) => lines.push(error_line("fleet", error, color)),
    }
    match &board.sessions {
        Ok(body) => {
            let data = snapshot_data(body);
            let attempts = data["attempts"].as_array().map(Vec::len).unwrap_or(0);
            let held = data["attempts"]
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .filter(|row| row["lease"].as_str() == Some("held"))
                        .count()
                })
                .unwrap_or(0);
            lines.push(format!(
                "  sessions attempts {attempts} · {} lease held {held}",
                paint(color, if held == 0 { DIM } else { GREEN }, "HELD")
            ));
        }
        Err(error) => lines.push(error_line("sessions", error, color)),
    }
    match &board.outbox {
        Ok(body) => {
            let items = snapshot_data(body)["items"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0);
            lines.push(format!("  outbox   items {items}"));
        }
        Err(error) => lines.push(error_line("outbox", error, color)),
    }
    if let Some(command) = &board.command {
        match command {
            Ok(body) => lines.push(format!(
                "  command  server phase {} {} {} · verification UNKNOWN (receipt unchecked)",
                paint(
                    color,
                    status_tone(body["status"].as_str().unwrap_or("UNKNOWN")),
                    body["status"].as_str().unwrap_or("UNKNOWN")
                ),
                crate::client::terminal_text(body["kind"].as_str().unwrap_or("unknown-kind")),
                crate::client::terminal_text(body["id"].as_str().unwrap_or("missing-id"))
            )),
            Err(error) => lines.push(error_line("command", error, color)),
        }
    }
    let harness_tone = status_tone(board.harness.outcome);
    lines.push(format!(
        "  harness  {} (local CLI environment; daemon runtime admission is unknown)",
        paint(color, harness_tone, board.harness.outcome)
    ));
    lines.join("\n")
}

pub(super) fn format_command_card(body: &Value, color: bool) -> String {
    format!(
        "{}\n  server phase {}\n  verification UNKNOWN (receipt unchecked)\n  kind     {}\n  command  {}",
        paint(color, CYAN, "COMMAND OBSERVATION"),
        paint(
            color,
            status_tone(body["status"].as_str().unwrap_or("UNKNOWN")),
            body["status"].as_str().unwrap_or("UNKNOWN")
        ),
        crate::client::terminal_text(body["kind"].as_str().unwrap_or("unknown-kind")),
        crate::client::terminal_text(body["id"].as_str().unwrap_or("missing-id"))
    )
}

fn error_line(label: &str, error: &str, color: bool) -> String {
    format!(
        "  {label:<9} {} {}",
        paint(color, RED, "UNKNOWN"),
        crate::client::terminal_text(error)
    )
}

pub(super) fn format_harness(report: &Report, color: bool) -> String {
    let mut lines = vec![format!(
        "harness  {}",
        paint(color, status_tone(report.outcome), report.outcome)
    )];
    for (name, state) in &report.rows {
        lines.push(format!(
            "  {:<42} {}",
            name,
            paint(color, status_tone(state), state)
        ));
    }
    if report.outcome == "UNBOUND" {
        lines.push(paint(
            color,
            GOLD,
            "worker will refuse COMMAND_CODING_HARNESS_UNBOUND; no provider is spawned",
        ));
    }
    lines.join("\n")
}

pub(super) fn screen_home(color: bool) -> &'static str {
    if color {
        "\x1b[H\x1b[J"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_command_text_cannot_inject_terminal_sequences() {
        let body = json!({"status":"PENDING", "kind":"bad\x1b]52;clipboard\x07", "id":"line\r\noverwrite"});
        let card = format_command_card(&body, false);
        assert!(!card.contains('\x1b'));
        assert!(!card.contains('\x07'));
        assert!(!card.contains('\r'));
        assert!(card.contains("\\r\\n"));
        assert!(!error_line("fleet", "server\x1b[2J", false).contains('\x1b'));
        let verified = format_command_card(
            &json!({"status":"VERIFIED","kind":"run_demo","id":"id"}),
            false,
        );
        assert!(verified.contains("server phase VERIFIED"));
        assert!(verified.contains("verification UNKNOWN (receipt unchecked)"));
        assert!(!verified.contains("ADMITTED"));
    }
}
