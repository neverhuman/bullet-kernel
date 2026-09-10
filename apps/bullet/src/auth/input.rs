//! Secret input uses a pipe or a terminal with echo and signal characters disabled.

use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::io::{IsTerminal, Read, Write};

struct HiddenInput;

impl Drop for HiddenInput {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        eprintln!();
    }
}

fn pipe_token(input: impl Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    input
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(|_| "AUTH_INPUT_FAILED")?;
    if bytes.len() > 256 {
        return Err("AUTH_INPUT_TOO_LONG".into());
    }
    std::str::from_utf8(&bytes)
        .map(|v| v.trim().to_owned())
        .map_err(|_| "AUTH_INPUT_INVALID".into())
}

pub(super) fn bootstrap(from_stdin: bool) -> Result<String, String> {
    if from_stdin {
        if std::io::stdin().is_terminal() {
            return Err("AUTH_PIPE_REQUIRED: omit --stdin for hidden interactive input".into());
        }
        return pipe_token(std::io::stdin());
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("AUTH_TERMINAL_REQUIRED: use --stdin with a pipe".into());
    }
    eprint!("Bootstrap token (hidden): ");
    std::io::stderr().flush().map_err(|_| "AUTH_INPUT_FAILED")?;
    enable_raw_mode().map_err(|_| "AUTH_TERMINAL_UNAVAILABLE")?;
    let _restore = HiddenInput;
    let mut token = String::new();
    loop {
        if let Event::Key(key) = read().map_err(|_| "AUTH_INPUT_FAILED")? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Char('c' | 'd') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err("AUTH_INPUT_CANCELLED".into())
                }
                KeyCode::Esc => return Err("AUTH_INPUT_CANCELLED".into()),
                KeyCode::Enter => return Ok(token),
                KeyCode::Backspace => {
                    token.pop();
                }
                KeyCode::Char(c)
                    if c.is_ascii()
                        && !c.is_ascii_control()
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if token.len() >= 255 {
                        return Err("AUTH_INPUT_TOO_LONG".into());
                    }
                    token.push(c);
                }
                _ => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_limit_never_silently_truncates_a_valid_prefix() {
        let token = format!("boot_{}", "a".repeat(64));
        assert_eq!(pipe_token(format!("{token}\n").as_bytes()).unwrap(), token);
        assert_eq!(
            pipe_token(format!("{token}{}hidden", " ".repeat(256)).as_bytes()).unwrap_err(),
            "AUTH_INPUT_TOO_LONG"
        );
        assert!(pipe_token(b"\xff".as_slice()).is_err());
    }
}
