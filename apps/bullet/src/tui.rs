//! The operator console is a consumer of the same atomic snapshot as the Portal.

mod model;
mod ui;

use clap::Args;
use std::path::PathBuf;

#[derive(Args, Default)]
pub(crate) struct TuiArgs {
    /// Private credentials saved by bullet auth login.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Reconnect to an exact mission, task, Attempt, Candidate, or event subject.
    #[arg(long)]
    subject: Option<String>,
    /// Print a single plain-text snapshot and exit.
    #[arg(long)]
    once: bool,
}

#[cfg(not(unix))]
pub(crate) fn run(_args: TuiArgs) -> Result<(), String> {
    Err("TUI_PRIVATE_STORE_UNSUPPORTED".into())
}

#[cfg(unix)]
pub(crate) fn run(args: TuiArgs) -> Result<(), String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use std::io::IsTerminal;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let directory = crate::auth::state_dir(args.state_dir)?;
    let credentials = crate::auth::store::CredentialStore::read_credentials(&directory)?
        .ok_or("AUTH_REQUIRED: run bullet auth login")?;
    let mut state = model::Model {
        destination: crate::client::terminal_text(&credentials.farmd),
        ..model::Model::default()
    };
    let mut reconnect = args.subject;
    if args.once
        || !std::io::stdout().is_terminal()
        || std::env::var("TERM").as_deref() == Ok("dumb")
    {
        state.update(crate::client::operator_snapshot(&credentials));
        if let Ok((coding, next_after)) = crate::client::coding_commands(&credentials, 0) {
            state.set_coding(coding, next_after);
        }
        if let Some(subject) = reconnect {
            state.reconnect(&subject);
        }
        println!("{}", state.plain());
        return state.error.map_or(Ok(()), Err);
    }
    if !std::io::stdin().is_terminal() {
        return Err("TUI_TERMINAL_REQUIRED: use --once".into());
    }
    let (request_tx, request_rx) = mpsc::sync_channel::<u64>(1);
    let (response_tx, response_rx) = mpsc::sync_channel(1);
    // This thread only performs GETs; dropping the client never cancels farm work.
    std::thread::spawn(move || {
        while let Ok(after) = request_rx.recv() {
            let snapshot = crate::client::operator_snapshot(&credentials);
            let (coding, next_after) = crate::client::coding_commands(&credentials, after)
                .unwrap_or_else(|_| (Vec::new(), None));
            if response_tx.send((snapshot, coding, next_after)).is_err() {
                break;
            }
        }
    });
    let mut terminal = ratatui::try_init().map_err(|_| "TUI_TERMINAL_UNAVAILABLE")?;
    let _restore = RestoreTerminal;
    let color = std::env::var_os("NO_COLOR").is_none();
    // First paint must not wait for any network request, even on a cold connection.
    terminal
        .draw(|frame| ui::draw(frame, &mut state, color))
        .map_err(|_| "TUI_DRAW_FAILED")?;
    request_tx
        .try_send(state.coding_after)
        .map_err(|_| "TUI_REFRESH_UNAVAILABLE")?;
    let mut next_refresh = Instant::now() + Duration::from_secs(2);
    let mut pending = true;
    state.refresh_pending = true;
    loop {
        if let Ok((snapshot, coding, next_after)) = response_rx.try_recv() {
            pending = false;
            state.refresh_pending = false;
            state.update(snapshot);
            state.set_coding(coding, next_after);
            if state.snapshot.is_some() {
                if let Some(subject) = reconnect.take() {
                    state.reconnect(&subject);
                }
            }
        }
        if !pending && Instant::now() >= next_refresh {
            request_tx
                .try_send(state.coding_after)
                .map_err(|_| "TUI_REFRESH_UNAVAILABLE")?;
            pending = true;
            state.refresh_pending = true;
            next_refresh = Instant::now() + Duration::from_secs(2);
        }
        state.refresh_pending = pending;
        terminal
            .draw(|frame| ui::draw(frame, &mut state, color))
            .map_err(|_| "TUI_DRAW_FAILED")?;
        if !event::poll(Duration::from_millis(100)).map_err(|_| "TUI_INPUT_FAILED")? {
            continue;
        }
        let Event::Key(key) = event::read().map_err(|_| "TUI_INPUT_FAILED")? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            break;
        }
        if key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::CONTROL) {
            state.palette = !state.palette;
            state.palette_selection = 0;
            continue;
        }
        match key.code {
            KeyCode::Char('?') => state.help = !state.help,
            KeyCode::Char('J') => state.raw_json = !state.raw_json,
            KeyCode::Esc => state.back(),
            KeyCode::Tab | KeyCode::BackTab => state.details_focus = !state.details_focus,
            KeyCode::Up | KeyCode::Char('k') => state.step(-1),
            KeyCode::Down | KeyCode::Char('j') => state.step(1),
            KeyCode::Enter => state.enter(),
            KeyCode::Char('r') if !pending => next_refresh = Instant::now(),
            KeyCode::Char('n') | KeyCode::Char(']') if !pending && state.page_coding(true) => {
                next_refresh = Instant::now();
            }
            KeyCode::Char('p') | KeyCode::Char('[') if !pending && state.page_coding(false) => {
                next_refresh = Instant::now();
            }
            _ => (),
        }
    }
    drop(request_tx);
    ratatui::restore();
    let subject = state
        .selected_id
        .as_deref()
        .or(reconnect.as_deref())
        .map(crate::client::terminal_text)
        .map(|text| model::redact_ledger_hex(&text))
        .unwrap_or_default()
        .replace('\'', "'\\''");
    let path = reconnect_state_dir(&directory);
    println!(
        "DETACHED: durable work continues. Reconnect: bullet tui --state-dir '{path}'{}",
        if subject.is_empty() {
            String::new()
        } else {
            format!(" --subject '{subject}'")
        }
    );
    Ok(())
}

#[cfg(unix)]
fn reconnect_state_dir(directory: &std::path::Path) -> String {
    let raw = crate::client::terminal_text(&directory.to_string_lossy()).replace('\'', "'\\''");
    let Ok(home) = std::env::var("HOME") else {
        return raw;
    };
    let home = crate::client::terminal_text(&home);
    raw.strip_prefix(&home)
        .map(|rest| format!("$HOME{rest}"))
        .unwrap_or(raw)
}

#[cfg(unix)]
struct RestoreTerminal;
#[cfg(unix)]
impl Drop for RestoreTerminal {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
