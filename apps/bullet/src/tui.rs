//! The operator console is a consumer of the same atomic snapshot as the Portal.

#[cfg(unix)]
mod loader;
mod model;
mod submissions;
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
    use std::time::{Duration, Instant};

    let mut state = model::Model::default();
    let mut reconnect = args.subject;
    if args.once
        || !std::io::stdout().is_terminal()
        || std::env::var("TERM").as_deref() == Ok("dumb")
    {
        let directory = crate::auth::state_dir(args.state_dir)?;
        let credentials = crate::auth::store::CredentialStore::read_credentials(&directory)?
            .ok_or("AUTH_REQUIRED: run bullet auth login")?;
        state.destination = crate::client::terminal_text(&credentials.farmd);
        state.update(crate::client::operator_snapshot(&credentials));
        state
            .submissions
            .update(crate::client::coding_commands(&credentials));
        if let Some(subject) = reconnect {
            if subject.starts_with("cmd_") && state.submissions.error.is_some() {
                state.error = state.submissions.error.clone();
            } else {
                state.reconnect(&subject);
            }
        }
        println!("{}", state.plain());
        return state.error.map_or(Ok(()), Err);
    }
    if !std::io::stdin().is_terminal() {
        return Err("TUI_TERMINAL_REQUIRED: use --once".into());
    }
    let mut terminal = ratatui::try_init().map_err(|_| "TUI_TERMINAL_UNAVAILABLE")?;
    let _restore = RestoreTerminal;
    let color = std::env::var_os("NO_COLOR").is_none();
    // Paint before even starting credential or destination discovery.
    terminal
        .draw(|frame| ui::draw(frame, &mut state, color))
        .map_err(|_| "TUI_DRAW_FAILED")?;
    let (request_tx, response_rx) = loader::start(args.state_dir.clone());
    let mut directory = args.state_dir;
    let mut identity = None;
    request_tx
        .try_send(())
        .map_err(|_| "TUI_REFRESH_UNAVAILABLE")?;
    let mut next_refresh = Instant::now() + Duration::from_secs(2);
    let mut pending = true;
    state.refresh_pending = true;
    loop {
        while let Ok(event) = response_rx.try_recv() {
            match event {
                loader::Event::Credentials {
                    identity: owner,
                    directory: path,
                    destination,
                } => {
                    if identity.as_ref() != Some(&owner) {
                        state.clear_owner();
                    }
                    identity = Some(owner);
                    directory = Some(path);
                    state.destination = destination;
                }
                loader::Event::Snapshot { operator, commands } => {
                    pending = false;
                    state.submissions.update(*commands);
                    state.update(*operator);
                    state.rebuild();
                    let ready = reconnect.as_deref().is_some_and(|subject| {
                        if subject.starts_with("cmd_") {
                            state.submissions.snapshot.is_some()
                                && state.submissions.error.is_none()
                        } else {
                            state.snapshot.is_some() && state.error.is_none()
                        }
                    });
                    if ready {
                        if let Some(subject) = reconnect.take() {
                            state.reconnect(&subject);
                        }
                    }
                }
                loader::Event::Authentication(error) => {
                    pending = false;
                    identity = None;
                    state.clear_owner();
                    state.update(Err(error));
                }
            }
        }
        if !pending && Instant::now() >= next_refresh {
            request_tx
                .try_send(())
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
            _ => (),
        }
    }
    drop(request_tx);
    ratatui::restore();
    let subject = reconnect
        .as_deref()
        .or(state.selected_id.as_deref())
        .map(crate::client::terminal_text)
        .unwrap_or_default()
        .replace('\'', "'\\''");
    let path = directory
        .as_deref()
        .map(reconnect_state_dir)
        .map(|path| format!(" --state-dir {path}"))
        .unwrap_or_default();
    println!(
        "DETACHED: durable work continues. Reconnect: bullet tui{path}{}",
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
    let home = std::env::var_os("HOME").map(PathBuf::from);
    reconnect_path_word(directory, home.as_deref())
}

#[cfg(unix)]
fn reconnect_path_word(directory: &std::path::Path, home: Option<&std::path::Path>) -> String {
    let quote = |path: &std::path::Path| {
        format!(
            "'{}'",
            crate::client::terminal_text(&path.to_string_lossy()).replace('\'', "'\\''")
        )
    };
    if let Some(home) = home.filter(|path| !path.as_os_str().is_empty()) {
        if let Ok(rest) = directory.strip_prefix(home) {
            return if rest.as_os_str().is_empty() {
                "\"$HOME\"".into()
            } else {
                format!("\"$HOME\"/{}", quote(rest))
            };
        }
    }
    quote(directory)
}

#[cfg(all(test, unix))]
mod tests {
    use super::reconnect_path_word;
    use std::path::Path;

    #[test]
    fn reconnect_path_preserves_shell_expansion_quotes_and_home_boundaries() {
        let home = Path::new("/home/operator");
        assert_eq!(reconnect_path_word(home, Some(home)), "\"$HOME\"");
        let word = reconnect_path_word(Path::new("/home/operator/state ' $(false)"), Some(home));
        assert_eq!(word, "\"$HOME\"/'state '\\'' $(false)'");
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s' {word}"))
            .output()
            .unwrap();
        assert!(output.status.success());
        let expected = Path::new(&std::env::var_os("HOME").unwrap()).join("state ' $(false)");
        assert_eq!(output.stdout, expected.as_os_str().as_encoded_bytes());
        assert_eq!(
            reconnect_path_word(Path::new("/home/operator-extra/state"), Some(home)),
            "'/home/operator-extra/state'"
        );
        assert_eq!(
            reconnect_path_word(Path::new("/tmp/private state"), None),
            "'/tmp/private state'"
        );
    }
}

#[cfg(unix)]
struct RestoreTerminal;
#[cfg(unix)]
impl Drop for RestoreTerminal {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
