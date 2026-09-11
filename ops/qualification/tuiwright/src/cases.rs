use crate::{evidence::Evidence, fixture::Fixture, session::Session};
use anyhow::{bail, ensure, Result};
use serde_json::json;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tuiwright::Key;

pub const IDENTITIES: [&str; 4] = [
    "six_withheld_http",
    "six_locked_credentials",
    "six_missing_credentials",
    "revoked_owner_recovery",
];

pub fn run(id: &str, binary: &Path, evidence: &mut Evidence) -> Result<()> {
    match id {
        "six_withheld_http" => six_clients(id, binary, evidence, "CONNECTING"),
        "six_locked_credentials" => six_clients(id, binary, evidence, "AUTH_BUSY"),
        "six_missing_credentials" => six_clients(id, binary, evidence, "AUTH_REQUIRED"),
        "revoked_owner_recovery" => revoked(id, binary, evidence),
        _ => bail!("CASE_UNKNOWN"),
    }
}

fn spawn(binary: &Path, fixture: &Fixture) -> Result<Session> {
    Session::start(
        binary,
        &[
            "tui".into(),
            "--state-dir".into(),
            fixture.directory.path().to_string_lossy().into_owned(),
        ],
        None,
    )
}

fn key(
    id: &str,
    client: usize,
    session: &Session,
    key: Key,
    evidence: &mut Evidence,
) -> Result<()> {
    evidence.event(id, "key", json!({"client":client,"key":format!("{key}")}))?;
    session.page().press(key)
}

fn navigate(id: &str, client: usize, session: &Session, evidence: &mut Evidence) -> Result<()> {
    let start = Instant::now();
    key(id, client, session, Key::Char('?'), evidence)?;
    session.wait_text("Operator help")?;
    evidence.event(
        id,
        "key_to_observed_screen",
        json!({"client":client,"elapsed_us":start.elapsed().as_micros()}),
    )?;
    key(id, client, session, Key::Esc, evidence)?;
    session
        .page()
        .expect_screen()
        .not_to_contain_text("Operator help")?;
    key(id, client, session, Key::Ctrl('k'), evidence)?;
    session.wait_text("Navigate")?;
    key(id, client, session, Key::Char('j'), evidence)?;
    key(id, client, session, Key::Enter, evidence)?;
    session.wait_text("┌Tasks")?;
    for (cols, rows) in [(96, 24), (120, 30)] {
        evidence.event(
            id,
            "resize",
            json!({"client":client,"cols":cols,"rows":rows}),
        )?;
        session.page().resize(cols, rows)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let screen = loop {
            let screen = session.page().screen();
            // Page changes its parser dimensions immediately. These corners at
            // the new right edge additionally require Bullet's actual redraw.
            if screen.cols == cols
                && screen.rows == rows
                && screen.contains_text("┌Tasks")
                && screen
                    .cell(3, cols - 1)
                    .is_some_and(|cell| cell.text == "┐")
                && screen
                    .cell(rows - 4, cols - 1)
                    .is_some_and(|cell| cell.text == "┘")
            {
                break screen;
            }
            ensure!(session.running()?, "PROCESS_EXITED_DURING_RESIZE");
            ensure!(
                Instant::now() < deadline,
                "APPLICATION_RESIZE_REDRAW_NOT_OBSERVED"
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        evidence.screen(id, client, "navigation-resize", screen)?;
    }
    Ok(())
}

fn submissions(id: &str, client: usize, session: &Session, evidence: &mut Evidence) -> Result<()> {
    // Palette selection starts at Missions; these are actual task, Attempt and
    // submission views, not a fixture-created task for a pending command.
    for (steps, title) in [(1, "┌Tasks"), (2, "┌Session Supervisor")] {
        key(id, client, session, Key::Ctrl('k'), evidence)?;
        session.wait_text("Navigate")?;
        for _ in 0..steps {
            key(id, client, session, Key::Char('j'), evidence)?;
        }
        key(id, client, session, Key::Enter, evidence)?;
        session.wait_text(title)?;
        ensure!(
            !session.page().screen().contains_text("run_coding"),
            "SUBMISSION_FABRICATED_AS_EXECUTION"
        );
        evidence.screen(
            id,
            client,
            "no-submission-execution-join",
            session.page().screen(),
        )?;
    }
    key(id, client, session, Key::Ctrl('k'), evidence)?;
    session.wait_text("Navigate")?;
    for _ in 0..6 {
        key(id, client, session, Key::Char('j'), evidence)?;
    }
    key(id, client, session, Key::Enter, evidence)?;
    session.wait_text("┌Submissions")?;
    session.wait_text("submissions snapshot 9")?;
    session.wait_text("[PENDING] run_coding submission")?;
    key(id, client, session, Key::Char('J'), evidence)?;
    session.wait_text("raw JSON")?;
    let screen = session.page().screen();
    ensure!(
        screen.cols == 120 && screen.rows == 30,
        "SUBMISSION_GEOMETRY_CHANGED"
    );
    // Read only the inspector's interior, joining its wrapped lines. Preserve
    // the complete unmodified raster/text observation in the screen artifact.
    let detail = (4..26)
        .map(|row| {
            (55..119)
                .filter_map(|col| screen.cell(row, col))
                .map(|cell| cell.text.as_str())
                .collect::<String>()
                .trim()
                .to_owned()
        })
        .collect::<String>();
    ensure!(
        detail.contains(&format!("cmd_{}", "2".repeat(64))),
        "SUBMISSION_ID_CHANGED"
    );
    ensure!(
        detail.contains(&"3".repeat(64)),
        "SUBMISSION_DIGEST_CHANGED"
    );
    evidence.screen(id, client, "independent-submission", screen)?;
    key(id, client, session, Key::Char('J'), evidence)?;
    Ok(())
}

fn six_clients(id: &str, binary: &Path, evidence: &mut Evidence, blocked: &str) -> Result<()> {
    let fixture = Fixture::start(blocked == "CONNECTING")?;
    let lock = if blocked == "AUTH_BUSY" {
        Some(fixture.lock_credentials()?)
    } else {
        None
    };
    if blocked == "AUTH_REQUIRED" {
        fixture.credentials(false)?;
    }
    let mut clients = Vec::new();
    for client in 0..6 {
        let session = spawn(binary, &fixture)?;
        let painted = session.wait_text(blocked)?;
        evidence.event(
            id,
            "first_observed_shell",
            json!({"client":client,"elapsed_us":painted.as_micros(),"state":blocked}),
        )?;
        evidence.screen(id, client, "blocked-shell", session.page().screen())?;
        clients.push(session);
    }
    for (client, session) in clients.iter().enumerate() {
        ensure!(
            !session.page().screen().contains_text("OBSERVED"),
            "UNOBSERVED_DATA_LABELLED_OBSERVED"
        );
        navigate(id, client, session, evidence)?;
    }
    if blocked == "CONNECTING" {
        let deadline = Instant::now() + Duration::from_secs(5);
        while fixture.reads.load(Ordering::SeqCst) < 6 {
            ensure!(Instant::now() < deadline, "SIX_REQUESTS_NOT_OBSERVED");
            std::thread::sleep(Duration::from_millis(2));
        }
    } else {
        ensure!(
            fixture.reads.load(Ordering::SeqCst) == 0,
            "GET_BEFORE_CREDENTIAL_DISCOVERY"
        );
    }
    let first_exit = clients[0].detach()?;
    evidence.event(
        id,
        "detached_while_blocked",
        serde_json::to_value(first_exit)?,
    )?;
    for session in &clients[1..] {
        ensure!(session.running()?, "COUPLED_DETACH");
    }
    drop(lock);
    if blocked == "AUTH_REQUIRED" {
        fixture.credentials(true)?;
    }
    fixture.gate.store(false, Ordering::SeqCst);
    for (client, session) in clients.iter_mut().enumerate().skip(1) {
        key(id, client, session, Key::Char('r'), evidence)?;
        session.wait_text("OBSERVED")?;
        session.wait_text("┌Tasks")?;
        evidence.screen(id, client, "recovered", session.page().screen())?;
        submissions(id, client, session, evidence)?;
        evidence.event(id, "detached", serde_json::to_value(session.detach()?)?)?;
    }
    fixture.finish()?;
    Ok(())
}

fn revoked(id: &str, binary: &Path, evidence: &mut Evidence) -> Result<()> {
    for (client, status) in [401, 403].into_iter().enumerate() {
        let fixture = Fixture::start(false)?;
        let mut session = spawn(binary, &fixture)?;
        session.wait_text("Synthetic Tuiwright mission")?;
        fixture.status.store(status, Ordering::SeqCst);
        key(id, client, &session, Key::Char('r'), evidence)?;
        session.wait_text(&format!("FARMD_SNAPSHOT_REFUSED: HTTP {status}"))?;
        let screen = session.page().screen();
        ensure!(
            !screen.contains_text("Synthetic Tuiwright mission")
                && !screen.contains_text("OBSERVED")
                && !screen.contains_text("STALE"),
            "REVOKED_OWNER_DATA_RETAINED"
        );
        evidence.screen(id, client, "revoked-owner-cleared", screen)?;
        key(id, client, &session, Key::Char('?'), evidence)?;
        session.wait_text("Operator help")?;
        key(id, client, &session, Key::Esc, evidence)?;
        session
            .page()
            .expect_screen()
            .not_to_contain_text("Operator help")?;
        fixture.status.store(200, Ordering::SeqCst);
        key(id, client, &session, Key::Char('r'), evidence)?;
        session.wait_text("Synthetic Tuiwright mission")?;
        evidence.screen(id, client, "owner-recovered", session.page().screen())?;
        submissions(id, client, &session, evidence)?;
        evidence.event(id, "detached", serde_json::to_value(session.detach()?)?)?;
        fixture.finish()?;
    }
    Ok(())
}
