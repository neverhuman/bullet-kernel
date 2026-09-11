//! Bounded background discovery and authenticated reads for an attached console.

use crate::auth::store::{CredentialStore, Credentials};
use crate::client::models::{CommandDiscoverySnapshot, OperatorSnapshot};
use bullet_domain::Digest;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender};

pub(super) enum Event {
    Credentials {
        identity: String,
        directory: PathBuf,
        destination: String,
    },
    Snapshot {
        operator: Box<Result<OperatorSnapshot, String>>,
        commands: Box<Result<CommandDiscoverySnapshot, String>>,
    },
    Authentication(String),
}

fn identity(credentials: &Credentials) -> String {
    // Only a one-way local comparison key crosses into the view. Tokens never
    // enter a display, diagnostic record, or durable projection.
    let mut bytes = Vec::new();
    for field in [
        &credentials.farmd,
        &credentials.origin,
        &credentials.cookie,
        &credentials.csrf,
    ] {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    Digest::of(&bytes).to_hex()
}

fn load(selected: Option<PathBuf>, responses: &SyncSender<Event>) -> Result<(), String> {
    let directory = crate::auth::state_dir(selected)?;
    let credentials = CredentialStore::read_credentials(&directory)?
        .ok_or("AUTH_REQUIRED: run bullet auth login, then refresh")?;
    let selected_identity = identity(&credentials);
    responses
        .send(Event::Credentials {
            identity: selected_identity.clone(),
            directory: directory.clone(),
            destination: crate::client::terminal_text(&credentials.farmd),
        })
        .map_err(|_| "TUI_DETACHED")?;
    let snapshot = crate::client::operator_snapshot(&credentials);
    let current = CredentialStore::read_credentials(&directory)?
        .ok_or("AUTH_REQUIRED: local credentials were removed")?;
    if identity(&current) != selected_identity {
        return Err("AUTH_CHANGED: credentials changed during the read; refreshing".into());
    }
    if matches!(
        snapshot.as_ref().map_err(String::as_str),
        Err("FARMD_SNAPSHOT_REFUSED: HTTP 401" | "FARMD_SNAPSHOT_REFUSED: HTTP 403")
    ) {
        return snapshot.map(|_| ());
    }
    let commands = crate::client::coding_commands(&credentials);
    let current = CredentialStore::read_credentials(&directory)?
        .ok_or("AUTH_REQUIRED: local credentials were removed")?;
    if identity(&current) != selected_identity {
        return Err("AUTH_CHANGED: credentials changed during command read".into());
    }
    if matches!(
        commands.as_ref().map_err(String::as_str),
        Err("FARMD_COMMANDS_REFUSED: HTTP 401" | "FARMD_COMMANDS_REFUSED: HTTP 403")
    ) {
        return commands.map(|_| ());
    }
    responses
        .send(Event::Snapshot {
            operator: Box::new(snapshot),
            commands: Box::new(commands),
        })
        .map_err(|_| "TUI_DETACHED".into())
}

pub(super) fn start(selected: Option<PathBuf>) -> (SyncSender<()>, Receiver<Event>) {
    let (requests, receiver) = mpsc::sync_channel(1);
    let (responses, events) = mpsc::sync_channel(1);
    // Discovery and filesystem contention cannot hold the terminal event loop.
    // Dropping this client never sends cancellation or any farm mutation.
    std::thread::spawn(move || {
        while receiver.recv().is_ok() {
            if let Err(error) = load(selected.clone(), &responses) {
                if responses.send(Event::Authentication(error)).is_err() {
                    break;
                }
            }
        }
    });
    (requests, events)
}
