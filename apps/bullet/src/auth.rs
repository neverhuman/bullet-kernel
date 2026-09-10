//! Operator client authentication. Credentials never appear in normal output.

#[cfg(unix)]
mod input;
#[cfg(unix)]
mod session;
#[cfg(unix)]
pub(crate) mod store;

#[cfg(unix)]
use crate::coding::http;
use clap::Subcommand;
use std::path::PathBuf;
#[cfg(unix)]
use store::{CredentialStore, Credentials};

#[derive(Subcommand)]
pub(crate) enum AuthCommands {
    /// Exchange a one-time bootstrap token using hidden input or a pipe.
    Login {
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        farmd: String,
        #[arg(long, default_value = "http://127.0.0.1:7420")]
        origin: String,
        /// Read the token from a pipe; never pass it as a command argument.
        #[arg(long)]
        stdin: bool,
        /// Private client state directory (defaults to XDG_STATE_HOME/bullet/operator).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Check the saved session against the daemon without displaying its secrets.
    Status {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Revoke this server session and remove its local credential copy.
    #[command(alias = "logout")]
    Revoke {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Delete this client's credential copy. This does not revoke server authority.
    Forget {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[cfg(unix)]
pub(crate) fn state_dir(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    let path = explicit
        .or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
                .map(|p| p.join("bullet/operator"))
        })
        .ok_or("AUTH_STATE_DIRECTORY_REQUIRED")?;
    if !path.is_absolute() {
        return Err("AUTH_STATE_DIRECTORY_MUST_BE_ABSOLUTE".into());
    }
    Ok(path)
}

#[cfg(not(unix))]
pub(crate) fn run(_command: AuthCommands) -> Result<(), String> {
    Err(
        "AUTH_PRIVATE_STORE_UNSUPPORTED: this platform has no qualified private credential store"
            .into(),
    )
}

#[cfg(unix)]
pub(crate) fn run(command: AuthCommands) -> Result<(), String> {
    match command {
        AuthCommands::Login {
            farmd,
            origin,
            stdin,
            state_dir: directory,
        } => {
            http::parse_loopback(&farmd)?;
            http::parse_loopback(&origin)?;
            let store = CredentialStore::open(&state_dir(directory)?)?;
            if store.load()?.is_some() {
                return Err(
                    "AUTH_ALREADY_STORED: check auth status before replacing credentials".into(),
                );
            }
            store.require_no_pending()?;
            let token = input::bootstrap(stdin)?;
            http::validate_secret(&token, "boot")?;
            let (cookie, csrf) = http::exchange_bootstrap(&farmd, &origin, &token)?;
            store.save(&Credentials {
                schema_version: 1,
                farmd,
                origin,
                cookie,
                csrf,
            })?;
            println!("AUTHENTICATED: credentials saved privately; use bullet auth status to check the session");
            Ok(())
        }
        AuthCommands::Status {
            state_dir: directory,
        } => {
            let credentials = CredentialStore::read_credentials(&state_dir(directory)?)?
                .ok_or("AUTH_REQUIRED: run bullet auth login")?;
            let view = session::status(&credentials)?;
            println!(
                "AUTHENTICATED: operator {} · session {} · expires {}",
                view.operator_id, view.session_id, view.expires_at
            );
            Ok(())
        }
        AuthCommands::Revoke {
            state_dir: directory,
        } => {
            let store = CredentialStore::open(&state_dir(directory)?)?;
            let credentials = store
                .load()?
                .ok_or("AUTH_REQUIRED: run bullet auth login")?;
            let view = session::revoke(&credentials)?;
            store.forget()?;
            println!(
                "REVOKED: session {} at {}; local credentials removed",
                view.session_id, view.revoked_at
            );
            Ok(())
        }
        AuthCommands::Forget {
            state_dir: directory,
        } => {
            CredentialStore::open(&state_dir(directory)?)?.forget()?;
            println!("FORGOTTEN: local credentials removed; server authority was not revoked");
            Ok(())
        }
    }
}
