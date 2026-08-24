//! Control-plane daemon. The portal is a projection of this API.

use bullet_farmd::api;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "bullet-farmd")]
struct Args {
    /// SQLite data directory.
    #[arg(long, default_value = "./target/demo")]
    data_dir: PathBuf,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:7420")]
    bind: SocketAddr,
    /// Exact loopback Portal origin allowed to bootstrap and mutate.
    #[arg(long)]
    portal_origin: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    if let Err(message) = validate_bind(args.bind) {
        eprintln!("bullet-farmd: {message}");
        return ExitCode::FAILURE;
    }
    if let Err(err) = std::fs::create_dir_all(&args.data_dir) {
        eprintln!("bullet-farmd: create data dir: {err}");
        return ExitCode::FAILURE;
    }
    let bootstrap = match bullet_farmd::auth::random_token("boot") {
        Ok(token) => token,
        Err(err) => {
            eprintln!("bullet-farmd: create bootstrap token: {err}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(args.bind).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("bullet-farmd: bind {}: {err}", args.bind);
            return ExitCode::FAILURE;
        }
    };
    let bound = match listener.local_addr() {
        Ok(bound) => bound,
        Err(err) => {
            eprintln!("bullet-farmd: inspect bound address: {err}");
            return ExitCode::FAILURE;
        }
    };
    let origin = args
        .portal_origin
        .unwrap_or_else(|| format!("http://{bound}"));
    let db = args.data_dir.join("ledger.sqlite");
    let app = match api::router_with_bootstrap(&db, &bootstrap, origin.clone()) {
        Ok(app) => app,
        Err(err) => {
            eprintln!("bullet-farmd: initialize local API: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!("Bullet Farm one-time bootstrap: {bootstrap}");
    println!("Exchange at: {origin}/v1/auth/bootstrap");
    tracing::info!("bullet-farmd listening on {bound}");
    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("bullet-farmd: serve: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn validate_bind(bind: SocketAddr) -> Result<(), String> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "refusing non-loopback bind {bind}; local V1 accepts loopback only"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_v1_accepts_only_loopback_addresses() {
        for address in ["127.0.0.1:7420", "[::1]:7420"] {
            let parsed: SocketAddr = address.parse().expect("loopback socket");
            assert!(validate_bind(parsed).is_ok(), "{address}");
        }
        for address in ["0.0.0.0:7420", "192.0.2.1:7420", "[::]:7420"] {
            let parsed: SocketAddr = address.parse().expect("non-loopback socket");
            assert!(validate_bind(parsed).is_err(), "{address}");
        }
    }
}
