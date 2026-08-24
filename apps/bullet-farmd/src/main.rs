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
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    if let Err(err) = std::fs::create_dir_all(&args.data_dir) {
        eprintln!("bullet-farmd: create data dir: {err}");
        return ExitCode::FAILURE;
    }
    let db = args.data_dir.join("ledger.sqlite");
    let app = match api::router(&db) {
        Ok(app) => app,
        Err(err) => {
            eprintln!("bullet-farmd: open ledger: {err}");
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
    tracing::info!("bullet-farmd listening on {}", args.bind);
    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("bullet-farmd: serve: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
