//! Control-plane daemon. The portal is a projection of this API.

mod api;

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

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
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir).unwrap_or_else(|err| panic!("create data dir: {err}"));
    let db = args.data_dir.join("ledger.sqlite");
    let app = api::router(&db);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .unwrap_or_else(|err| panic!("bind: {err}"));
    tracing::info!("bullet-farmd listening on {}", args.bind);
    axum::serve(listener, app)
        .await
        .unwrap_or_else(|err| panic!("serve: {err}"));
}
