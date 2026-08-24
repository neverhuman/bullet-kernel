//! Trust-boundary runner. Speaks the versioned loopback protocol.

mod protocol;
mod supervisor;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use protocol::{DispatchRequest, HeartbeatRequest, SalvageRequest, TerminateRequest};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use supervisor::Supervisor;

#[derive(Parser)]
#[command(name = "bullet-runner")]
struct Args {
    /// Journal directory.
    #[arg(long, default_value = "./target/demo/runner")]
    data_dir: PathBuf,
    /// Bind address. Loopback only.
    #[arg(long, default_value = "127.0.0.1:7421")]
    bind: SocketAddr,
}

#[derive(Clone)]
struct AppState {
    supervisor: Arc<Supervisor>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let supervisor =
        Supervisor::open(&args.data_dir).unwrap_or_else(|err| panic!("journal: {err}"));
    let app = router(supervisor);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .unwrap_or_else(|err| panic!("bind: {err}"));
    axum::serve(listener, app)
        .await
        .unwrap_or_else(|err| panic!("serve: {err}"));
}

fn router(supervisor: Supervisor) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/dispatch", post(dispatch))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/salvage", post(salvage))
        .route("/v1/terminate", post(terminate))
        .with_state(AppState {
            supervisor: Arc::new(supervisor),
        })
}

async fn dispatch(
    State(state): State<AppState>,
    Json(req): Json<DispatchRequest>,
) -> impl IntoResponse {
    match state.supervisor.dispatch(&req.session, None) {
        Ok(checkpoint) => (StatusCode::OK, Json(checkpoint)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err).into_response(),
    }
}

async fn heartbeat(
    State(state): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> impl IntoResponse {
    match state.supervisor.heartbeat(&req.session) {
        Ok(checkpoint) => (StatusCode::OK, Json(checkpoint)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err).into_response(),
    }
}

async fn salvage(
    State(state): State<AppState>,
    Json(req): Json<SalvageRequest>,
) -> impl IntoResponse {
    match state.supervisor.salvage(&req.session) {
        Ok(checkpoint) => (StatusCode::OK, Json(checkpoint)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err).into_response(),
    }
}

async fn terminate(
    State(state): State<AppState>,
    Json(req): Json<TerminateRequest>,
) -> impl IntoResponse {
    match state.supervisor.terminate(&req.session) {
        Ok(checkpoint) => (StatusCode::OK, Json(checkpoint)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err).into_response(),
    }
}
