//! Control-plane daemon. The portal is a projection of this API.

#[path = "main/launch.rs"]
mod launch;

use bullet_farmd::api;
use bullet_farmd::reaper::{self, ReapInterval};
use clap::Parser;
#[cfg(test)]
use launch::admit_lease_transport;
use launch::{
    admit_lease_transport_launch, provision_lease_transport_key, read_worker_token, validate_bind,
};
#[cfg(all(test, unix))]
use launch::{open_worker_token, read_worker_token_descriptor};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "bullet-farmd")]
struct Args {
    /// Create one durable lease-transport signing key and exit. The path must
    /// be absolute, absent, and beneath a private caller-owned directory.
    #[arg(long, value_name = "ABSOLUTE_PATH", exclusive = true)]
    provision_lease_transport_key: Option<PathBuf>,
    /// SQLite data directory.
    #[arg(long, default_value = "./target/demo")]
    data_dir: PathBuf,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:7420")]
    bind: SocketAddr,
    /// Exact loopback Portal origin allowed to bootstrap and mutate.
    #[arg(long)]
    portal_origin: Option<String>,
    /// Protected file containing the independent `wrk_` bearer for the
    /// internal command reconciler. Without it, the internal route is inert.
    #[arg(long)]
    worker_token_file: Option<PathBuf>,
    /// Writer-lease maintenance interval in milliseconds, 1..=500. The daemon
    /// always reaps; this argument may only make it reap more often. The
    /// default is half the shortest lease the ledger admits, so an expired
    /// lease waits at most one tick before it is reclaimed.
    #[arg(long, default_value_t = ReapInterval::policy_default())]
    reap_interval_ms: ReapInterval,
    /// Reserved Unix socket input. Refuses until durable peer registration exists.
    #[arg(long)]
    lease_transport_socket: Option<PathBuf>,
    /// Durable local peer-registry file (0700 parent, 0600 file).
    #[arg(long, requires = "lease_transport_socket")]
    lease_peer_registry: Option<PathBuf>,
    /// Durable local lease-transport signing key (0700 parent, 0600, 64 bytes).
    #[arg(long, requires = "lease_transport_socket")]
    lease_transport_key: Option<PathBuf>,
    /// Absolute Kernel authority socket for production gitd permit mint/check.
    #[arg(long, requires = "lease_transport_socket")]
    kernel_authority_socket: Option<PathBuf>,
    /// Debug-only exact Runner incarnation for component fixtures.
    #[cfg(debug_assertions)]
    #[arg(long, requires = "lease_transport_socket")]
    fixture_lease_peer_registration: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    if let Some(path) = args.provision_lease_transport_key.as_deref() {
        return match provision_lease_transport_key(path) {
            Ok(()) => {
                println!("LEASE_TRANSPORT_KEY_PROVISIONED: {}", path.display());
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("bullet-farmd: {message}");
                ExitCode::FAILURE
            }
        };
    }
    let lease_launch = match admit_lease_transport_launch(&args) {
        Ok(launch) => launch,
        Err(message) => {
            eprintln!("bullet-farmd: {message}");
            return ExitCode::FAILURE;
        }
    };
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
    let worker_token = match args.worker_token_file.as_deref().map(read_worker_token) {
        Some(Ok(token)) => Some(token),
        Some(Err(error)) => {
            eprintln!("bullet-farmd: worker token: {error}");
            return ExitCode::FAILURE;
        }
        None => None,
    };
    let db = args.data_dir.join("ledger.sqlite");
    let (app, state) = match api::daemon(
        &db,
        Some(&bootstrap),
        origin.clone(),
        worker_token.as_deref(),
    ) {
        Ok(parts) => parts,
        Err(err) => {
            eprintln!("bullet-farmd: initialize local API: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!("Bullet Farm one-time bootstrap: {bootstrap}");
    println!("Exchange at: {origin}/api/v1/auth/bootstrap");
    if worker_token.is_some() {
        tracing::info!("authenticated internal command reconciler enabled");
    }
    let mut lease_task: Option<tokio::task::JoinHandle<Result<(), std::io::Error>>> = None;
    if let Some(launch) = lease_launch {
        // A daemon that crashed or was killed leaves its socket file behind,
        // and the admission path refuses to replace an existing path -- so a
        // restart on the same path used to be impossible. Recover the one
        // safe case ourselves: a path nothing is listening on is stale and is
        // removed; a live listener means another daemon owns it, which is
        // fatal here rather than a squat to bulldoze.
        if launch.socket.exists() {
            match std::os::unix::net::UnixStream::connect(&launch.socket) {
                Ok(_) => {
                    eprintln!(
                        "bullet-farmd: lease-transport socket {} is live; another daemon owns it",
                        launch.socket.display()
                    );
                    return ExitCode::FAILURE;
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    if let Err(remove) = std::fs::remove_file(&launch.socket) {
                        eprintln!(
                            "bullet-farmd: cannot remove stale lease-transport socket {}: {remove}",
                            launch.socket.display()
                        );
                        return ExitCode::FAILURE;
                    }
                    tracing::warn!(
                        "removed stale lease-transport socket {}",
                        launch.socket.display()
                    );
                }
                Err(error) => {
                    eprintln!(
                        "bullet-farmd: lease-transport socket {} is unusable: {error}",
                        launch.socket.display()
                    );
                    return ExitCode::FAILURE;
                }
            }
        }
        let fixture = launch.fixture;
        let key_bytes = launch.key_bytes;
        let candidate_key = launch.candidate_key;
        let rpc_state = state.clone();
        lease_task = Some(tokio::spawn(async move {
            let result = match candidate_key {
                Some(key) => {
                    bullet_farmd::lease_transport_rpc::serve_with_candidate(
                        launch.socket,
                        rpc_state,
                        launch.transport,
                        launch.registry,
                        key,
                    )
                    .await
                }
                None => {
                    bullet_farmd::lease_transport_rpc::serve(
                        launch.socket,
                        rpc_state,
                        launch.transport,
                        launch.registry,
                    )
                    .await
                }
            };
            result
        }));
        if fixture {
            if args.kernel_authority_socket.is_some() {
                eprintln!(
                    "bullet-farmd: LEASE_PEER_REGISTRY_UNAVAILABLE: Kernel authority is not admitted on the debug fixture path"
                );
                return ExitCode::FAILURE;
            }
            tracing::warn!("debug-only fixture lease peer registration enabled");
        } else {
            tracing::info!("durable local lease-transport admission enabled");
        }
        if let (Some(kernel_socket), Some(key_bytes)) =
            (args.kernel_authority_socket.clone(), key_bytes)
        {
            let kernel = match bullet_farmd::kernel_authority::KernelAuthority::from_secret_bytes(
                &key_bytes,
            ) {
                Ok(kernel) => std::sync::Arc::new(kernel),
                Err(error) => {
                    eprintln!("bullet-farmd: kernel authority key: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let process = match std::fs::metadata("/proc/self") {
                Ok(meta) => meta,
                Err(error) => {
                    eprintln!("bullet-farmd: kernel authority identity: {error}");
                    return ExitCode::FAILURE;
                }
            };
            use std::os::unix::fs::MetadataExt;
            let farmd_uid = process.uid();
            let rpc_state = state.clone();
            tokio::spawn(async move {
                if let Err(error) = bullet_farmd::kernel_authority_rpc::serve(
                    kernel_socket,
                    rpc_state,
                    kernel,
                    farmd_uid,
                )
                .await
                {
                    tracing::error!("kernel-authority socket: {error}");
                }
            });
            tracing::info!("durable Kernel authority socket enabled");
        }
    }
    tracing::info!("bullet-farmd listening on {bound}");
    // Reclaiming an expired writer lease is the running daemon's own job, not
    // an operator's: without this tick a Variant whose runner died is freed
    // only when some successor happens to try to acquire it.
    let _tick = reaper::spawn(state.clone(), args.reap_interval_ms);
    // The lease-transport listener is load-bearing: a runner that cannot
    // reach it makes every attempt refuse. Its death used to be a detached
    // log line while the HTTP surface kept reporting healthy; now it takes
    // the daemon down with a visible error.
    match lease_task {
        Some(mut handle) => {
            tokio::select! {
                served = axum::serve(listener, app) => {
                    if let Err(err) = served {
                        eprintln!("bullet-farmd: serve: {err}");
                        return ExitCode::FAILURE;
                    }
                }
                lease = &mut handle => {
                    match lease {
                        Ok(Ok(())) => eprintln!(
                            "bullet-farmd: lease-transport listener exited; shutting down"
                        ),
                        Ok(Err(error)) => eprintln!(
                            "bullet-farmd: lease-transport socket failed: {error}"
                        ),
                        Err(join) => eprintln!(
                            "bullet-farmd: lease-transport task panicked: {join}"
                        ),
                    }
                    return ExitCode::FAILURE;
                }
            }
        }
        None => {
            if let Err(err) = axum::serve(listener, app).await {
                eprintln!("bullet-farmd: serve: {err}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
