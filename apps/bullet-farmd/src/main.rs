//! Control-plane daemon. The portal is a projection of this API.

use bullet_farmd::api;
use bullet_farmd::reaper::{self, ReapInterval};
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
    /// Debug-only exact Runner incarnation for component fixtures.
    #[cfg(debug_assertions)]
    #[arg(long, requires = "lease_transport_socket")]
    fixture_lease_peer_registration: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    #[cfg(debug_assertions)]
    let fixture_lease_registry = match validate_lease_transport_config(
        args.lease_transport_socket.as_deref(),
        args.fixture_lease_peer_registration.as_deref(),
    ) {
        Ok(registry) => registry,
        Err(message) => {
            eprintln!("bullet-farmd: {message}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(not(debug_assertions))]
    if let Err(message) = validate_lease_transport_config(args.lease_transport_socket.as_deref()) {
        eprintln!("bullet-farmd: {message}");
        return ExitCode::FAILURE;
    }
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
    #[cfg(debug_assertions)]
    if let (Some(socket), Some(registry)) = (args.lease_transport_socket, fixture_lease_registry) {
        let transport = match bullet_application::lease_transport::KernelLeaseTransport::generate()
        {
            Ok(transport) => std::sync::Arc::new(transport),
            Err(error) => {
                eprintln!("bullet-farmd: fixture lease transport: {error}");
                return ExitCode::FAILURE;
            }
        };
        let rpc_state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = bullet_farmd::lease_transport_rpc::serve(
                socket,
                rpc_state,
                transport,
                std::sync::Arc::new(registry),
            )
            .await
            {
                tracing::error!("fixture lease-transport socket: {error}");
            }
        });
        tracing::warn!("debug-only fixture lease peer registration enabled");
    }
    tracing::info!("bullet-farmd listening on {bound}");
    // Reclaiming an expired writer lease is the running daemon's own job, not
    // an operator's: without this tick a Variant whose runner died is freed
    // only when some successor happens to try to acquire it.
    let _tick = reaper::spawn(state.clone(), args.reap_interval_ms);
    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("bullet-farmd: serve: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(unix)]
fn read_worker_token(path: &std::path::Path) -> Result<String, String> {
    read_worker_token_descriptor(open_worker_token(path)?)
}

#[cfg(unix)]
fn open_worker_token(path: &std::path::Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn read_worker_token_descriptor(file: std::fs::File) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("token descriptor must refer to a regular file".into());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("token file must not be accessible by group or other users".into());
    }
    if metadata.len() > 128 {
        return Err("token file exceeds 128 bytes".into());
    }
    let mut bytes = Vec::with_capacity(128);
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 128 {
        return Err("token file exceeds 128 bytes".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "token file must be UTF-8".to_string())?;
    let token = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if token.contains(['\r', '\n']) {
        return Err("token file must contain exactly one token".into());
    }
    Ok(token.to_string())
}

#[cfg(not(unix))]
fn read_worker_token(_path: &std::path::Path) -> Result<String, String> {
    Err(
        "worker token files are unavailable without descriptor-safe admission on this platform"
            .into(),
    )
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

#[cfg(debug_assertions)]
fn validate_lease_transport_config(
    socket: Option<&std::path::Path>,
    fixture_registration: Option<&str>,
) -> Result<Option<bullet_farmd::lease_transport_rpc::LeasePeerRegistry>, String> {
    let Some(socket) = socket else {
        return if fixture_registration.is_some() {
            Err("FIXTURE_LEASE_SOCKET_REQUIRED: fixture registration needs --lease-transport-socket".into())
        } else {
            Ok(None)
        };
    };
    let Some(registration) = fixture_registration else {
        return Err("LEASE_PEER_REGISTRY_UNAVAILABLE: durable runner UID registration and pinned farmd identity are not configured".into());
    };
    let (runner, epoch) = registration.rsplit_once(':').ok_or_else(|| {
        "FIXTURE_LEASE_PEER_INVALID: expected <run_<32hex>:<nonzero-epoch>>".to_string()
    })?;
    let runner_id = bullet_domain::RunnerId::parse(runner)
        .map_err(|error| format!("FIXTURE_LEASE_PEER_INVALID: {error}"))?;
    let runner_epoch = epoch
        .parse::<u64>()
        .map_err(|_| "FIXTURE_LEASE_PEER_INVALID: epoch must be an integer".to_string())?;
    if runner_epoch == 0 {
        return Err("FIXTURE_LEASE_PEER_INVALID: epoch must be nonzero".into());
    }
    use std::os::unix::fs::MetadataExt;
    let process = std::fs::metadata("/proc/self")
        .map_err(|error| format!("FIXTURE_LEASE_PEER_IDENTITY_UNAVAILABLE: {error}"))?;
    let registry = bullet_farmd::lease_transport_rpc::LeasePeerRegistry::new(
        process.uid(),
        process.gid(),
        [
            bullet_farmd::lease_transport_rpc::RegisteredRunnerPeer::new(
                runner_id,
                runner_epoch,
                process.uid(),
            ),
        ],
    )
    .map_err(|error| format!("FIXTURE_LEASE_PEER_INVALID: {error}"))?;
    registry
        .preflight_socket_path(socket)
        .map_err(|error| format!("FIXTURE_LEASE_SOCKET_INVALID: {error}"))?;
    Ok(Some(registry))
}

#[cfg(not(debug_assertions))]
fn validate_lease_transport_config(socket: Option<&std::path::Path>) -> Result<(), String> {
    if socket.is_none() {
        Ok(())
    } else {
        Err("LEASE_PEER_REGISTRY_UNAVAILABLE: durable runner UID registration and pinned farmd identity are not configured".into())
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

    #[test]
    fn lease_socket_refuses_before_startup_without_registered_peer_configuration() {
        use std::os::unix::fs::PermissionsExt;

        assert!(validate_lease_transport_config(None, None)
            .expect("disabled transport")
            .is_none());
        let error = validate_lease_transport_config(
            Some(std::path::Path::new("/run/bullet/lease.sock")),
            None,
        )
        .expect_err("unregistered product transport must refuse");
        assert!(error.starts_with("LEASE_PEER_REGISTRY_UNAVAILABLE:"));

        let root = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o710))
            .expect("0710 fixture directory");
        let socket = root.path().join("lease.sock");
        let runner = bullet_domain::RunnerId::from_seed("fixture-runner");
        let registration = format!("{}:7", runner.as_str());
        assert!(
            validate_lease_transport_config(Some(&socket), Some(&registration))
                .expect("exact debug fixture")
                .is_some()
        );
        assert!(!socket.exists(), "preflight must not create the socket");
        let relative = std::path::Path::new("relative-fixture-lease.sock");
        assert!(validate_lease_transport_config(Some(relative), Some(&registration)).is_err());
        assert!(
            !relative.exists(),
            "relative refusal must not create a socket"
        );
        let missing = root.path().join("missing").join("lease.sock");
        assert!(validate_lease_transport_config(Some(&missing), Some(&registration)).is_err());
        assert!(
            !missing.exists(),
            "missing-parent refusal must not create a socket"
        );
        assert!(validate_lease_transport_config(Some(&socket), Some("bad:0")).is_err());
        assert!(validate_lease_transport_config(None, Some(&registration)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn worker_token_file_is_regular_private_and_single_line() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("worker.token");
        let token = "wrk_2222222222222222222222222222222222222222222222222222222222222222";
        std::fs::write(&path, format!("{token}\n")).expect("write token");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private mode");
        assert_eq!(read_worker_token(&path).expect("read"), token);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("group mode");
        assert!(read_worker_token(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private mode");
        std::fs::write(&path, format!("{token}\n{token}\n")).expect("multiline");
        assert!(read_worker_token(&path).is_err());
        std::fs::write(&path, "x".repeat(129)).expect("oversize");
        assert!(read_worker_token(&path).is_err());

        let target = directory.path().join("target.token");
        std::fs::write(&target, token).expect("target");
        let link = directory.path().join("link.token");
        symlink(&target, &link).expect("symlink");
        assert!(read_worker_token(&link).is_err());

        std::fs::write(&path, format!("{token}\n")).expect("restore admitted token");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private mode");
        let opened = open_worker_token(&path).expect("open admitted descriptor");
        let original = directory.path().join("original.token");
        std::fs::rename(&path, &original).expect("replace pathname");
        let attacker = "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        std::fs::write(&path, attacker).expect("replacement token");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement private mode");
        assert_eq!(
            read_worker_token_descriptor(opened).expect("read admitted descriptor"),
            token
        );
        assert_eq!(
            read_worker_token(&path).expect("read replacement"),
            attacker
        );
    }
}
