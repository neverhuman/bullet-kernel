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
    if let Some(launch) = lease_launch {
        let fixture = launch.fixture;
        let key_bytes = launch.key_bytes;
        let candidate_key = launch.candidate_key;
        let rpc_state = state.clone();
        tokio::spawn(async move {
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
            if let Err(error) = result {
                tracing::error!("lease-transport socket: {error}");
            }
        });
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
    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("bullet-farmd: serve: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_transport_key_provisioning_is_exclusive_create_only_and_valid() {
        use bullet_harness_core::lease_transport::LeaseTransportSigningKey;
        use clap::Parser as _;
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private custody root");
        let key = root.path().join("lease-transport.key");
        assert!(Args::try_parse_from([
            "bullet-farmd",
            "--provision-lease-transport-key",
            key.to_str().expect("UTF-8 fixture path"),
        ])
        .is_ok());
        assert!(Args::try_parse_from([
            "bullet-farmd",
            "--provision-lease-transport-key",
            key.to_str().expect("UTF-8 fixture path"),
            "--bind",
            "127.0.0.1:0",
        ])
        .is_err());

        provision_lease_transport_key(&key).expect("create exact key");
        let metadata = std::fs::symlink_metadata(&key).expect("key metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let bytes = std::fs::read(&key).expect("key bytes");
        assert_eq!(bytes.len(), 64);
        LeaseTransportSigningKey::from_bytes("kernel-local", "lease-1", &bytes)
            .expect("provisioned key is cryptographically valid");
        let before = bytes;
        assert!(provision_lease_transport_key(&key).is_err());
        assert_eq!(std::fs::read(&key).expect("unchanged key"), before);
        assert!(!root.path().join("ledger.sqlite").exists());

        let relative = PathBuf::from("relative-lease-transport.key");
        assert!(provision_lease_transport_key(&relative).is_err());
        assert!(!relative.exists());
        let unsafe_parent = root.path().join("unsafe-parent");
        std::fs::create_dir(&unsafe_parent).expect("unsafe parent");
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o755))
            .expect("unsafe parent mode");
        let unsafe_key = unsafe_parent.join("lease-transport.key");
        assert!(provision_lease_transport_key(&unsafe_key).is_err());
        assert!(!unsafe_key.exists());
        assert_eq!(
            std::fs::symlink_metadata(&unsafe_parent)
                .expect("unsafe parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "refusal must not chmod an existing unsafe parent",
        );
    }

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

        assert!(admit_lease_transport(None, None, None, None)
            .expect("disabled transport")
            .is_none());
        let error = match admit_lease_transport(
            Some(std::path::PathBuf::from("/run/bullet/lease.sock")),
            None,
            None,
            None,
        ) {
            Ok(_) => panic!("unregistered product transport must refuse"),
            Err(error) => error,
        };
        assert!(error.starts_with("LEASE_PEER_REGISTRY_UNAVAILABLE:"));

        let root = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o710))
            .expect("0710 fixture directory");
        let socket = root.path().join("lease.sock");
        let runner = bullet_domain::RunnerId::from_seed("fixture-runner");
        let registration = format!("{}:7", runner.as_str());
        let fixture = admit_lease_transport(Some(socket.clone()), None, None, Some(&registration))
            .expect("exact debug fixture")
            .expect("fixture launch");
        assert!(fixture.fixture);
        assert!(fixture.candidate_key.is_none());
        assert!(!socket.exists(), "preflight must not create the socket");
        let relative = std::path::PathBuf::from("relative-fixture-lease.sock");
        assert!(
            admit_lease_transport(Some(relative.clone()), None, None, Some(&registration)).is_err()
        );
        assert!(
            !relative.exists(),
            "relative refusal must not create a socket"
        );
        let missing = root.path().join("missing").join("lease.sock");
        assert!(
            admit_lease_transport(Some(missing.clone()), None, None, Some(&registration)).is_err()
        );
        assert!(
            !missing.exists(),
            "missing-parent refusal must not create a socket"
        );
        assert!(admit_lease_transport(Some(socket.clone()), None, None, Some("bad:0")).is_err());
        assert!(admit_lease_transport(None, None, None, Some(&registration)).is_err());

        let custody = root.path().join("custody");
        std::fs::create_dir_all(&custody).expect("custody");
        std::fs::set_permissions(&custody, std::fs::Permissions::from_mode(0o700)).expect("0700");
        let key = custody.join("signing.key");
        let registry = custody.join("peer-registry.json");
        bullet_farmd::lease_transport_custody::write_new_signing_key(&key).expect("key");
        let process = std::fs::metadata("/proc/self").expect("self");
        use std::os::unix::fs::MetadataExt;
        bullet_farmd::lease_transport_custody::write_peer_registry(
            &registry,
            &bullet_farmd::lease_transport_custody::DurablePeerRegistryFile {
                farmd_uid: process.uid(),
                socket_gid: process.gid(),
                runners: vec![
                    bullet_farmd::lease_transport_custody::DurableRegisteredRunner {
                        runner_id: runner.to_string(),
                        runner_epoch: 7,
                        service_uid: process.uid(),
                    },
                ],
            },
        )
        .expect("registry");
        let durable =
            admit_lease_transport(Some(socket.clone()), Some(&registry), Some(&key), None)
                .expect("durable local admission");
        let durable = durable.expect("launch");
        assert!(!durable.fixture);
        assert!(durable.candidate_key.is_some());
        assert!(
            !socket.exists(),
            "durable preflight must not create the socket"
        );
        assert!(admit_lease_transport(
            Some(socket),
            Some(&registry),
            Some(&key),
            Some(&registration)
        )
        .is_err());
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
