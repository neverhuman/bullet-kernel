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
