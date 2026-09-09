use super::super::recovery::MAX_INTENTS;
use super::super::*;
use bullet_application::lease_transport::SignedAcquireBody;
use bullet_domain::WorkPackageId;
use bullet_harness_core::launch_grant::canonical_json;
use std::os::unix::fs::{symlink, PermissionsExt};

fn body(runner: &RunnerId, ttl_seconds: i64) -> SignedAcquireBody {
    SignedAcquireBody {
        work_package_id: WorkPackageId::from_seed("recovery-package"),
        runner_id: runner.clone(),
        runner_epoch: 7,
        idempotency_key: "recovery-intent".into(),
        ttl_seconds,
    }
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[test]
fn canonical_intent_survives_restart_and_preserves_original_ttl() {
    let root = private_root();
    let path = root.path().join("recovery.json");
    let runner = RunnerId::from_seed("recovery-runner");
    let mut journal = RecoveryJournal::new(runner.clone(), 7);
    assert!(journal.reserve(body(&runner, 7)).unwrap());
    persist_recovery(&path, &journal).unwrap();
    let loaded = load_recovery(&path, &runner, 7).unwrap();
    let attempt = AttemptId::from_seed("recovery-intent");
    let meta = loaded.intent_for(&attempt).expect("durable intent");
    assert_eq!(meta.body.ttl_seconds, 7);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes, canonical_json(&loaded).unwrap());
}

#[test]
fn malformed_foreign_noncanonical_and_unsafe_custody_refuse() {
    let root = private_root();
    let path = root.path().join("recovery.json");
    let runner = RunnerId::from_seed("recovery-runner");
    let mut journal = RecoveryJournal::new(runner.clone(), 7);
    journal.reserve(body(&runner, 7)).unwrap();
    persist_recovery(&path, &journal).unwrap();

    let foreign = RunnerId::from_seed("foreign-runner");
    assert!(load_recovery(&path, &foreign, 7).is_err());
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["schema_version"] = serde_json::json!("lease-recovery.v1alpha1");
    std::fs::write(&path, canonical_json(&value).unwrap()).unwrap();
    let version = match load_recovery(&path, &runner, 7) {
        Ok(_) => panic!("legacy recovery schema must refuse"),
        Err(error) => error,
    };
    assert!(matches!(
        version,
        RunnerError::Lease { ref code, .. } if code == "LEASE_RECOVERY_VERSION_UNSUPPORTED"
    ));

    persist_recovery(&path, &journal).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["unknown"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_recovery(&path, &runner, 7).is_err());

    std::fs::remove_file(&path).unwrap();
    symlink(root.path().join("missing"), &path).unwrap();
    assert!(load_recovery(&path, &runner, 7).is_err());
    std::fs::remove_file(&path).unwrap();
    persist_recovery(&path, &journal).unwrap();
    let alias = root.path().join("alias.json");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(load_recovery(&path, &runner, 7).is_err());
}

#[test]
fn body_drift_capacity_and_persistence_failure_refuse_before_network() {
    let root = private_root();
    let path = root.path().join("recovery.json");
    let runner = RunnerId::from_seed("recovery-runner");
    let socket = root.path().join("never-created.sock");
    let mut journal = RecoveryJournal::new(runner.clone(), 7);
    assert!(journal.reserve(body(&runner, 7)).unwrap());
    assert!(!journal.reserve(body(&runner, 7)).unwrap());
    assert!(journal.reserve(body(&runner, 15)).is_err());

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let client =
        SignedLeaseRpcClient::new_admitted(&socket, runner, 7, ExpectedLeaseServer::new(0, 0));
    assert!(client.with_recovery_file(&path).is_err());
    assert!(
        !socket.exists(),
        "custody refusal must precede socket access"
    );
}

#[test]
fn oversized_publication_preserves_the_prior_loadable_record() {
    let root = private_root();
    let path = root.path().join("recovery.json");
    let runner = RunnerId::from_seed("recovery-runner");
    let mut original = RecoveryJournal::new(runner.clone(), 7);
    original.reserve(body(&runner, 7)).unwrap();
    persist_recovery(&path, &original).unwrap();
    let original_bytes = std::fs::read(&path).unwrap();

    let mut oversized = RecoveryJournal::new(runner.clone(), 7);
    for index in 0..MAX_INTENTS {
        let mut candidate = body(&runner, 7);
        candidate.idempotency_key = format!("{index:03}-{}", "x".repeat(240));
        assert!(oversized.reserve(candidate).unwrap());
    }
    let error = persist_recovery(&path, &oversized).unwrap_err();
    assert!(
        matches!(error, RunnerError::Lease { ref code, .. } if code == "LEASE_RECOVERY_CAPACITY")
    );
    assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
    assert!(load_recovery(&path, &runner, 7).is_ok());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}
