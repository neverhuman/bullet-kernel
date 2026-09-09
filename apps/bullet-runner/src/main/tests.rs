use super::{
    adapter_for, admit_candidate_authority, admit_signed_lease_client, lease_transport_refusal,
    parse_runner_id, parse_work_package_id, run, run_admitted, Args,
};
use bullet_domain::{AttemptId, RunnerId, WorkPackageId, REPOSITORY_GATE_ID};
use bullet_harness_core::CandidatePreparationSigningKey;
use clap::{error::ErrorKind, Parser};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn args(root: &Path, runner_id: &RunnerId, key: &Path) -> Args {
    Args {
        farmd: "http://127.0.0.1:9".into(),
        lease_socket: Some(root.join("lease.sock")),
        farmd_uid: Some(1),
        socket_gid: Some(1),
        lease_recovery: Some(root.join("recovery.json")),
        candidate_request_digest: "a".repeat(64),
        candidate_verification_key: key.into(),
        runner_id: runner_id.to_string(),
        work_package_id: WorkPackageId::from_seed("admitted-package").to_string(),
        runner_epoch: 1,
        provider: "sim".into(),
        model: None,
        dogfood_data_dir: None,
        dogfood_policy: None,
        dogfood_binding: None,
        dogfood_enrollment: None,
        dogfood_issuer: None,
        dogfood_key_id: None,
        dogfood_executable: None,
        dogfood_credentials: Vec::new(),
        dogfood_receipt: None,
        dogfood_max_budget_usd: None,
        dogfood_wall_timeout_secs: None,
        workspace_root: root.join("must-not-create-workspace"),
        source_repo: root.join("missing-source"),
        base_sha: "a".repeat(40),
        preservation_destination: root.join("preserved-candidate"),
        objective: "must not dispatch".into(),
        gate_ids: vec![REPOSITORY_GATE_ID.into()],
        scope: vec!["src".into()],
        data_dir: root.join("must-not-create-journal"),
        idempotency_key: "pre-acquired-attempt".into(),
        ttl_seconds: 15,
    }
}

fn write_candidate_key(root: &Path) -> PathBuf {
    let signer =
        CandidatePreparationSigningKey::generate("kernel-local", "candidate-preparation-1")
            .expect("test key");
    let key = root.join("candidate-public.json");
    std::fs::write(
        &key,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "v1alpha1",
            "issuer": "kernel-local",
            "key_id": "candidate-preparation-1",
            "public_key_hex": signer.public_key_hex(),
        }))
        .expect("key JSON"),
    )
    .expect("write key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("key mode");
    key
}

fn required_cli(
    runner_id: &RunnerId,
    key: &Path,
    work_package_id: Option<&str>,
    idempotency_key: Option<&str>,
) -> Vec<String> {
    let mut argv = vec![
        "bullet-runner".into(),
        "--candidate-request-digest".into(),
        "a".repeat(64),
        "--candidate-verification-key".into(),
        key.display().to_string(),
        "--runner-id".into(),
        runner_id.to_string(),
        "--workspace-root".into(),
        "/tmp/bullet-runner-cli-workspace".into(),
        "--source-repo".into(),
        "/tmp/bullet-runner-cli-source".into(),
        "--base-sha".into(),
        "a".repeat(40),
        "--preservation-destination".into(),
        "/tmp/bullet-runner-cli-preserved".into(),
        "--objective".into(),
        "exact selection".into(),
        "--gate-id".into(),
        REPOSITORY_GATE_ID.into(),
        "--scope".into(),
        "src".into(),
    ];
    if let Some(value) = work_package_id {
        argv.extend(["--work-package-id".into(), value.into()]);
    }
    if let Some(value) = idempotency_key {
        argv.extend(["--idempotency-key".into(), value.into()]);
    }
    argv
}

#[test]
fn outcome_json_contains_one_strict_candidate_preservation_binding() {
    use bullet_runner_core::{
        AttemptOutcome, CandidatePreservation, CandidateReceipt, PreservationReceipt,
    };

    let temp = tempfile::tempdir().expect("private preservation fixture");
    let destination = temp.path().join("preserved");
    std::fs::create_dir(&destination).expect("preserved destination");
    let attempt_id = AttemptId::from_seed("outcome-preservation");
    let candidate = CandidateReceipt {
        id: format!("can_{}", "1".repeat(64)),
        content_id: format!("cnt_{}", "2".repeat(64)),
        base_commit: format!("sha1:{}", "3".repeat(40)),
        head_commit: format!("sha1:{}", "4".repeat(40)),
        tree_hash: format!("sha1:{}", "5".repeat(40)),
        patch_hash: "6".repeat(64),
        actual_scope: vec!["PONG.txt".into()],
        prepared_at: "2026-08-28T00:00:00Z".into(),
    };
    let preservation = CandidatePreservation {
        candidate_id: candidate.id.clone(),
        base_commit: candidate.base_commit.clone(),
        head_commit: candidate.head_commit.clone(),
        tree_hash: candidate.tree_hash.clone(),
        patch_hash: candidate.patch_hash.clone(),
        attempt_id: attempt_id.clone(),
        fence: 7,
        receipt: PreservationReceipt {
            token: "sealed-receipt".into(),
            digest: "7".repeat(64),
            artifact_digest: "8".repeat(64),
            destination,
        },
    };
    let value = super::outcome_json(&AttemptOutcome {
        attempt_id: attempt_id.clone(),
        fence: 7,
        candidate: candidate.clone(),
        preservation,
        repair_rounds: 0,
        gates: Vec::new(),
    });
    assert_eq!(value.as_object().map(serde_json::Map::len), Some(7));
    let parsed: CandidatePreservation =
        serde_json::from_value(value["preservation"].clone()).expect("strict preservation");
    parsed
        .validate_against(&candidate, &attempt_id, 7)
        .expect("exact outcome binding");
    let mut substituted = parsed;
    substituted.candidate_id = format!("can_{}", "9".repeat(64));
    assert!(substituted
        .validate_against(&candidate, &attempt_id, 7)
        .is_err());
    let mut hostile = value["preservation"].clone();
    hostile["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CandidatePreservation>(hostile).is_err());
    let mut nested = value["preservation"].clone();
    nested["receipt"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CandidatePreservation>(nested).is_err());
    let mut candidate_hostile = value["candidate"].clone();
    candidate_hostile["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CandidateReceipt>(candidate_hostile).is_err());
}

async fn read_json(stream: &mut tokio::net::UnixStream) -> serde_json::Value {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.expect("read request");
        if byte[0] == b'\n' {
            return serde_json::from_slice(&bytes).expect("request JSON");
        }
        bytes.push(byte[0]);
        assert!(bytes.len() < 65_536, "request must remain bounded");
    }
}

async fn write_json(stream: &mut tokio::net::UnixStream, value: serde_json::Value) {
    let mut bytes = serde_json::to_vec(&value).expect("response JSON");
    bytes.push(b'\n');
    stream.write_all(&bytes).await.expect("write response");
}

async fn assert_exact_acquire(
    listener: tokio::net::UnixListener,
    socket: PathBuf,
    package: WorkPackageId,
    runner: RunnerId,
) {
    let metadata = std::fs::metadata(socket).expect("socket metadata");
    let (mut stream, _) = listener.accept().await.expect("accept Runner");
    let hello = read_json(&mut stream).await;
    assert_eq!(hello["proto"], "bullet-farm.lease-transport.rpc.v1");
    write_json(
        &mut stream,
        serde_json::json!({
            "ok": true,
            "proto": "bullet-farm.lease-transport.rpc.v1",
            "peer_uid": metadata.uid(),
            "peer_gid": metadata.gid(),
            "peer_pid": std::process::id(),
            "socket_dev": metadata.dev(),
            "socket_ino": metadata.ino(),
            "listener_dev": metadata.dev(),
            "listener_ino": metadata.ino(),
        }),
    )
    .await;
    let request = read_json(&mut stream).await;
    assert_eq!(request["method"], "acquire", "next_ready must never run");
    assert_eq!(request["params"]["work_package_id"], package.as_str());
    assert_eq!(request["params"]["runner_id"], runner.as_str());
    assert_eq!(request["params"]["runner_epoch"], 1);
    assert_eq!(request["params"]["idempotency_key"], "pre-acquired-attempt");
    assert_eq!(
        request["params"].as_object().map(|value| value.len()),
        Some(5)
    );
    write_json(
        &mut stream,
        serde_json::json!({
            "id": 1,
            "error": {"code": "TEST_STOP", "message": "stop after exact acquire"}
        }),
    )
    .await;
}

#[tokio::test]
async fn runner_identity_and_candidate_key_are_required_before_dispatch() {
    let expected = RunnerId::from_seed("admitted-runner");
    assert_eq!(parse_runner_id(expected.as_str()).unwrap(), expected);
    for invalid in ["", "admitted-runner", "run_short", "run_not-hex"] {
        assert!(parse_runner_id(invalid).is_err(), "{invalid:?} must refuse");
    }
    let package = WorkPackageId::from_seed("admitted-package");
    assert_eq!(parse_work_package_id(package.as_str()).unwrap(), package);
    for invalid in ["", "admitted-package", "wpk_short", "wpk_not-hex"] {
        assert!(
            parse_work_package_id(invalid).is_err(),
            "{invalid:?} must refuse"
        );
    }

    let parser_key = Path::new("/tmp/candidate-public.json");
    for argv in [
        required_cli(&expected, parser_key, None, Some("pre-acquired-attempt")),
        required_cli(&expected, parser_key, Some(package.as_str()), None),
    ] {
        let error = match Args::try_parse_from(argv) {
            Err(error) => error,
            Ok(_) => panic!("missing exact replay subject must refuse"),
        };
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    let (code, message) = lease_transport_refusal();
    assert_eq!(code, "LEASE_TRANSPORT_ADMISSION_UNAVAILABLE");
    assert!(message.contains("authenticated"));
    assert!(message.contains("descriptor-bound"));
    assert!(message.contains("durable"));

    let root = std::env::temp_dir().join(format!(
        "bullet-runner-refusal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    assert!(!root.exists(), "test subject must begin absent");
    let missing_key = root.join("missing-candidate-public.json");
    let mut malformed_package = args(&root, &expected, &missing_key);
    malformed_package.work_package_id = "wpk_not-hex".into();
    assert_eq!(run(malformed_package).await, ExitCode::from(2));
    assert!(
        !root.exists(),
        "malformed work package must refuse before key or transport access"
    );
    let status = run(args(&root, &expected, &missing_key)).await;
    assert_eq!(status, ExitCode::from(2));
    assert!(!root.exists(), "missing key refusal must be inert");

    std::fs::create_dir_all(&root).expect("admission subject dir");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private admission subject dir");
    let key = write_candidate_key(&root);
    let workspace = root.join("must-not-create-workspace");
    let journal = root.join("must-not-create-journal");

    let mut relative = args(&root, &expected, &key);
    relative.lease_socket = Some(PathBuf::from("relative/lease.sock"));
    assert_eq!(run(relative).await, ExitCode::from(2));
    assert!(!workspace.exists(), "relative socket must remain inert");

    let mut unregistered = args(&root, &expected, &key);
    unregistered.farmd_uid = None;
    unregistered.socket_gid = None;
    unregistered.lease_recovery = None;
    assert_eq!(run(unregistered).await, ExitCode::from(2));
    assert!(!workspace.exists(), "unregistered socket must remain inert");
    assert!(!journal.exists(), "unregistered socket must remain inert");

    let admitted = admit_signed_lease_client(&args(&root, &expected, &key));
    assert!(
        admitted.is_ok(),
        "absolute socket + UID + GID + recovery constructs only the admitted client"
    );
    assert!(!workspace.exists(), "construction must remain inert");
    assert!(!journal.exists(), "construction must remain inert");

    let exact_socket = root.join("exact-selection.sock");
    let listener = tokio::net::UnixListener::bind(&exact_socket).expect("bind exact fake");
    std::fs::set_permissions(&exact_socket, std::fs::Permissions::from_mode(0o660))
        .expect("socket mode");
    let metadata = std::fs::metadata(&exact_socket).expect("socket metadata");
    let mut selected = args(&root, &expected, &key);
    selected.lease_socket = Some(exact_socket.clone());
    selected.farmd_uid = Some(metadata.uid());
    selected.socket_gid = Some(metadata.gid());
    selected.workspace_root = root.join("exact-workspace");
    selected.data_dir = root.join("exact-journal");
    std::fs::create_dir(&selected.workspace_root).expect("exact workspace root");
    let candidate_admission = admit_candidate_authority(&selected).expect("Candidate admission");
    let client = admit_signed_lease_client(&selected).expect("signed client");
    let package = parse_work_package_id(&selected.work_package_id).expect("exact package");
    let server = tokio::spawn(assert_exact_acquire(
        listener,
        exact_socket,
        package.clone(),
        expected.clone(),
    ));
    assert_eq!(
        run_admitted(
            selected,
            client,
            std::sync::Arc::new(bullet_harness_sim::SimAdapter::new()),
            candidate_admission,
            package
        )
        .await,
        ExitCode::FAILURE
    );
    server.await.expect("exact fake task");
}

// ---------------------------------------------------------------------------
// De-sim: the runner used to accept only `--provider sim`, so the transaction
// loop only ever saw a canned proposal. These pin the replacement contract.
// ---------------------------------------------------------------------------

fn dogfood_args(root: &Path, runner_id: &RunnerId, key: &Path) -> Args {
    let mut selected = args(root, runner_id, key);
    selected.provider = "claude".into();
    selected.dogfood_data_dir = Some(root.join("dd"));
    selected.dogfood_policy = Some(root.join("policy.json"));
    selected.dogfood_binding = Some(root.join("binding.json"));
    selected.dogfood_enrollment = Some(root.join("enrollment.json"));
    selected.dogfood_issuer = Some("dogfood-local".into());
    selected.dogfood_key_id = Some("dogfood-runner-1".into());
    selected.dogfood_executable =
        Some(PathBuf::from("/usr/lib/bullet/providers/claude/bin/claude"));
    selected.dogfood_receipt = Some(root.join("receipt.json"));
    selected.dogfood_max_budget_usd = Some(0.5);
    selected.workspace_root = root.join("workspace");
    selected
}

#[test]
fn the_simulator_is_selected_only_when_it_is_named() {
    let root = tempfile::tempdir().expect("temp root");
    let runner_id = RunnerId::from_seed("provider-selection");
    let key = write_candidate_key(root.path());
    let mut selected = args(root.path(), &runner_id, &key);

    selected.provider = "sim".into();
    assert_eq!(
        adapter_for(&selected.provider, &selected)
            .expect("the simulator needs no admission")
            .descriptor()
            .provider,
        "sim"
    );

    selected.provider = "claude".into();
    // The whole point: a real provider name never yields the simulator. It
    // either yields the real adapter or it refuses.
    let refusal = adapter_for(&selected.provider, &selected)
        .err()
        .expect("claude without admission must refuse");
    assert!(
        refusal.starts_with("--dogfood-") && refusal.contains("required for a real provider"),
        "the refusal must name a missing dogfood input, got: {refusal}"
    );
    assert!(
        !refusal.contains("sim"),
        "a real provider must never mention the simulator: {refusal}"
    );

    selected.provider = "codex".into();
    let refusal = adapter_for(&selected.provider, &selected)
        .err()
        .expect("codex without a model must refuse");
    assert!(refusal.contains("--model"), "{refusal}");

    selected.model = Some("gpt-5".into());
    let adapter = adapter_for(&selected.provider, &selected).expect("codex constructs offline");
    assert_eq!(adapter.descriptor().provider, "codex");

    selected.provider = "cursor".into();
    selected.model = Some("composer-2".into());
    let adapter = adapter_for(&selected.provider, &selected).expect("cursor constructs offline");
    assert_eq!(adapter.descriptor().provider, "cursor");
}

#[test]
fn a_real_provider_yields_a_real_adapter_that_is_not_the_simulator() {
    let root = tempfile::tempdir().expect("temp root");
    let runner_id = RunnerId::from_seed("real-adapter");
    let key = write_candidate_key(root.path());
    let selected = dogfood_args(root.path(), &runner_id, &key);
    let adapter = adapter_for(&selected.provider, &selected)
        .expect("complete admission yields the real adapter");
    assert_eq!(adapter.descriptor().provider, "claude");
}

#[test]
fn every_dogfood_path_must_be_absolute() {
    let root = tempfile::tempdir().expect("temp root");
    let runner_id = RunnerId::from_seed("absolute-paths");
    let key = write_candidate_key(root.path());
    for (flag, apply) in [
        (
            "dogfood-data-dir",
            (|a: &mut Args| a.dogfood_data_dir = Some(PathBuf::from("dd"))) as fn(&mut Args),
        ),
        ("dogfood-policy", |a: &mut Args| {
            a.dogfood_policy = Some(PathBuf::from("p.json"))
        }),
        ("dogfood-binding", |a: &mut Args| {
            a.dogfood_binding = Some(PathBuf::from("b.json"))
        }),
        ("dogfood-enrollment", |a: &mut Args| {
            a.dogfood_enrollment = Some(PathBuf::from("e.json"))
        }),
        ("dogfood-executable", |a: &mut Args| {
            a.dogfood_executable = Some(PathBuf::from("claude"))
        }),
        ("dogfood-receipt", |a: &mut Args| {
            a.dogfood_receipt = Some(PathBuf::from("r.json"))
        }),
        ("workspace-root", |a: &mut Args| {
            a.workspace_root = PathBuf::from("workspace")
        }),
    ] {
        let mut selected = dogfood_args(root.path(), &runner_id, &key);
        apply(&mut selected);
        let refusal = adapter_for(&selected.provider, &selected)
            .err()
            .unwrap_or_else(|| panic!("--{flag} relative path must refuse"));
        assert!(
            refusal.contains(flag) && refusal.contains("absolute"),
            "--{flag} must be refused by name as non-absolute, got: {refusal}"
        );
    }
}

#[test]
fn a_real_turn_never_starts_without_a_stated_spend_ceiling() {
    let root = tempfile::tempdir().expect("temp root");
    let runner_id = RunnerId::from_seed("spend-ceiling");
    let key = write_candidate_key(root.path());
    for (budget, expect) in [
        (None, "is required"),
        (Some(0.0), "positive finite"),
        (Some(-1.0), "positive finite"),
        (Some(f64::NAN), "positive finite"),
        (Some(f64::INFINITY), "positive finite"),
    ] {
        let mut selected = dogfood_args(root.path(), &runner_id, &key);
        selected.dogfood_max_budget_usd = budget;
        let refusal = adapter_for(&selected.provider, &selected)
            .err()
            .unwrap_or_else(|| panic!("budget {budget:?} must refuse"));
        assert!(
            refusal.contains("dogfood-max-budget-usd") && refusal.contains(expect),
            "budget {budget:?} refusal was: {refusal}"
        );
    }
}

#[tokio::test]
async fn provider_admission_is_decided_before_any_other_admission_touches_the_host() {
    // Ordering matters: an operator who fat-fingers a dogfood flag should be
    // told that, not sent down the Candidate-grant or lease-socket path first.
    // Nothing on disk may be created by the refusal.
    let root = tempfile::tempdir().expect("temp root");
    let runner_id = RunnerId::from_seed("ordering");
    let mut selected = dogfood_args(root.path(), &runner_id, Path::new("/nonexistent/key.json"));
    selected.dogfood_policy = None;
    let workspace = selected.workspace_root.clone();
    let journal = selected.data_dir.clone();

    assert_eq!(run(selected).await, ExitCode::from(2));
    assert!(
        !workspace.exists(),
        "a refused run must create no workspace"
    );
    assert!(!journal.exists(), "a refused run must create no journal");
}
