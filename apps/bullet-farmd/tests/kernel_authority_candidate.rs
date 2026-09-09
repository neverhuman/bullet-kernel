use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    execution_toolchain_digest, CandidatePreparationIssuer, CandidatePreparationSigningKey,
    CandidatePreparationSource, CandidatePreparationStore, ExecutionEnvelopeV1, ExecutionToolV1,
    LedgerCandidatePreparationIssuer,
};
use bullet_application::{materialize_plan, LeaseService, Ledger, PlanInput};
use bullet_domain::{Attempt, Digest, TaskClass};
use bullet_farmd::{api, kernel_authority::KernelAuthority, kernel_authority_rpc};
use bullet_harness_core::{
    candidate_preparation_scope_paths_digest, CandidatePreparationGrantV1,
    SignedCandidatePreparationGrantV1,
};
use chrono::Utc;
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const PROTO: &str = "bullet-farm.kernel-authority.rpc.v1";
const OPERATION: &str = "prepare-candidate";
const FINGERPRINT_DOMAIN: &[u8] = b"bullet-gitd.pre-contract-request-fingerprint.v1";
const WAIT: Duration = Duration::from_secs(4);

struct Fixture {
    _root: tempfile::TempDir,
    db: PathBuf,
    key_bytes: Vec<u8>,
    authority: Value,
    params: Value,
    loss_params: Value,
    absent_params: Value,
    uid: u32,
}

impl Fixture {
    fn new() -> Self {
        let mut builder = tempfile::Builder::new();
        builder.permissions(std::fs::Permissions::from_mode(0o700));
        let root = builder.tempdir().expect("private root");
        let key_path = root.path().join("authority.key");
        bullet_farmd::lease_transport_custody::write_new_signing_key(&key_path)
            .expect("service key");
        let key_bytes = std::fs::read(&key_path).expect("read service key");
        let candidate_key = CandidatePreparationSigningKey::from_bytes(
            "kernel-local",
            "candidate-preparation-1",
            &key_bytes,
        )
        .expect("Candidate key");
        let db = root.path().join("ledger.sqlite3");
        drop(SqliteLedger::open(&db).expect("migrate"));
        let granted_scope = vec!["src".to_owned()];
        let scope_digest =
            candidate_preparation_scope_paths_digest(&granted_scope).expect("scope paths digest");
        rusqlite::Connection::open(&db)
            .expect("scope authority connection")
            .execute(
                "UPDATE authority_revisions
                 SET scope_digest = ?1, authority_epoch = 2
                 WHERE singleton = 1",
                [scope_digest],
            )
            .expect("provision scope authority");
        let mut ledger = SqliteLedger::open(&db).expect("open");
        let graph = materialize_plan(
            &mut ledger,
            "kernel-final-check",
            &PlanInput {
                title: "Kernel final check".into(),
                objective: "consume exact durable Candidate grant".into(),
                packages: vec![("prepare".into(), TaskClass::BoundedBugFix)],
            },
            &LeaseService::rfc3339(Utc::now()),
        )
        .expect("plan");
        let (attempt, authority, _) =
            LeaseService::acquire(&mut ledger, &graph, 0, "kernel-final-check", 15).expect("lease");
        let registered = ledger
            .register_candidate_preparation_source(&source(&attempt, '1'))
            .expect("source");
        let issued = LedgerCandidatePreparationIssuer::new(&mut ledger, &candidate_key)
            .mint(&registered.request_digest)
            .expect("grant");
        let loss_source = ledger
            .register_candidate_preparation_source(&source(&attempt, '2'))
            .expect("loss source");
        let loss_grant = LedgerCandidatePreparationIssuer::new(&mut ledger, &candidate_key)
            .mint(&loss_source.request_digest)
            .expect("loss grant");
        let mut absent_claims = issued.grant.clone();
        absent_claims.request_digest = "f".repeat(64);
        let absent = candidate_key.sign(&absent_claims).expect("absent grant");
        let params = candidate_params(&issued.grant, &issued.signed, &authority, &granted_scope);
        let loss_params = candidate_params(
            &loss_grant.grant,
            &loss_grant.signed,
            &authority,
            &granted_scope,
        );
        let absent_params = candidate_params(&absent_claims, &absent, &authority, &granted_scope);
        drop(ledger);
        Self {
            _root: root,
            db,
            key_bytes,
            authority: serde_json::to_value(authority).expect("authority JSON"),
            params,
            loss_params,
            absent_params,
            uid: std::fs::metadata("/proc/self").expect("self").uid(),
        }
    }

    async fn start(&self, name: &str) -> Server {
        let socket = self._root.path().join(format!("{name}.sock"));
        let (_, state) =
            api::daemon(&self.db, None, "http://127.0.0.1:7420".into(), None).expect("state");
        let authority = Arc::new(
            KernelAuthority::from_secret_bytes(&self.key_bytes).expect("Kernel authority"),
        );
        let path = socket.clone();
        let uid = self.uid;
        let task =
            tokio::spawn(
                async move { kernel_authority_rpc::serve(path, state, authority, uid).await },
            );
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(socket.exists() && !task.is_finished(), "socket never bound");
        Server {
            socket,
            task: Some(task),
        }
    }
}

fn candidate_params(
    claims: &CandidatePreparationGrantV1,
    signed: &SignedCandidatePreparationGrantV1,
    authority: &bullet_domain::AuthorityToken,
    granted_scope: &[String],
) -> Value {
    json!({
        "change": {
            "id": claims.change_id,
            "mission": claims.mission_id,
            "acceptance_root": authority.acceptance_contract_id.as_str()
                .strip_prefix("acc_").expect("acceptance prefix"),
        },
        "provenance": {
            "schema_version": 1,
            "repository_id": claims.repository_id,
            "producing_attempt_id": claims.attempt_id,
            "attempt_fence": claims.attempt_fence,
            "work_package_id": claims.work_package_id,
            "variant_id": claims.variant_id,
            "plan_revision_id": claims.plan_revision_id,
            "graph_revision_id": claims.graph_revision_id,
            "base_checkpoint_id": id("chk", '1'),
            "base_commit": format!("sha1:{}", "1".repeat(40)),
            "parent_candidate_ids": claims.parent_candidate_ids,
            "granted_scope": granted_scope,
            "context_capsule_id": claims.context_capsule_id,
            "configuration_snapshot_id": format!("cnt_{}", authority.config_snapshot_hash.to_hex()),
            "policy_snapshot_id": format!("cnt_{}", authority.policy_snapshot_hash.to_hex()),
            "routing_snapshot_id": format!("cnt_{}", authority.routing_policy_hash.to_hex()),
            "environment_digest": claims.environment_digest,
            "toolchain_digest": claims.toolchain_digest,
        },
        "candidate_preparation_grant": signed,
    })
}

struct Server {
    socket: PathBuf,
    task: Option<JoinHandle<Result<(), std::io::Error>>>,
}

impl Server {
    async fn stop(mut self) {
        let task = self.task.take().expect("server task");
        task.abort();
        let _ = task.await;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn source(attempt: &Attempt, suffix: char) -> CandidatePreparationSource {
    let tools = vec![ExecutionToolV1 {
        schema_version: "v1alpha1".into(),
        tool_id: id("etl", suffix),
        role: "git".into(),
        executable_path: "/usr/bin/git".into(),
        executable_digest: "a".repeat(64),
        descriptor_digest: "b".repeat(64),
        version: "2.45.2".into(),
    }];
    let now = unix_ms();
    CandidatePreparationSource {
        schema_version: "v1alpha1".into(),
        attempt_id: attempt.id.clone(),
        root_change: true,
        change_id: id("chg", suffix),
        parent_candidate_ids: vec![],
        execution_envelope: ExecutionEnvelopeV1 {
            schema_version: "v1alpha1".into(),
            execution_envelope_id: id("exe", suffix),
            issuer: "bullet-kernel".into(),
            key_id: "execution-1".into(),
            signing_purpose: "execution-envelope-signing".into(),
            claims_domain: "execution.envelope.v1alpha1".into(),
            runner_id: attempt.runner_id.to_string(),
            runner_epoch: attempt.runner_epoch,
            provider: "simulator".into(),
            model: "deterministic".into(),
            adapter: "simulator-v1".into(),
            provider_profile_id: id("prf", suffix),
            platform: "linux-x86_64".into(),
            containment_profile_id: id("ctp", suffix),
            environment_digest: "c".repeat(64),
            toolchain_digest: execution_toolchain_digest(&tools).expect("tool digest"),
            sandbox_image_digest: "d".repeat(64),
            tools,
            authority_epoch: 2,
            freeze_generation: 0,
            issued_at_unix_ms: now.saturating_sub(1_000),
            expires_at_unix_ms: now + 14_000,
        },
        ttl_ms: 5_000,
    }
}

async fn final_check(server: &Server, fixture: &Fixture, params: &Value) -> Value {
    final_check_with_authority(server, &fixture.authority, params).await
}

async fn final_check_with_authority(server: &Server, authority: &Value, params: &Value) -> Value {
    let params = check_params_with_authority(server, authority, params).await;
    rpc(&server.socket, "check", params).await
}

async fn check_params(server: &Server, fixture: &Fixture, params: &Value) -> Value {
    check_params_with_authority(server, &fixture.authority, params).await
}

async fn check_params_with_authority(server: &Server, authority: &Value, params: &Value) -> Value {
    let mint = rpc(
        &server.socket,
        "mint",
        json!({"operation": OPERATION, "authority": authority, "params": params}),
    )
    .await;
    assert!(mint["error"].is_null(), "{mint}");
    let permit = mint["result"]["kernel_permit"].clone();
    let fingerprint = request_fingerprint(authority, params);
    json!({
        "operation": OPERATION,
        "authority": authority,
        "params": params,
        "kernel_permit": permit,
        "transport_fingerprint": fingerprint,
    })
}

async fn drop_check_response(server: &Server, fixture: &Fixture, params: &Value) {
    let params = check_params(server, fixture, params).await;
    let mut stream = UnixStream::connect(&server.socket).await.expect("connect");
    let mut request = serde_json::to_vec(&json!({
        "proto": PROTO,
        "id": 1,
        "method": "check",
        "params": params,
        "now_unix_ms": unix_ms(),
    }))
    .expect("request");
    request.push(b'\n');
    stream.write_all(&request).await.expect("write");
    drop(stream);
}

async fn rpc(socket: &Path, method: &str, params: Value) -> Value {
    let mut stream = UnixStream::connect(socket).await.expect("connect");
    let mut request = serde_json::to_vec(&json!({
        "proto": PROTO,
        "id": 1,
        "method": method,
        "params": params,
        "now_unix_ms": unix_ms(),
    }))
    .expect("request");
    request.push(b'\n');
    stream.write_all(&request).await.expect("write");
    let reply = read_frame(&mut stream).await;
    assert_eq!(reply["proto"], PROTO, "response protocol drift: {reply}");
    assert_eq!(reply["id"], 1, "response request ID drift: {reply}");
    let object = reply.as_object().expect("response object");
    assert_eq!(
        object.contains_key("result"),
        !object.contains_key("error"),
        "response must contain exactly one of result or error: {reply}",
    );
    assert_eq!(object.len(), 3, "response envelope must be closed: {reply}");
    reply
}

async fn read_frame(stream: &mut UnixStream) -> Value {
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = timeout(WAIT, stream.read(&mut byte))
            .await
            .expect("read hung")
            .expect("read");
        assert_ne!(count, 0, "EOF before response");
        if byte[0] == b'\n' {
            return serde_json::from_slice(&frame).expect("response JSON");
        }
        frame.push(byte[0]);
    }
}

fn request_fingerprint(authority: &Value, params: &Value) -> String {
    let authority = serde_json::to_vec(authority).expect("authority bytes");
    let params = serde_json::to_vec(params).expect("params bytes");
    let mut framed = Vec::new();
    for value in [
        FINGERPRINT_DOMAIN,
        OPERATION.as_bytes(),
        &authority,
        &params,
    ] {
        framed.extend_from_slice(&(value.len() as u64).to_le_bytes());
        framed.extend_from_slice(value);
    }
    Digest::of(&framed).to_hex()
}

fn consumption_count(db: &Path) -> usize {
    SqliteLedger::open(db)
        .expect("inspect")
        .list_events()
        .expect("events")
        .into_iter()
        .filter(|event| event.kind == "candidate_preparation_grant_consumed")
        .count()
}

fn unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time range")
}

fn id(prefix: &str, suffix: char) -> String {
    format!("{prefix}_{}", suffix.to_string().repeat(64))
}

async fn assert_request_binding_hostiles_refuse(server: &Server, fixture: &Fixture) {
    let hostiles = [
        ("/change/id", json!(id("chg", '9'))),
        ("/change/mission", json!(id("mis", '9'))),
        ("/change/acceptance_root", json!("9".repeat(64))),
        ("/provenance/schema_version", json!(2)),
        ("/provenance/repository_id", json!(id("rep", '9'))),
        ("/provenance/producing_attempt_id", json!(id("atm", '9'))),
        ("/provenance/attempt_fence", json!(999)),
        ("/provenance/work_package_id", json!(id("wpk", '9'))),
        ("/provenance/variant_id", json!(id("var", '9'))),
        ("/provenance/plan_revision_id", json!(id("pln", '9'))),
        ("/provenance/graph_revision_id", json!(id("grf", '9'))),
        ("/provenance/parent_candidate_ids", json!([id("can", '9')])),
        ("/provenance/granted_scope", json!(["other"])),
        ("/provenance/context_capsule_id", json!(id("cnt", '9'))),
        (
            "/provenance/configuration_snapshot_id",
            json!(id("cnt", '8')),
        ),
        ("/provenance/policy_snapshot_id", json!(id("cnt", '7'))),
        ("/provenance/routing_snapshot_id", json!(id("cnt", '6'))),
        ("/provenance/environment_digest", json!("5".repeat(64))),
        ("/provenance/toolchain_digest", json!("4".repeat(64))),
    ];
    for (pointer, replacement) in hostiles {
        let mut params = fixture.params.clone();
        *params.pointer_mut(pointer).expect("hostile pointer") = replacement;
        let response = final_check(server, fixture, &params).await;
        assert_eq!(
            response["error"]["code"], "CANDIDATE_PREPARATION_REFUSED",
            "{pointer}: {response}"
        );
    }
}

#[tokio::test]
async fn final_check_requires_exact_stored_grant_and_consumes_across_restart() {
    let fixture = Fixture::new();
    let server = fixture.start("first").await;
    let missing = final_check(&server, &fixture, &json!({})).await;
    assert_eq!(missing["error"]["code"], "CANDIDATE_PREPARATION_REFUSED");
    let mut invalid_params = fixture.params.clone();
    let paseto = invalid_params["candidate_preparation_grant"]["paseto"]
        .as_str()
        .expect("PASETO")
        .to_owned();
    invalid_params["candidate_preparation_grant"]["paseto"] = json!(format!("{paseto}x"));
    let invalid = final_check(&server, &fixture, &invalid_params).await;
    assert_eq!(
        invalid["error"]["code"],
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );
    let absent = final_check(&server, &fixture, &fixture.absent_params).await;
    assert_eq!(absent["error"]["code"], "CANDIDATE_PREPARATION_REFUSED");
    assert_request_binding_hostiles_refuse(&server, &fixture).await;
    let mut altered_authority = fixture.authority.clone();
    altered_authority["graph_sequence"] = json!(2);
    let altered = final_check_with_authority(&server, &altered_authority, &fixture.params).await;
    assert_eq!(altered["error"]["code"], "CANDIDATE_PREPARATION_REFUSED");
    assert_eq!(consumption_count(&fixture.db), 0);
    let checked = final_check(&server, &fixture, &fixture.params).await;
    assert_eq!(checked["result"]["operation"], OPERATION, "{checked}");
    assert_eq!(consumption_count(&fixture.db), 1);
    drop_check_response(&server, &fixture, &fixture.loss_params).await;
    for _ in 0..200 {
        if consumption_count(&fixture.db) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(consumption_count(&fixture.db), 2);
    server.stop().await;

    let restarted = fixture.start("restart").await;
    let replay = final_check(&restarted, &fixture, &fixture.loss_params).await;
    assert_eq!(replay["error"]["code"], "CANDIDATE_PREPARATION_REPLAYED");
    assert_eq!(consumption_count(&fixture.db), 2);
    assert_eq!(replay["result"], Value::Null);
}
