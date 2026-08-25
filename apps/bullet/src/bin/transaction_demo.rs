//! Offline five-plane transaction-component saga. `run_demo` stays the
//! projection seeder. This binary is what `just demo` drives, but its
//! ephemeral self-signed receipt cannot clear a transaction gate.

use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, CommandRequest, Ledger, PlanInput};
use bullet_domain::AttemptState;
use bullet_domain::{Digest, RunnerId, TaskClass, REPOSITORY_GATE_ID};
use bullet_effects_core::{
    authorize, dispatch, propose, reconcile, IntentInput, LocalBareForge, LossMode,
    LostResponseForge, ReconcileOutcome, ZERO_OID,
};
use bullet_harness_core::proposal::{PatchMutation, PatchOperation, PatchProposal, Preimage};
use bullet_harness_core::transaction_proof::{
    TransactionComponentSigningKey, TransactionComponentSubject, TRANSACTION_COMPONENT_CLASS,
    TRANSACTION_COMPONENT_SCHEMA_VERSION, TRANSACTION_COMPONENT_TRUST,
};
use bullet_runner_core::lease::{AcquireRequest, HeartbeatCall, LeaseClient, ReleaseCall};
use bullet_runner_core::{gitd_fixture_binary, GitdSession, SignedLeaseRpcClient};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::Duration;

const FIXTURE_KEY: [u8; 32] = [0x5a; 32];

#[derive(Serialize)]
struct FixturePermitClaims {
    schema_version: String,
    attempt_id: String,
    attempt_fence: u64,
    workspace_nonce_hex: String,
    destination: String,
}

#[derive(Serialize)]
struct FixturePermit {
    claims: FixturePermitClaims,
    mac_hex: String,
}

fn fail(message: impl Into<String>) -> String {
    message.into()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn framed_digest(fields: &[&[u8]]) -> String {
    let mut buf = Vec::new();
    for field in fields {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    Digest::of(&buf).to_hex()
}

fn mint_fixture_permit(claims: FixturePermitClaims) -> FixturePermit {
    let body = serde_json::to_vec(&claims).expect("claims");
    let mac_hex = framed_digest(&[b"bullet-gitd.fixture-permit.mac.v1", &FIXTURE_KEY, &body]);
    FixturePermit { claims, mac_hex }
}

fn private_dir(path: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(path).map_err(|err| fail(format!("create {}: {err}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| fail(format!("chmod {}: {err}", path.display())))?;
    }
    fs::canonicalize(path).map_err(|err| fail(format!("canonicalize {}: {err}", path.display())))
}

fn kernel_bin(name: &str) -> PathBuf {
    let env = format!("BULLET_{}_BIN", name.to_ascii_uppercase().replace('-', "_"));
    if let Some(path) = std::env::var_os(&env) {
        return PathBuf::from(path);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug")
        .join(name)
}

fn wait_for(path: &Path, tries: u32) -> Result<(), String> {
    for _ in 0..tries {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(fail(format!("timed out waiting for {}", path.display())))
}

fn free_port() -> Result<u16, String> {
    Ok(TcpListener::bind("127.0.0.1:0")
        .map_err(|err| fail(err.to_string()))?
        .local_addr()
        .map_err(|err| fail(err.to_string()))?
        .port())
}

fn wait_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn sh(dir: &Path, script: &str) -> Result<(), String> {
    let out = Command::new("sh")
        .arg("-ec")
        .arg(script)
        .current_dir(dir)
        .output()
        .map_err(|err| fail(format!("spawn git: {err}")))?;
    if !out.status.success() {
        return Err(fail(format!(
            "git: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn init_source(root: &Path) -> Result<(PathBuf, String), String> {
    let src = root.join("source");
    fs::create_dir_all(src.join("src")).map_err(|err| fail(err.to_string()))?;
    fs::write(src.join("src").join("lib.rs"), "pub fn seed() {}\n")
        .map_err(|err| fail(err.to_string()))?;
    sh(
        &src,
        "git init -q -b main . && git config user.name bullet && git config user.email bullet@test && git add . && git commit -qm seed",
    )?;
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&src)
        .output()
        .map_err(|err| fail(err.to_string()))?;
    let hex = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((src, format!("sha1:{hex}")))
}

fn spawn_farmd(data: &Path, socket: &Path, port: u16) -> Result<Child, String> {
    let bin = kernel_bin("bullet-farmd");
    if !bin.is_file() {
        return Err(fail(format!(
            "bullet-farmd missing at {} (build -p bullet-farmd)",
            bin.display()
        )));
    }
    Command::new(bin)
        .arg("--data-dir")
        .arg(data)
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--lease-transport-socket")
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| fail(format!("spawn farmd: {err}")))
}

fn run_verifier(
    workspace: &Path,
    base: &str,
    head: &str,
    tree: &str,
    attempt: &str,
    overlap: bool,
) -> Result<(i32, Value), String> {
    let bin = kernel_bin("bullet-verifier");
    if !bin.is_file() {
        return Err(fail(format!(
            "bullet-verifier missing at {}",
            bin.display()
        )));
    }
    let request = json!({
        "workspace_repo_path": workspace.display().to_string(),
        "base_sha": base,
        "head_sha": head,
        "tree_sha": tree,
        "gate_id": REPOSITORY_GATE_ID,
        "author_attempt_id": attempt,
    });
    let mut cmd = Command::new(bin);
    cmd.arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if overlap {
        cmd.env("BULLET_VERIFIER_AUTHOR_OVERLAP", "1");
    }
    let mut child = cmd
        .spawn()
        .map_err(|err| fail(format!("spawn verifier: {err}")))?;
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| fail("verifier stdin"))?
        .write_all(request.to_string().as_bytes())
        .map_err(|err| fail(err.to_string()))?;
    let out = child
        .wait_with_output()
        .map_err(|err| fail(err.to_string()))?;
    let text = if out.stdout.is_empty() {
        String::from_utf8_lossy(&out.stderr).into_owned()
    } else {
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let value = serde_json::from_str(text.trim()).unwrap_or(json!({ "raw": text.trim() }));
    Ok((out.status.code().unwrap_or(1), value))
}

fn strip_oid(oid: &str) -> &str {
    oid.rsplit(':').next().unwrap_or(oid)
}

fn content_id(label: &str) -> String {
    format!("cnt_{}", Digest::of(label.as_bytes()).to_hex())
}

async fn run() -> Result<(), String> {
    let pid = std::process::id();
    let scratch = private_dir(&PathBuf::from(format!("/tmp/bullet-txn-{pid}")))?;
    let data = match std::env::var_os("BULLET_DATA_DIR") {
        Some(path) => private_dir(&PathBuf::from(path))?,
        None => private_dir(&scratch.join("data"))?,
    };
    let db = data.join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&db).map_err(|err| fail(err.to_string()))?;
    let now = Utc::now().to_rfc3339();
    let graph = materialize_plan(
        &mut ledger,
        "txn-proof-demo",
        &PlanInput {
            title: "Offline TRANSACTION_PROOF".into(),
            objective: "Five-plane fixture component without live providers.".into(),
            packages: vec![(
                "signed offline transaction".into(),
                TaskClass::BoundedBugFix,
            )],
        },
        &now,
    )
    .map_err(|err| fail(err.to_string()))?;
    let package = graph
        .packages
        .first()
        .ok_or_else(|| fail("demo graph has no package"))?
        .clone();
    let command = CommandRequest::new(
        "txn-proof-demo",
        "run_demo",
        &json!({ "evidence_class": TRANSACTION_COMPONENT_CLASS }),
    )
    .map_err(|err| fail(err.to_string()))?;
    let command = ledger
        .submit_command(&command)
        .map_err(|err| fail(err.to_string()))?;
    drop(ledger);

    let socket = data.join("lease-transport.sock");
    let port = free_port()?;
    let mut farmd = spawn_farmd(&data, &socket, port)?;
    if let Err(error) = wait_for(&socket, 80) {
        wait_child(&mut farmd);
        return Err(error);
    }

    let runner = RunnerId::from_seed("txn-demo-runner");
    let client = SignedLeaseRpcClient::new(socket, runner.clone(), 1);
    let first = match client
        .acquire(&AcquireRequest {
            work_package_id: package.id.clone(),
            runner_id: runner.clone(),
            runner_epoch: 1,
            idempotency_key: "txn-demo-a1".into(),
            ttl_seconds: 15,
        })
        .await
    {
        Ok(grant) => grant,
        Err(error) => {
            wait_child(&mut farmd);
            return Err(fail(error.to_string()));
        }
    };
    if first.attempt.fence != 1 {
        wait_child(&mut farmd);
        return Err(fail(format!(
            "first fence was {}, expected 1",
            first.attempt.fence
        )));
    }

    let fixture_bin = gitd_fixture_binary();
    if !fixture_bin.is_file() {
        wait_child(&mut farmd);
        return Err(fail(format!(
            "bullet-gitd-fixture missing at {} (build --features fixture-authority)",
            fixture_bin.display()
        )));
    }
    let (source, base) = match init_source(&scratch) {
        Ok(source) => source,
        Err(error) => {
            wait_child(&mut farmd);
            return Err(error);
        }
    };
    let fixture_root = match private_dir(&scratch.join("farm")) {
        Ok(root) => root,
        Err(error) => {
            wait_child(&mut farmd);
            return Err(error);
        }
    };
    let token = match serde_json::to_value(&first.authority_token) {
        Ok(token) => token,
        Err(error) => {
            wait_child(&mut farmd);
            return Err(fail(error.to_string()));
        }
    };
    let permit = mint_fixture_permit(FixturePermitClaims {
        schema_version: "v1".into(),
        attempt_id: first.attempt.id.to_string(),
        attempt_fence: first.attempt.fence,
        workspace_nonce_hex: hex_encode(&first.authority_token.workspace_nonce),
        destination: fixture_root.display().to_string(),
    });
    let permit_path = scratch.join("permit.json");
    if let Err(error) = fs::write(
        &permit_path,
        serde_json::to_vec(&permit).map_err(|err| fail(err.to_string()))?,
    ) {
        wait_child(&mut farmd);
        return Err(fail(error.to_string()));
    }
    let mut gitd = match GitdSession::spawn_with(
        fixture_bin,
        [
            "--root",
            fixture_root.to_str().ok_or_else(|| fail("root utf8"))?,
            "--key-hex",
            &hex_encode(&FIXTURE_KEY),
            "--permit-file",
            permit_path.to_str().ok_or_else(|| fail("permit utf8"))?,
        ],
        token,
    )
    .await
    {
        Ok(session) => session,
        Err(error) => {
            wait_child(&mut farmd);
            return Err(fail(error.to_string()));
        }
    };

    let workspace = match gitd
        .clone_workspace(&source, &base, &fixture_root, &["src".into()])
        .await
    {
        Ok(workspace) => workspace,
        Err(error) => {
            let _ = gitd.kill().await;
            wait_child(&mut farmd);
            return Err(fail(error.to_string()));
        }
    };

    let proposal = PatchProposal {
        schema_version: 1,
        proposal_id: content_id("txn-demo-proposal"),
        producing_attempt_id: first.attempt.id.to_string(),
        base_checkpoint_id: workspace.base_checkpoint_id.clone(),
        base_checkpoint_digest: workspace.base_checkpoint_digest.clone(),
        operations: vec![PatchOperation {
            path: "src/lib.rs".into(),
            preimage: Preimage::Digest {
                digest: Digest::of(b"pub fn seed() {}\n").to_hex(),
            },
            mutation: PatchMutation::Write {
                content_utf8: "pub fn demo() {}\n".into(),
            },
        }],
        gate_ids: vec![REPOSITORY_GATE_ID.into()],
        intent_summary: String::new(),
        claims: Vec::new(),
        uncertainties: Vec::new(),
        done: true,
    };
    let applied = match gitd.apply_proposal(&proposal).await {
        Ok(applied) => applied,
        Err(error) => {
            let _ = gitd.kill().await;
            wait_child(&mut farmd);
            return Err(fail(error.to_string()));
        }
    };

    let prepare = match gitd
        .invoke(
            "prepare_candidate",
            json!({
                "change": {
                    "id": format!("chg_{}", Digest::of(b"txn-demo-change").to_hex()),
                    "mission": "txn-proof-demo",
                    "acceptance_root": Digest::of(b"acc").to_hex()
                },
                "provenance": {
                    "schema_version": 1,
                    "repository_id": first.authority_token.repository_id.to_string(),
                    "producing_attempt_id": first.attempt.id.to_string(),
                    "attempt_fence": first.attempt.fence,
                    "work_package_id": package.id.to_string(),
                    "variant_id": first.authority_token.variant_id.to_string(),
                    "plan_revision_id": first.authority_token.plan_revision_id.to_string(),
                    "graph_revision_id": format!("grf_{}", Digest::of(b"txn-demo-graph").to_hex()),
                    "base_checkpoint_id": applied.checkpoint.id,
                    "base_commit": workspace.base_sha,
                    "parent_candidate_ids": [],
                    "granted_scope": ["src"],
                    "context_capsule_id": content_id("ctx"),
                    "configuration_snapshot_id": content_id("cfg"),
                    "policy_snapshot_id": content_id("pol"),
                    "routing_snapshot_id": content_id("rte"),
                    "environment_digest": Digest::of(b"env").to_hex(),
                    "toolchain_digest": Digest::of(b"tool").to_hex()
                }
            }),
        )
        .await
    {
        Ok(prepare) => prepare,
        Err(error) => {
            let _ = gitd.kill().await;
            wait_child(&mut farmd);
            return Err(fail(format!("prepare_candidate: {error}")));
        }
    };
    let candidate_id = prepare
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| fail(format!("candidate id missing: {prepare}")))?
        .to_string();
    let head = prepare
        .get("head_commit")
        .or_else(|| prepare.pointer("/manifest/head_commit"))
        .and_then(Value::as_str)
        .ok_or_else(|| fail(format!("head missing: {prepare}")))?
        .to_string();
    let tree = prepare
        .get("tree_hash")
        .or_else(|| prepare.get("tree_oid"))
        .or_else(|| prepare.pointer("/manifest/tree_oid"))
        .and_then(Value::as_str)
        .ok_or_else(|| fail(format!("tree missing: {prepare}")))?
        .to_string();

    let (writer_code, writer_body) = run_verifier(
        &workspace.repo_dir,
        strip_oid(&workspace.base_sha),
        strip_oid(&head),
        strip_oid(&tree),
        first.attempt.id.as_str(),
        true,
    )?;
    let writer_proof_refused = writer_code != 0
        && writer_body
            .get("reason_code")
            .and_then(Value::as_str)
            .is_some_and(|code| code == "VERIFIER_IS_AUTHOR");
    let (verifier_code, verifier_body) = run_verifier(
        &workspace.repo_dir,
        strip_oid(&workspace.base_sha),
        strip_oid(&head),
        strip_oid(&tree),
        first.attempt.id.as_str(),
        false,
    )?;
    let verifier_outcome = verifier_body
        .get("outcome")
        .or_else(|| verifier_body.get("result"))
        .and_then(Value::as_str)
        .unwrap_or(if verifier_code == 0 { "PASS" } else { "FAIL" })
        .to_string();

    let effects_root = scratch.join("effects");
    fs::create_dir_all(&effects_root).map_err(|err| fail(err.to_string()))?;
    let workspace_git = effects_root.join("workspace");
    fs::create_dir_all(&workspace_git).map_err(|err| fail(err.to_string()))?;
    sh(
        &workspace_git,
        "git init -q -b main . && git config user.name bullet && git config user.email bullet@test && echo demo > f && git add . && git commit -qm demo",
    )?;
    let head_out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&workspace_git)
        .output()
        .map_err(|err| fail(err.to_string()))?;
    let effect_head = String::from_utf8_lossy(&head_out.stdout).trim().to_string();
    let mut effects = SqliteLedger::open(&db).map_err(|err| fail(err.to_string()))?;
    let token_ref = &first.authority_token;
    let forge = LocalBareForge::init(&effects_root.join("target.git"))
        .map_err(|err| fail(err.to_string()))?;
    let intent = IntentInput {
        provider: "local-bare".into(),
        logical_effect_key: format!("push:txn:{}", first.attempt.fence),
        target_ref: "refs/heads/bullet/candidate/txn-demo".into(),
        new_oid: effect_head,
        expected_old_oid: ZERO_OID.into(),
        attempt_id: token_ref.attempt_id.clone(),
        fence: token_ref.attempt_fence,
        policy_version: "policy-v1".into(),
        provider_idempotency_key: None,
    };
    let (row, _) = propose(&mut effects, &intent, &now).map_err(|err| fail(err.to_string()))?;
    let (_authorized, seq) = {
        let mut last = None;
        let mut authorized = None;
        for _ in 0..8 {
            match authorize(&mut effects, &row.id, token_ref, &now) {
                Ok(ok) => {
                    authorized = Some(ok);
                    break;
                }
                Err(error) => {
                    last = Some(error.to_string());
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        authorized.ok_or_else(|| fail(last.unwrap_or_else(|| "authorize failed".into())))?
    };
    let mut lossy = LostResponseForge::new(forge);
    lossy.lose_next(LossMode::AfterPush);
    let unknown = dispatch(
        &mut effects,
        &mut lossy,
        &row.id,
        &workspace_git,
        Some(seq),
        &now,
    )
    .map_err(|err| fail(err.to_string()))?;
    if unknown != bullet_application::EffectState::OutcomeUnknown {
        let _ = gitd.kill().await;
        wait_child(&mut farmd);
        return Err(fail(format!("lost response was {unknown:?}, not UNKNOWN")));
    }
    let adopted = reconcile(
        &mut effects,
        &mut lossy,
        &row.id,
        &workspace_git,
        Some(seq),
        &now,
    )
    .map_err(|err| fail(err.to_string()))?;
    if adopted != ReconcileOutcome::Adopted {
        let _ = gitd.kill().await;
        wait_child(&mut farmd);
        return Err(fail(format!("expected Adopted, got {adopted:?}")));
    }
    let settled = effects
        .get_effect_intent_by_id(&row.id)
        .map_err(|err| fail(err.to_string()))?
        .map(|record| record.state)
        .ok_or_else(|| fail("settled intent missing"))?;

    let preserve_to = scratch.join("preserve");
    if let Err(error) = gitd.preserve(&preserve_to).await {
        let _ = gitd.kill().await;
        wait_child(&mut farmd);
        return Err(fail(format!("preserve: {error}")));
    }
    gitd.kill().await.map_err(|err| fail(err.to_string()))?;

    if let Err(error) = client
        .release(&ReleaseCall {
            attempt_id: first.attempt.id.clone(),
            outcome: AttemptState::Superseded,
            requeue: true,
        })
        .await
    {
        wait_child(&mut farmd);
        return Err(fail(error.to_string()));
    }
    let second = match client
        .acquire(&AcquireRequest {
            work_package_id: package.id.clone(),
            runner_id: runner.clone(),
            runner_epoch: 1,
            idempotency_key: "txn-demo-a2".into(),
            ttl_seconds: 15,
        })
        .await
    {
        Ok(grant) => grant,
        Err(error) => {
            wait_child(&mut farmd);
            return Err(fail(error.to_string()));
        }
    };
    if second.attempt.fence != 2 {
        wait_child(&mut farmd);
        return Err(fail(format!(
            "successor fence was {}, expected 2",
            second.attempt.fence
        )));
    }
    let stale = client
        .heartbeat(&HeartbeatCall {
            variant_id: first.lease.variant_id.clone(),
            attempt_id: first.attempt.id.clone(),
            fence: first.attempt.fence,
            runner_id: runner,
            runner_epoch: 1,
            workspace_nonce: first.authority_token.workspace_nonce,
            ttl_seconds: 15,
        })
        .await;
    let stale_refused = stale.is_err();
    if !stale_refused {
        wait_child(&mut farmd);
        return Err(fail("stale fence heartbeat was accepted"));
    }
    if !writer_proof_refused {
        wait_child(&mut farmd);
        return Err(fail(format!("writer proof was not refused: {writer_body}")));
    }

    let subject = TransactionComponentSubject {
        schema_version: TRANSACTION_COMPONENT_SCHEMA_VERSION.into(),
        evidence_class: TRANSACTION_COMPONENT_CLASS.into(),
        signing_trust: TRANSACTION_COMPONENT_TRUST.into(),
        transaction_gate_eligible: false,
        fence_first: first.attempt.fence,
        fence_second: second.attempt.fence,
        attempt_first: first.attempt.id.to_string(),
        attempt_second: second.attempt.id.to_string(),
        candidate_id,
        verifier_outcome,
        writer_proof_refused,
        effect_unknown: unknown.as_str().into(),
        effect_settled: settled.as_str().into(),
        stale_refused,
        gitd_fixture: true,
        command_id: command.id.to_string(),
        command_phase: command.phase.as_str().into(),
    };
    let proof_key = TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1")
        .map_err(|err| fail(err.to_string()))?;
    let proof = proof_key
        .sign(&subject)
        .map_err(|err| fail(err.to_string()))?;
    let proof_json = serde_json::to_string_pretty(&proof).map_err(|err| fail(err.to_string()))?;
    let proof_path = data.join("TRANSACTION_COMPONENT_RECEIPT.json");
    fs::write(&proof_path, &proof_json).map_err(|err| fail(err.to_string()))?;
    println!("{proof_json}");
    println!("COMPONENT_PROOF: {}", proof_path.display());
    wait_child(&mut farmd);
    Ok(())
}

fn main() -> ExitCode {
    match tokio::runtime::Runtime::new()
        .expect("tokio")
        .block_on(run())
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bullet-transaction-demo: {message}");
            ExitCode::FAILURE
        }
    }
}
