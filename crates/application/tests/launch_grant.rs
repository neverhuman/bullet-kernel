//! The issuer mints only from the durable active lease, persists a
//! single-use nonce, and refuses without a coherent lease or with a stale
//! fence. Nothing here spawns a provider.

use bullet_application::launch_grant::{
    durable_lease_binding, LaunchGrantIssuer, LaunchGrantNonceStore, LaunchGrantRequest,
    LedgerLaunchGrantIssuer, StoreNonceLedger, GENESIS_AUTHORITY_EPOCH, GENESIS_FREEZE_GENERATION,
};
use bullet_application::{
    materialize_plan, LeaseService, Ledger, MemoryLedger, PlanInput, StoredGraph,
};
use bullet_domain::{Attempt, AttemptId, AttemptState, TaskClass};
use bullet_harness_core::launch_grant::{
    verify_launch_grant, LaunchGrantExpectation, LaunchGrantSigningKey, PolicyBinding,
    ProviderBinding,
};
use bullet_harness_core::ProviderProtocol;
use chrono::{DateTime, TimeZone, Utc};

fn plan() -> PlanInput {
    PlanInput {
        title: "launch grant".into(),
        objective: "bind the durable lease".into(),
        packages: vec![("package".into(), TaskClass::BoundedBugFix)],
    }
}

fn leased(seed: &str) -> (MemoryLedger, StoredGraph, Attempt) {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let graph = materialize_plan(&mut ledger, seed, &plan(), &now).unwrap();
    let (attempt, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, seed, 15).unwrap();
    (ledger, graph, attempt)
}

fn request(attempt: &Attempt) -> LaunchGrantRequest {
    LaunchGrantRequest {
        attempt_id: attempt.id.clone(),
        provider: "claude".into(),
        adapter: "claude-stream-json-v1".into(),
        provider_profile_id: format!("prf_{}", "4".repeat(64)),
        model: "claude-test".into(),
        credential_generation: 1,
        protocol: "claude_stream_json".into(),
        executable_path: "/usr/local/bin/claude".into(),
        executable_digest: "3".repeat(64),
        descriptor_digest: "4".repeat(64),
        capability_digest: "5".repeat(64),
        sandbox_manifest_digest: "7".repeat(64),
        environment_digest: "c".repeat(64),
        gate_ids: vec![format!("gat_{}", "8".repeat(64))],
        max_invocations: 3,
        max_wall_clock_ms: 900_000,
        max_cost_micro_usd: 2_500_000,
        ttl_ms: 15_000,
    }
}

fn policy(live: bool) -> PolicyBinding {
    PolicyBinding {
        policy_snapshot_digest: "6".repeat(64),
        policy_generation: 1,
        live_admission_enabled: live,
    }
}

fn provider_binding(request: &LaunchGrantRequest) -> ProviderBinding {
    ProviderBinding {
        provider: request.provider.clone(),
        adapter: request.adapter.clone(),
        provider_profile_id: request.provider_profile_id.clone(),
        model: request.model.clone(),
        credential_generation: request.credential_generation,
        protocol: ProviderProtocol::ClaudeStreamJson,
        executable_path: request.executable_path.clone(),
        executable_digest: request.executable_digest.clone(),
        descriptor_digest: request.descriptor_digest.clone(),
        capability_digest: request.capability_digest.clone(),
        sandbox_manifest_digest: request.sandbox_manifest_digest.clone(),
        environment_digest: request.environment_digest.clone(),
    }
}

fn simulation_now(ledger: &MemoryLedger, offset_ms: i64) -> DateTime<Utc> {
    let base = DateTime::parse_from_rfc3339(&ledger.simulation_time()).unwrap();
    Utc.timestamp_millis_opt(base.timestamp_millis() + offset_ms)
        .unwrap()
}

#[test]
fn mint_binds_the_durable_lease_and_the_nonce_is_single_use() {
    let (mut ledger, graph, attempt) = leased("mint");
    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let request = request(&attempt);
    let now = simulation_now(&ledger, 1_000);
    let grant = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&request, now)
        .unwrap();
    assert_eq!(grant.issuer, "bullet-kernel");
    assert!(grant.paseto.starts_with("v4.public."));

    let durable = durable_lease_binding(&mut ledger, &attempt.id).unwrap();
    assert_eq!(durable.binding.mission_id, graph.mission.id.to_string());
    assert_eq!(
        durable.binding.repository_id,
        graph.mission.repository_id.to_string()
    );
    assert_eq!(durable.binding.attempt_fence, attempt.fence);
    assert_eq!(durable.binding.runner_epoch, attempt.runner_epoch);
    assert_eq!(
        durable.binding.authority_epoch,
        ledger.current_authority().unwrap().authority_epoch()
    );
    assert_eq!(
        durable.binding.freeze_generation,
        ledger.current_authority().unwrap().freeze_generation()
    );
    assert_eq!(durable.binding.authority_epoch, GENESIS_AUTHORITY_EPOCH);
    assert_eq!(durable.binding.freeze_generation, GENESIS_FREEZE_GENERATION);
    assert_eq!(durable.lease_expires_at_unix_ms, 15_000);
    let expectation = |live: bool, now_unix_ms: u64| LaunchGrantExpectation {
        now_unix_ms,
        lease: durable.binding.clone(),
        provider: provider_binding(&request),
        policy: policy(live),
    };
    let verifier = key.verification_key().unwrap();
    let disabled = verify_launch_grant(
        &grant,
        &verifier,
        &expectation(false, 1_000),
        &mut StoreNonceLedger(&mut ledger),
    )
    .unwrap_err();
    assert_eq!(disabled.reason_code(), "POLICY_LIVE_ADMISSION_DISABLED");

    let verified = verify_launch_grant(
        &grant,
        &verifier,
        &expectation(true, 1_000),
        &mut StoreNonceLedger(&mut ledger),
    )
    .unwrap();
    let claims = verified.claims();
    assert_eq!(claims.attempt_id, attempt.id.to_string());
    assert_eq!(claims.variant_id, attempt.variant_id.to_string());
    assert_eq!(claims.work_package_id, attempt.work_package_id.to_string());
    assert_eq!(claims.workspace_id, attempt.workspace_id.to_string());
    assert_eq!(
        (claims.issued_at_unix_ms, claims.not_before_unix_ms),
        (1_000, 1_000)
    );
    assert_eq!(
        claims.expires_at_unix_ms, 15_000,
        "clamped to the lease expiry"
    );
    assert_ne!(claims.grant_id, claims.grant_nonce);
    let stored = ledger
        .get_launch_grant_nonce(&claims.grant_nonce)
        .unwrap()
        .unwrap();
    assert_eq!(stored.record.grant_id, claims.grant_id);
    assert_eq!(stored.record.attempt_id, attempt.id);
    assert_eq!(stored.record.expires_at_unix_ms, 15_000);
    assert!(stored.consumed_at.is_some());

    let replay = verify_launch_grant(
        &grant,
        &verifier,
        &expectation(true, 1_000),
        &mut StoreNonceLedger(&mut ledger),
    )
    .unwrap_err();
    assert_eq!(replay.reason_code(), "LAUNCH_GRANT_REPLAYED");

    let second = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&request, now)
        .unwrap();
    assert_ne!(second.paseto, grant.paseto, "fresh nonce and grant id");
}

#[test]
fn mint_refuses_without_a_coherent_active_lease() {
    let (mut ledger, _graph, attempt) = leased("refuse");
    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let now = simulation_now(&ledger, 1_000);

    let mut unknown = request(&attempt);
    unknown.attempt_id = AttemptId::from_seed("never-leased");
    let error = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&unknown, now)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_REFUSED");

    for (name, mutate) in [
        (
            "ttl_zero",
            (|r: &mut LaunchGrantRequest| r.ttl_ms = 0) as fn(&mut LaunchGrantRequest),
        ),
        ("ttl_long", |r| r.ttl_ms = 15_001),
        ("digest", |r| r.executable_digest = "nope".into()),
    ] {
        let mut bad = request(&attempt);
        mutate(&mut bad);
        let error = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
            .mint(&bad, now)
            .unwrap_err();
        assert_eq!(error.reason_code(), "LAUNCH_GRANT_REFUSED", "{name}");
    }
    let mut shape = request(&attempt);
    shape.gate_ids = vec!["cargo test".into()];
    let error = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&shape, now)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_INVALID");
    assert!(ledger
        .get_launch_grant_nonce(&"0".repeat(64))
        .unwrap()
        .is_none());

    let late = simulation_now(&ledger, 15_000);
    let error = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&request(&attempt), late)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_REFUSED");
    assert!(error.to_string().contains("lease expires"));

    ledger.advance_simulation_time(16).unwrap();
    let expired = ledger.expire_leases().unwrap();
    assert_eq!(expired.len(), 1);
    let after_expiry = simulation_now(&ledger, 0);
    let error = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&request(&attempt), after_expiry)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_REFUSED");
}

#[test]
fn mint_refuses_a_stale_fence_after_the_lease_moved_on() {
    let (mut ledger, graph, first) = leased("fence");
    let lease = ledger.get_lease(&first.variant_id).unwrap().unwrap();
    LeaseService::release(
        &mut ledger,
        &bullet_application::LeaseGrant {
            attempt: first.clone(),
            lease,
        },
        AttemptState::Crashed,
        true,
    )
    .unwrap();
    let (second, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "fence-2", 15).unwrap();
    assert_eq!(second.fence, first.fence + 1);
    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let now = simulation_now(&ledger, 1_000);
    let stale = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&request(&first), now)
        .unwrap_err();
    assert_eq!(stale.reason_code(), "LAUNCH_GRANT_REFUSED");
    assert!(stale.to_string().contains("stale fence"));
    let fresh = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy(false))
        .mint(&request(&second), now)
        .unwrap();
    assert_eq!(fresh.key_id, "launch-grant-alpha");
    let binding = durable_lease_binding(&mut ledger, &second.id).unwrap();
    assert_eq!(binding.binding.attempt_fence, second.fence);
}
