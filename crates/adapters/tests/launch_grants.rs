//! SQLite launch-grant nonces: single use under the database clock, and the
//! full issuer path against a real durable lease.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::launch_grant::{
    durable_lease_binding, verify_launch_grant, LaunchGrantExpectation, LaunchGrantIssuer,
    LaunchGrantNonceRecord, LaunchGrantNonceStore, LaunchGrantRequest, LaunchGrantSigningKey,
    LedgerLaunchGrantIssuer, NonceConsumption, PolicyBinding, ProviderBinding, ProviderProtocol,
    StoreNonceLedger,
};
use bullet_application::{materialize_plan, LeaseService, PlanInput};
use bullet_domain::{Attempt, AttemptId, TaskClass};
use chrono::Utc;

fn record(
    nonce: char,
    grant: char,
    attempt: &AttemptId,
    expires_at_unix_ms: u64,
) -> LaunchGrantNonceRecord {
    LaunchGrantNonceRecord {
        grant_nonce: nonce.to_string().repeat(64),
        grant_id: grant.to_string().repeat(64),
        attempt_id: attempt.clone(),
        attempt_fence: 1,
        expires_at_unix_ms,
        issued_at: LeaseService::rfc3339(Utc::now()),
    }
}

fn far_future() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap() + 60_000
}

#[test]
fn nonces_are_consumed_exactly_once_under_the_database_clock() {
    let directory = support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("nonces.sqlite")).unwrap();
    let attempt = AttemptId::from_seed("attempt");
    let other = AttemptId::from_seed("other");
    let live = record('a', 'b', &attempt, far_future());
    ledger.record_launch_grant_nonce(&live).unwrap();
    let duplicate = ledger
        .record_launch_grant_nonce(&record('a', 'c', &attempt, far_future()))
        .unwrap_err();
    assert_eq!(duplicate.reason_code(), "GRAPH_CONFLICT");
    let duplicate_grant = ledger
        .record_launch_grant_nonce(&record('d', 'b', &attempt, far_future()))
        .unwrap_err();
    assert_eq!(duplicate_grant.reason_code(), "GRAPH_CONFLICT");
    assert!(ledger
        .record_launch_grant_nonce(&LaunchGrantNonceRecord {
            grant_nonce: "not-hex".into(),
            ..record('e', 'e', &attempt, far_future())
        })
        .is_err());

    let stored = ledger
        .get_launch_grant_nonce(&live.grant_nonce)
        .unwrap()
        .unwrap();
    assert_eq!(stored.record, live);
    assert!(stored.consumed_at.is_none());
    assert_eq!(
        ledger
            .consume_launch_grant_nonce(&live.grant_nonce, &other)
            .unwrap(),
        NonceConsumption::Unknown
    );
    assert_eq!(
        ledger
            .consume_launch_grant_nonce(&live.grant_nonce, &attempt)
            .unwrap(),
        NonceConsumption::Consumed
    );
    let consumed = ledger
        .get_launch_grant_nonce(&live.grant_nonce)
        .unwrap()
        .unwrap();
    assert!(consumed.consumed_at.is_some());
    assert_eq!(
        ledger
            .consume_launch_grant_nonce(&live.grant_nonce, &attempt)
            .unwrap(),
        NonceConsumption::Replayed
    );
    assert_eq!(
        ledger
            .consume_launch_grant_nonce(&"f".repeat(64), &attempt)
            .unwrap(),
        NonceConsumption::Unknown
    );
    let stale = record('1', '2', &attempt, 1);
    ledger.record_launch_grant_nonce(&stale).unwrap();
    assert_eq!(
        ledger
            .consume_launch_grant_nonce(&stale.grant_nonce, &attempt)
            .unwrap(),
        NonceConsumption::Expired
    );
    assert!(ledger
        .get_launch_grant_nonce(&stale.grant_nonce)
        .unwrap()
        .unwrap()
        .consumed_at
        .is_none());
}

fn acquire(ledger: &mut SqliteLedger, seed: &str) -> Attempt {
    let graph = materialize_plan(
        ledger,
        seed,
        &PlanInput {
            title: "launch".into(),
            objective: "durable lease".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        &LeaseService::rfc3339(Utc::now()),
    )
    .unwrap();
    let (attempt, _token, _grant) = LeaseService::acquire(ledger, &graph, 0, seed, 15).unwrap();
    attempt
}

#[test]
fn issuer_mints_from_the_sqlite_lease_and_replay_is_durable() {
    let directory = support::private_tempdir();
    let path = directory.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let attempt = acquire(&mut ledger, "sqlite-grant");
    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let request = LaunchGrantRequest {
        attempt_id: attempt.id.clone(),
        provider: "codex".into(),
        adapter: "codex-app-server-v1".into(),
        provider_profile_id: format!("prf_{}", "4".repeat(64)),
        model: "codex-test".into(),
        credential_generation: 2,
        protocol: "codex_app_server_jsonl".into(),
        executable_path: "/usr/local/bin/codex".into(),
        executable_digest: "3".repeat(64),
        descriptor_digest: "4".repeat(64),
        capability_digest: "5".repeat(64),
        sandbox_manifest_digest: "7".repeat(64),
        environment_digest: "c".repeat(64),
        gate_ids: vec![format!("gat_{}", "8".repeat(64))],
        max_invocations: 1,
        max_wall_clock_ms: 1_000,
        max_cost_micro_usd: 0,
        ttl_ms: 5_000,
    };
    let policy = PolicyBinding {
        policy_snapshot_digest: "6".repeat(64),
        policy_generation: 1,
        live_admission_enabled: true,
    };
    let now = Utc::now();
    let grant = LedgerLaunchGrantIssuer::new(&mut ledger, &key, policy.clone())
        .mint(&request, now)
        .unwrap();
    let durable = durable_lease_binding(&mut ledger, &attempt.id).unwrap();
    let expectation = LaunchGrantExpectation {
        now_unix_ms: u64::try_from(now.timestamp_millis()).unwrap() + 100,
        lease: durable.binding,
        provider: ProviderBinding {
            provider: "codex".into(),
            adapter: "codex-app-server-v1".into(),
            provider_profile_id: request.provider_profile_id.clone(),
            model: "codex-test".into(),
            credential_generation: 2,
            protocol: ProviderProtocol::CodexAppServerJsonl,
            executable_path: "/usr/local/bin/codex".into(),
            executable_digest: "3".repeat(64),
            descriptor_digest: "4".repeat(64),
            capability_digest: "5".repeat(64),
            sandbox_manifest_digest: "7".repeat(64),
            environment_digest: "c".repeat(64),
        },
        policy,
    };
    let verifier = key.verification_key().unwrap();
    let verified = verify_launch_grant(
        &grant,
        &verifier,
        &expectation,
        &mut StoreNonceLedger(&mut ledger),
    )
    .unwrap();
    assert_eq!(verified.claims().attempt_fence, attempt.fence);
    drop(ledger);
    let mut reopened = SqliteLedger::open(&path).unwrap();
    let replay = verify_launch_grant(
        &grant,
        &verifier,
        &expectation,
        &mut StoreNonceLedger(&mut reopened),
    )
    .unwrap_err();
    assert_eq!(replay.reason_code(), "LAUNCH_GRANT_REPLAYED");
}
