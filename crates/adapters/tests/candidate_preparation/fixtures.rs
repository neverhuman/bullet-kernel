use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    execution_toolchain_digest, CandidatePreparationSource, ExecutionEnvelopeV1, ExecutionToolV1,
};
use bullet_application::{materialize_plan, LeaseService, Ledger, PlanInput};
use bullet_domain::{Attempt, TaskClass};
use chrono::Utc;

pub struct Fixture {
    pub _directory: tempfile::TempDir,
    pub path: std::path::PathBuf,
    pub ledger: SqliteLedger,
    pub attempt: Attempt,
}

pub fn fixture(seed: &str) -> Fixture {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let directory = builder.tempdir().unwrap();
    let path = directory.path().join("candidate.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "Candidate preparation".into(),
            objective: "bind durable source truth".into(),
            packages: vec![("prepare".into(), TaskClass::BoundedBugFix)],
        },
        &LeaseService::rfc3339(Utc::now()),
    )
    .unwrap();
    let (attempt, _, _) = LeaseService::acquire(&mut ledger, &graph, 0, seed, 15).unwrap();
    Fixture {
        _directory: directory,
        path,
        ledger,
        attempt,
    }
}

pub fn source(attempt: &Attempt, seed: char) -> CandidatePreparationSource {
    let tools = vec![ExecutionToolV1 {
        schema_version: "v1alpha1".into(),
        tool_id: id("etl", seed),
        role: "git".into(),
        executable_path: "/usr/bin/git".into(),
        executable_digest: "a".repeat(64),
        descriptor_digest: "b".repeat(64),
        version: "2.45.2".into(),
    }];
    let now = u64::try_from(Utc::now().timestamp_millis()).unwrap();
    CandidatePreparationSource {
        schema_version: "v1alpha1".into(),
        attempt_id: attempt.id.clone(),
        root_change: true,
        change_id: id("chg", seed),
        parent_candidate_ids: vec![],
        execution_envelope: ExecutionEnvelopeV1 {
            schema_version: "v1alpha1".into(),
            execution_envelope_id: id("exe", seed),
            issuer: "bullet-kernel".into(),
            key_id: "execution-1".into(),
            signing_purpose: "execution-envelope-signing".into(),
            claims_domain: "execution.envelope.v1alpha1".into(),
            runner_id: attempt.runner_id.to_string(),
            runner_epoch: attempt.runner_epoch,
            provider: "simulator".into(),
            model: "deterministic".into(),
            adapter: "simulator-v1".into(),
            provider_profile_id: id("prf", seed),
            platform: "linux-x86_64".into(),
            containment_profile_id: id("ctp", seed),
            environment_digest: "c".repeat(64),
            toolchain_digest: execution_toolchain_digest(&tools).unwrap(),
            sandbox_image_digest: "d".repeat(64),
            tools,
            authority_epoch: 1,
            freeze_generation: 0,
            issued_at_unix_ms: now.saturating_sub(1_000),
            expires_at_unix_ms: now + 14_000,
        },
        ttl_ms: 5_000,
    }
}

pub fn id(prefix: &str, seed: char) -> String {
    format!("{prefix}_{}", seed.to_string().repeat(64))
}

pub fn event_count(ledger: &SqliteLedger, kind: &str) -> usize {
    ledger
        .list_events()
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == kind)
        .count()
}
