use super::MutationPermitPresentation;
use crate::sqlite::mutation_authority::{MutationCompletion, MutationDisposition};
use crate::sqlite::SqliteLedger;
use bullet_application::{
    materialize_plan, ActiveLeaseSubject, LeaseService, Ledger, MutationReserveRequest,
    OneUsePermit, PlanInput,
};
use bullet_domain::schema_bundle::{
    AuthorityAudienceV1, MutationOperationV1, MutationPermitClaimsV1, SignedMutationPermitV1,
    SCHEMA_VERSION,
};
use bullet_domain::{Digest, RepositoryId, TaskClass};
use chrono::Utc;
use rusqlite::Connection;
use std::path::Path;

#[test]
fn exact_presentation_survives_restart_and_terminal_replay() {
    let directory = secure_tempdir();
    let path = directory.path().join("permit-presentation.sqlite3");
    let lease_request = setup(&path, "permit-presentation");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let grant = ledger.acquire_lease(&lease_request).expect("active lease");
    let subject = ActiveLeaseSubject::from_attempt(&grant.attempt);

    for (mutation_id, operation) in [
        ("mut_short".into(), "apply-patch".into()),
        (format!("mut_{}", "A".repeat(64)), "apply-patch".into()),
        (
            format!("mut_{}", Digest::of(b"legacy-operation").to_hex()),
            "apply_change".into(),
        ),
    ] {
        let invalid = MutationReserveRequest {
            mutation_id,
            operation,
            request_digest: Digest::of(b"invalid-request").to_hex(),
        };
        assert_eq!(
            ledger
                .reserve_mutation(&subject, &invalid)
                .expect_err("invalid reservation")
                .reason_code(),
            "MUTATION_AUTHORITY_INVALID_REQUEST"
        );
        assert!(ledger
            .mutation_disposition(&invalid.mutation_id)
            .expect("readback")
            .is_none());
    }
    let request = mutation_request("durable");
    let reserved = ledger
        .reserve_mutation(&subject, &request)
        .expect("reserve");
    assert_eq!(reserved.disposition, MutationDisposition::Reserved);
    assert_eq!(reserved.graph_revision, 1);
    assert_eq!(reserved.workspace_generation, 1);
    assert_eq!(reserved.scope_digest, "0".repeat(64));
    assert!(reserved.presentation.is_none());
    assert_eq!(
        ledger.reserve_mutation(&subject, &request).expect("replay"),
        reserved
    );
    let raw = Connection::open(&path).expect("raw missing presentation");
    assert!(raw
        .execute(
            "UPDATE mutation_authority SET disposition = 'CONSUMED'
             WHERE mutation_id = ?1",
            [&request.mutation_id],
        )
        .is_err());
    drop(raw);
    let presentation = presentation(&subject, &reserved.permit, "durable");
    let consumed = ledger
        .present_mutation(&subject, &reserved.permit, &presentation)
        .expect("present");
    assert_eq!(consumed.disposition, MutationDisposition::Consumed);
    let persisted = consumed.presentation.as_ref().expect("presentation");
    assert_eq!(
        persisted.permit_digest,
        Digest::of(&presentation.signed_permit_bytes).to_hex()
    );
    assert_eq!(
        ledger
            .present_mutation(&subject, &reserved.permit, &presentation)
            .expect("exact presentation replay"),
        consumed
    );
    let mut changed = presentation.clone();
    changed.verified_claims.authority_envelope_digest = Digest::of(b"changed").to_hex();
    assert_eq!(
        ledger
            .present_mutation(&subject, &reserved.permit, &changed)
            .expect_err("changed replay")
            .reason_code(),
        "MUTATION_AUTHORITY_CONFLICT"
    );
    drop(ledger);
    let mut reopened = SqliteLedger::open(&path).expect("reopen consumed");
    assert_eq!(
        reopened
            .present_mutation(&subject, &reserved.permit, &presentation)
            .expect("lost-response replay")
            .disposition,
        MutationDisposition::Consumed
    );
    let completion = MutationCompletion::Settled {
        result_digest: Digest::of(b"authoritative-ref-readback").to_hex(),
    };
    let settled = reopened
        .complete_mutation(&subject, &reserved.permit, &completion)
        .expect("settle");
    assert_eq!(settled.disposition, MutationDisposition::Settled);
    assert_eq!(
        reopened
            .complete_mutation(&subject, &reserved.permit, &completion)
            .expect("terminal replay"),
        settled
    );
    let raw = Connection::open(path).expect("raw immutable presentation");
    assert!(raw
        .execute(
            "UPDATE mutation_permit_presentations SET issuer = 'changed'",
            [],
        )
        .is_err());
    assert!(raw
        .execute("DELETE FROM mutation_permit_presentations", [])
        .is_err());
    assert!(raw
        .execute(
            "UPDATE mutation_authority SET disposition = 'CONSUMED', completion_digest = NULL",
            [],
        )
        .is_err());
}

#[test]
fn every_authority_movement_invalidates_reserved_and_unknowns_consumed() {
    for movement in [
        "graph",
        "workspace",
        "scope",
        "policy",
        "routing",
        "authority",
        "freeze",
        "restore",
    ] {
        let directory = secure_tempdir();
        let path = directory
            .path()
            .join(format!("movement-{movement}.sqlite3"));
        let lease_request = setup(&path, movement);
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let grant = ledger.acquire_lease(&lease_request).expect("lease");
        let subject = ActiveLeaseSubject::from_attempt(&grant.attempt);
        let reserved_request = mutation_request(&format!("reserved-{movement}"));
        ledger
            .reserve_mutation(&subject, &reserved_request)
            .expect("reserve before movement");
        let consumed_request = mutation_request(&format!("consumed-{movement}"));
        let consumed_permit = ledger
            .reserve_mutation(&subject, &consumed_request)
            .expect("reserve consumed")
            .permit;
        ledger
            .present_mutation(
                &subject,
                &consumed_permit,
                &presentation(&subject, &consumed_permit, movement),
            )
            .expect("consume before movement");
        drop(ledger);
        move_authority(&path, movement);
        let mut reopened = SqliteLedger::open(&path).expect("reopen after movement");
        assert_eq!(
            reopened
                .mutation_disposition(&reserved_request.mutation_id)
                .expect("reserved readback")
                .expect("reserved row")
                .disposition,
            MutationDisposition::Invalidated,
            "{movement}"
        );
        let unknown = reopened
            .mutation_disposition(&consumed_request.mutation_id)
            .expect("consumed readback")
            .expect("consumed row");
        assert_eq!(
            unknown.disposition,
            MutationDisposition::Unknown,
            "{movement}"
        );
        assert!(unknown.completion_digest.is_some());
        assert!(unknown.presentation.is_some());
        let after = mutation_request(&format!("after-{movement}"));
        assert_eq!(
            reopened
                .reserve_mutation(&subject, &after)
                .expect_err("stale lease after movement")
                .reason_code(),
            "STALE_AUTHORITY",
            "{movement}"
        );
        assert!(reopened
            .mutation_disposition(&after.mutation_id)
            .expect("zero-row refusal")
            .is_none());
    }
}

#[test]
fn hostile_presentations_refuse_without_consuming_or_adding_rows() {
    let directory = secure_tempdir();
    let path = directory.path().join("hostile-presentations.sqlite3");
    let lease_request = setup(&path, "hostile-presentations");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let grant = ledger.acquire_lease(&lease_request).expect("lease");
    let subject = ActiveLeaseSubject::from_attempt(&grant.attempt);
    let request = mutation_request("hostile");
    let permit = ledger
        .reserve_mutation(&subject, &request)
        .expect("reserve")
        .permit;
    let valid = presentation(&subject, &permit, "hostile");
    let mut cases = Vec::new();
    let mut malformed = valid.clone();
    malformed.signed_permit_bytes = b"not-json".to_vec();
    cases.push(malformed);
    let mut changed_request = valid.clone();
    changed_request.verified_claims.request_digest = Digest::of(b"changed").to_hex();
    cases.push(changed_request);
    let mut changed_operation = valid.clone();
    changed_operation.verified_claims.operation = MutationOperationV1::Checkpoint;
    cases.push(changed_operation);
    let mut bad_repository = valid.clone();
    bad_repository.verified_claims.repository_id = "rep_short".into();
    cases.push(bad_repository);
    let mut bad_digest = valid.clone();
    bad_digest.verified_claims.authority_token_nonce = "A".repeat(64);
    cases.push(bad_digest);
    let mut expired = valid.clone();
    let now = unix_ms();
    expired.verified_claims.issued_at_unix_ms = now.saturating_sub(1_000);
    expired.verified_claims.not_before_unix_ms = now.saturating_sub(1_000);
    expired.verified_claims.expires_at_unix_ms = now;
    cases.push(expired);
    for hostile in cases {
        let error = ledger
            .present_mutation(&subject, &permit, &hostile)
            .expect_err("hostile presentation");
        assert!(matches!(
            error.reason_code(),
            "MUTATION_AUTHORITY_INVALID_REQUEST" | "MUTATION_AUTHORITY_CONFLICT"
        ));
        let row = ledger
            .mutation_disposition(&request.mutation_id)
            .expect("readback")
            .expect("reservation");
        assert_eq!(row.disposition, MutationDisposition::Reserved);
        assert!(row.presentation.is_none());
        assert_eq!(presentation_count(&path), 0);
    }
}

#[test]
fn aborted_is_typed_unknown_is_durable_and_corruption_fails_closed() {
    let directory = secure_tempdir();
    let path = directory.path().join("unknown-and-corrupt.sqlite3");
    let lease_request = setup(&path, "unknown-and-corrupt");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let grant = ledger.acquire_lease(&lease_request).expect("lease");
    let subject = ActiveLeaseSubject::from_attempt(&grant.attempt);
    let request = mutation_request("unknown-and-corrupt");
    let permit = ledger
        .reserve_mutation(&subject, &request)
        .expect("reserve")
        .permit;
    ledger
        .present_mutation(
            &subject,
            &permit,
            &presentation(&subject, &permit, "unknown-and-corrupt"),
        )
        .expect("present");
    let digest = Digest::of(b"readback-observation").to_hex();
    assert_eq!(
        ledger
            .complete_mutation(
                &subject,
                &permit,
                &MutationCompletion::Aborted {
                    observation_digest: digest.clone(),
                },
            )
            .expect_err("aborted unsupported")
            .reason_code(),
        "MUTATION_ABORTED_UNSUPPORTED"
    );
    assert_eq!(
        ledger
            .mutation_disposition(&request.mutation_id)
            .expect("readback")
            .expect("row")
            .disposition,
        MutationDisposition::Consumed
    );
    let unknown = MutationCompletion::Unknown {
        observation_digest: digest,
    };
    ledger
        .complete_mutation(&subject, &permit, &unknown)
        .expect("unknown");
    drop(ledger);
    corrupt_presentation_bytes(&path);
    for _ in 0..2 {
        let reopened = SqliteLedger::open(&path).expect("schema remains exact");
        assert_eq!(
            reopened
                .mutation_disposition(&request.mutation_id)
                .expect_err("corrupt presentation")
                .reason_code(),
            "STORE_FAILURE"
        );
    }
}

fn mutation_request(seed: &str) -> MutationReserveRequest {
    MutationReserveRequest {
        mutation_id: format!("mut_{}", Digest::of(seed.as_bytes()).to_hex()),
        operation: "apply-patch".into(),
        request_digest: Digest::of(format!("request-{seed}").as_bytes()).to_hex(),
    }
}

fn presentation(
    subject: &ActiveLeaseSubject,
    permit: &OneUsePermit,
    seed: &str,
) -> MutationPermitPresentation {
    let now = unix_ms();
    let issuer = "bullet-kernel-component".to_string();
    let signed = SignedMutationPermitV1 {
        schema_version: SCHEMA_VERSION.into(),
        issuer: issuer.clone(),
        key_id: "component-fixture-key".into(),
        paseto: format!("v4.public.component-{seed}"),
    };
    MutationPermitPresentation {
        signed_permit_bytes: serde_json::to_vec(&signed).expect("signed envelope"),
        verified_claims: MutationPermitClaimsV1 {
            schema_version: SCHEMA_VERSION.into(),
            issuer,
            audience: AuthorityAudienceV1::BulletGitd,
            operation: MutationOperationV1::ApplyPatch,
            authority_envelope_digest: Digest::of(format!("envelope-{seed}").as_bytes()).to_hex(),
            authority_token_nonce: Digest::of(format!("token-{seed}").as_bytes()).to_hex(),
            mutation_id: permit.mutation_id.clone(),
            reservation_id: permit.reservation_id.clone(),
            request_digest: permit.request_digest.clone(),
            repository_id: RepositoryId::from_seed("component-repository").to_string(),
            workspace_id: subject.workspace_id.to_string(),
            workspace_generation: 1,
            attempt_id: subject.attempt_id.to_string(),
            attempt_fence: subject.fence,
            authority_epoch: 1,
            freeze_generation: 0,
            issued_at_unix_ms: now.saturating_sub(50),
            not_before_unix_ms: now.saturating_sub(50),
            expires_at_unix_ms: now.saturating_add(900),
            permit_nonce: Digest::of(format!("permit-{seed}").as_bytes()).to_hex(),
        },
    }
}

fn move_authority(path: &std::path::Path, movement: &str) {
    let raw = Connection::open(path).expect("raw authority movement");
    match movement {
        "graph" => raw.execute("UPDATE authority_revisions SET graph_revision = 2", []),
        "workspace" => raw.execute(
            "UPDATE authority_revisions SET workspace_generation = 2",
            [],
        ),
        "scope" => raw.execute(
            "UPDATE authority_revisions SET scope_digest = ?1, authority_epoch = 2",
            ["b".repeat(64)],
        ),
        "policy" => raw.execute("UPDATE authority_revisions SET policy_generation = 2", []),
        "routing" => raw.execute("UPDATE authority_revisions SET routing_generation = 2", []),
        "authority" => raw.execute("UPDATE authority_revisions SET authority_epoch = 2", []),
        "freeze" => raw.execute("UPDATE authority_revisions SET freeze_generation = 1", []),
        "restore" => raw.execute(
            "UPDATE restore_state SET restore_epoch = 1, source_snapshot_digest = ?1,
                                      restored_at = '2026-08-26T00:00:00.000Z'",
            [Digest::of(b"restore").to_hex()],
        ),
        _ => unreachable!(),
    }
    .expect("advance authority");
}

fn corrupt_presentation_bytes(path: &std::path::Path) {
    let raw = Connection::open(path).expect("raw corruption");
    let trigger: String = raw
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
             AND name = 'mutation_permit_presentations_no_update'",
            [],
            |row| row.get(0),
        )
        .expect("update trigger");
    raw.execute_batch("DROP TRIGGER mutation_permit_presentations_no_update;")
        .expect("drop fixture trigger");
    raw.execute(
        "UPDATE mutation_permit_presentations SET signed_permit_bytes = X'00'",
        [],
    )
    .expect("corrupt bytes");
    raw.execute_batch(&trigger).expect("restore exact trigger");
}

fn presentation_count(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .expect("raw count")
        .query_row(
            "SELECT COUNT(*) FROM mutation_permit_presentations",
            [],
            |row| row.get(0),
        )
        .expect("presentation count")
}

fn unix_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).expect("current Unix time")
}

fn setup(path: &Path, seed: &str) -> bullet_application::LeaseRequest {
    let mut ledger = SqliteLedger::open(path).expect("open setup");
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "permit presentation".into(),
            objective: "prove exact durable first use".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("materialize setup");
    LeaseService::request_for(&graph, 0, &format!("{seed}-lease"), 5).expect("lease request")
}

fn secure_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure tempdir mode");
    }
    directory
}
