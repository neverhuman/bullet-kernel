use crate::fixture::Fixture;
use crate::model::{self, WorkerManifest};
use crate::{process, snapshot};

const CRASH_EXIT: i32 = 86;

pub(crate) fn assert_adopted(
    fixture: &Fixture,
    pushes: usize,
    transition_events: usize,
) -> Result<(), String> {
    assert_eq!(fixture.remote_ref()?, Some(fixture.desired_oid.clone()));
    assert_eq!(
        snapshot::intent(&fixture.database)?,
        ("COMMITTED".into(), 1)
    );
    assert_eq!(
        snapshot::claims(&fixture.database)?,
        vec![(1, "ADOPTED".into(), None)]
    );
    assert_eq!(snapshot::push_attempt_count(&fixture.forge_log)?, pushes);
    assert_eq!(snapshot::push_count(&fixture.forge_log)?, pushes);
    let mut events = vec!["effect_recovery_claimed"];
    events.extend(std::iter::repeat_n(
        "effect_recovery_transition",
        transition_events,
    ));
    assert_projection(
        fixture,
        "verified",
        &[("ABSENT", None), ("MATCH", Some(&fixture.desired_oid))],
        &events,
    )?;
    snapshot::claim_receipt(&fixture.database)?
        .ok_or_else(|| "adoption receipt absent".to_string())?;
    Ok(())
}

pub(crate) fn assert_successor_after_stale(
    fixture: &Fixture,
    authority_a_digest: &str,
) -> Result<(), String> {
    assert_eq!(fixture.remote_ref()?, Some(fixture.desired_oid.clone()));
    assert_eq!(
        snapshot::intent(&fixture.database)?,
        ("COMMITTED".into(), 1)
    );
    let claims = snapshot::claim_subjects(&fixture.database)?;
    assert_eq!(claims.len(), 2);
    let authority_b = fixture.authority.successor_authority_digest.to_hex();
    assert_eq!(claims[0].generation, 1);
    assert_eq!(claims[0].authority_digest, authority_a_digest);
    assert_eq!(claims[1].generation, 2);
    assert_eq!(claims[1].authority_digest, authority_b);
    assert_ne!(claims[0].id, claims[1].id);
    let outbox = snapshot::recovery_outbox(&fixture.database)?;
    assert_eq!(outbox.len(), 2);
    assert_outbox(&outbox[0], &claims[0].id, "unknown");
    assert_outbox(&outbox[1], &claims[1].id, "verified");
    assert_receipts(
        fixture,
        &[("ABSENT", None), ("MATCH", Some(&fixture.desired_oid))],
    )?;
    let events = snapshot::recovery_events(&fixture.database)?;
    assert_eq!(events.len(), 5);
    assert_event(&events[0], "effect_recovery_claimed", fixture, &claims[0]);
    assert_event(&events[1], "effect_recovery_claimed", fixture, &claims[1]);
    for event in &events[2..] {
        assert_event(event, "effect_recovery_transition", fixture, &claims[1]);
    }
    snapshot::claim_receipt(&fixture.database)?
        .ok_or_else(|| "successor adoption receipt absent".to_string())?;
    Ok(())
}

pub(crate) fn assert_log(fixture: &Fixture, expected: &[&str]) -> Result<(), String> {
    assert_eq!(snapshot::forge_log(&fixture.forge_log)?, expected);
    assert_eq!(
        snapshot::push_attempt_count(&fixture.forge_log)?,
        expected
            .iter()
            .filter(|event| **event == "PUSH_BEGIN")
            .count()
    );
    assert_eq!(
        snapshot::push_count(&fixture.forge_log)?,
        expected.iter().filter(|event| **event == "PUSH_OK").count()
    );
    Ok(())
}

pub(crate) fn assert_projection(
    fixture: &Fixture,
    phase: &str,
    receipts: &[(&str, Option<&str>)],
    event_kinds: &[&str],
) -> Result<(), String> {
    let claims = snapshot::claim_subjects(&fixture.database)?;
    assert_eq!(claims.len(), 1);
    let claim = &claims[0];
    assert_eq!(claim.generation, 1);
    assert_eq!(
        claim.authority_digest,
        fixture.authority.successor_authority_digest.to_hex()
    );
    let outbox = snapshot::recovery_outbox(&fixture.database)?;
    assert_eq!(outbox.len(), 1);
    assert_outbox(&outbox[0], &claim.id, phase);
    assert_receipts(fixture, receipts)?;
    let events = snapshot::recovery_events(&fixture.database)?;
    assert_eq!(events.len(), event_kinds.len());
    for (event, kind) in events.iter().zip(event_kinds) {
        assert_event(event, kind, fixture, claim);
    }
    Ok(())
}

fn assert_outbox(row: &snapshot::OutboxSubject, claim_id: &str, phase: &str) {
    assert_eq!(row.payload, claim_id);
    assert_eq!(row.phase, phase);
    assert_eq!(row.delivered, matches!(phase, "applied" | "verified"));
    assert_eq!(row.acknowledged, matches!(phase, "verified" | "unknown"));
}

fn assert_receipts(fixture: &Fixture, expected: &[(&str, Option<&str>)]) -> Result<(), String> {
    let receipts = snapshot::recovery_receipts(&fixture.database)?;
    assert_eq!(receipts.len(), expected.len());
    let mut ids = std::collections::BTreeSet::new();
    for (receipt, (verdict, observed)) in receipts.iter().zip(expected) {
        assert_eq!(receipt.id.len(), 68);
        assert!(receipt.id.starts_with("efr_"));
        assert!(ids.insert(receipt.id.as_str()));
        assert_eq!(receipt.effect_intent_id, fixture.intent_id.as_str());
        assert_eq!(receipt.remote_identity, fixture.target_ref);
        assert_eq!(receipt.method, "local-bare-read-ref-v1");
        assert_eq!(receipt.verdict, *verdict);
        assert_eq!(receipt.observed_oid.as_deref(), *observed);
        assert_eq!(receipt.adopted_after_unknown, *verdict == "MATCH");
    }
    Ok(())
}

fn assert_event(
    event: &snapshot::EventSubject,
    kind: &str,
    fixture: &Fixture,
    claim: &snapshot::ClaimSubject,
) {
    assert_eq!(event.kind, kind);
    assert_eq!(event.stream_id.as_deref(), Some(fixture.intent_id.as_str()));
    assert_eq!(event.correlation_id.as_deref(), Some(claim.id.as_str()));
    assert_eq!(
        event.authority_digest.as_deref(),
        Some(claim.authority_digest.as_str())
    );
}

pub(crate) fn recovery_push_log() -> [&'static str; 7] {
    [
        "OPEN",
        "DESCRIPTOR",
        "READ",
        "DESCRIPTOR",
        "PUSH_BEGIN",
        "PUSH_OK",
        "READ",
    ]
}

pub(crate) fn invoke_crash(
    fixture: &Fixture,
    sequence: u64,
    manifest: &WorkerManifest,
) -> Result<(), String> {
    let (path, digest) = model::write(&fixture.root, sequence, manifest)?;
    let result = process::run_worker(&fixture.root, &path, &digest)?;
    if result.status.code() != Some(CRASH_EXIT)
        || result.diagnostic.is_some()
        || manifest.result.exists()
    {
        return Err(format!(
            "worker did not crash at committed boundary: {:?} diagnostic={:?}",
            result.status.code(),
            result.diagnostic
        ));
    }
    Ok(())
}

pub(crate) fn invoke_ok(
    fixture: &Fixture,
    sequence: u64,
    manifest: &WorkerManifest,
    expected: &str,
) -> Result<(), String> {
    let (path, digest) = model::write(&fixture.root, sequence, manifest)?;
    let result = process::run_worker(&fixture.root, &path, &digest)?;
    process::assert_success(&result)?;
    let actual = std::fs::read_to_string(&manifest.result).map_err(|error| error.to_string())?;
    if actual != format!("{expected}\n") {
        return Err(format!("worker result mismatch: {actual:?}"));
    }
    Ok(())
}
