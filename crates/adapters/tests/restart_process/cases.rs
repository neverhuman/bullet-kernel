use crate::assertions::{
    assert_adopted, assert_log, assert_projection, assert_successor_after_stale, invoke_crash,
    invoke_ok, recovery_push_log,
};
use crate::fixture::Fixture;
use crate::model::{CrashAfter, WorkerAction};
use crate::{hostiles, snapshot};

pub(crate) fn run_matrix() -> Result<(), String> {
    crash_after_claim()?;
    crash_after_retry_reservation()?;
    crash_after_remote_push()?;
    crash_after_terminal_commit()?;
    stale_successor_is_fenced_before_forge_io()?;
    third_party_remote_is_orphaned_without_push()?;
    hostiles::run()
}

fn crash_after_claim() -> Result<(), String> {
    let mut fixture = Fixture::new("process-claim")?;
    assert_ne!(fixture.base_oid, fixture.desired_oid);
    assert_eq!(fixture.remote_ref()?, None);
    let crash = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::Claim)?;
    invoke_crash(&fixture, 1, &crash)?;
    assert_eq!(fixture.remote_ref()?, None);
    assert_eq!(
        snapshot::claims(&fixture.database)?,
        vec![(1, "CLAIMED".into(), None)]
    );
    assert_log(&fixture, &[])?;
    assert_projection(&fixture, "pending", &[], &["effect_recovery_claimed"])?;

    let finish = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::None)?;
    invoke_ok(&fixture, 2, &finish, "ADOPTED")?;
    assert_log(&fixture, &recovery_push_log())?;
    assert_adopted(&fixture, 1, 3)
}

fn crash_after_retry_reservation() -> Result<(), String> {
    let mut fixture = Fixture::new("process-reservation")?;
    let crash = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::RetryReserved)?;
    invoke_crash(&fixture, 1, &crash)?;
    assert_eq!(fixture.remote_ref()?, None);
    assert_eq!(
        snapshot::intent(&fixture.database)?,
        ("DISPATCHING".into(), 1)
    );
    assert_eq!(
        snapshot::claims(&fixture.database)?,
        vec![(1, "RETRY_RESERVED".into(), None)]
    );
    assert_log(&fixture, &["OPEN", "DESCRIPTOR", "READ"])?;
    assert_projection(
        &fixture,
        "applied",
        &[("ABSENT", None)],
        &["effect_recovery_claimed", "effect_recovery_transition"],
    )?;

    let finish = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::None)?;
    invoke_ok(&fixture, 2, &finish, "ADOPTED")?;
    assert_log(
        &fixture,
        &[
            "OPEN",
            "DESCRIPTOR",
            "READ",
            "OPEN",
            "DESCRIPTOR",
            "READ",
            "DESCRIPTOR",
            "PUSH_BEGIN",
            "PUSH_OK",
            "READ",
        ],
    )?;
    assert_adopted(&fixture, 1, 3)
}

fn crash_after_remote_push() -> Result<(), String> {
    let mut fixture = Fixture::new("process-push")?;
    let crash = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::Push)?;
    invoke_crash(&fixture, 1, &crash)?;
    assert_eq!(fixture.remote_ref()?, Some(fixture.desired_oid.clone()));
    assert_eq!(
        snapshot::intent(&fixture.database)?,
        ("DISPATCHING".into(), 1)
    );
    assert_eq!(
        snapshot::claims(&fixture.database)?,
        vec![(1, "RETRY_RESERVED".into(), None)]
    );
    assert_log(
        &fixture,
        &[
            "OPEN",
            "DESCRIPTOR",
            "READ",
            "DESCRIPTOR",
            "PUSH_BEGIN",
            "PUSH_OK",
        ],
    )?;
    assert_projection(
        &fixture,
        "applied",
        &[("ABSENT", None)],
        &["effect_recovery_claimed", "effect_recovery_transition"],
    )?;

    let finish = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::None)?;
    invoke_ok(&fixture, 2, &finish, "ADOPTED")?;
    assert_log(
        &fixture,
        &[
            "OPEN",
            "DESCRIPTOR",
            "READ",
            "DESCRIPTOR",
            "PUSH_BEGIN",
            "PUSH_OK",
            "OPEN",
            "DESCRIPTOR",
            "READ",
        ],
    )?;
    assert_adopted(&fixture, 1, 2)
}

fn crash_after_terminal_commit() -> Result<(), String> {
    let mut fixture = Fixture::new("process-terminal")?;
    let crash = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::Adopted)?;
    invoke_crash(&fixture, 1, &crash)?;
    assert_adopted(&fixture, 1, 3)?;
    assert_log(&fixture, &recovery_push_log())?;
    let durable_before = snapshot::durable(&fixture.database)?;
    let log_before = std::fs::read(&fixture.forge_log).map_err(|error| error.to_string())?;
    let remote_before = fixture.remote_ref()?;

    let replay = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::None)?;
    invoke_ok(&fixture, 2, &replay, "NO_WORK")?;
    assert_eq!(snapshot::durable(&fixture.database)?, durable_before);
    assert_eq!(
        std::fs::read(&fixture.forge_log).map_err(|error| error.to_string())?,
        log_before
    );
    assert_eq!(fixture.remote_ref()?, remote_before);
    Ok(())
}

fn stale_successor_is_fenced_before_forge_io() -> Result<(), String> {
    let mut fixture = Fixture::new("process-stale")?;
    let authority_a = fixture.authority.clone();
    let authority_a_digest = authority_a.successor_authority_digest.to_hex();
    let token_a = fixture.token.clone();
    let grant_a = fixture.grant.clone();
    let crash = fixture.manifest(
        WorkerAction::Reconcile,
        CrashAfter::Claim,
        authority_a.clone(),
        token_a.clone(),
        grant_a.clone(),
    )?;
    invoke_crash(&fixture, 1, &crash)?;
    fixture.acquire_successor("process-stale-recovery-b")?;
    let durable_before = snapshot::durable(&fixture.database)?;
    let log_before = std::fs::read(&fixture.forge_log).map_err(|error| error.to_string())?;
    let stale = fixture.manifest(
        WorkerAction::StaleReadbackProbe,
        CrashAfter::None,
        authority_a,
        token_a,
        grant_a,
    )?;
    invoke_ok(&fixture, 2, &stale, "STALE_AUTHORITY")?;
    assert_eq!(
        std::fs::read(&fixture.forge_log).map_err(|error| error.to_string())?,
        log_before
    );
    assert_eq!(snapshot::durable(&fixture.database)?, durable_before);
    assert_eq!(fixture.remote_ref()?, None);

    let finish = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::None)?;
    invoke_ok(&fixture, 3, &finish, "ADOPTED")?;
    assert_eq!(
        snapshot::claims(&fixture.database)?,
        vec![
            (1, "INVALIDATED".into(), Some("CLAIMED".into())),
            (2, "ADOPTED".into(), None),
        ]
    );
    assert_log(&fixture, &recovery_push_log())?;
    assert_successor_after_stale(&fixture, &authority_a_digest)
}

fn third_party_remote_is_orphaned_without_push() -> Result<(), String> {
    let mut fixture = Fixture::new("process-orphan")?;
    let third_oid = fixture.preseed_third_oid()?;
    let remote_before = fixture.remote_ref()?;
    let reconcile = fixture.current_manifest(WorkerAction::Reconcile, CrashAfter::None)?;
    invoke_ok(&fixture, 1, &reconcile, "ORPHANED_REMOTE")?;
    assert_eq!(remote_before, Some(third_oid.clone()));
    assert_eq!(fixture.remote_ref()?, remote_before);
    assert_log(&fixture, &["OPEN", "DESCRIPTOR", "READ"])?;
    assert_eq!(
        snapshot::intent(&fixture.database)?,
        ("ORPHANED_REMOTE".into(), 0)
    );
    assert_eq!(
        snapshot::claims(&fixture.database)?,
        vec![(1, "ORPHANED".into(), None)]
    );
    assert_projection(
        &fixture,
        "unknown",
        &[("MISMATCH", Some(third_oid.as_str()))],
        &["effect_recovery_claimed", "effect_recovery_transition"],
    )?;
    snapshot::claim_receipt(&fixture.database)?
        .ok_or_else(|| "orphan receipt absent".to_string())?;
    Ok(())
}
