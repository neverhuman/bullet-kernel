//! Exact selected-Variant lookup parity for Memory and SQLite.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{
    KernelLeaseTransport, SignedAcquireBody, SignedReleaseBody,
};
use bullet_application::store::CurrentPackage;
use bullet_application::store::ProjectionReader;
use bullet_application::{
    materialize_plan, materialize_synthetic_selection, Ledger, LedgerError, MemoryLedger,
    PlanInput, ReleaseRequest, StoredGraph,
};
use bullet_domain::{AttemptState, RunnerId, TaskClass, Variant, VariantId};

const AT: &str = "2026-01-01T00:00:00.000Z";

fn graph<L: Ledger>(ledger: &mut L, seed: &str) -> StoredGraph {
    let mut graph = materialize_plan(
        ledger,
        seed,
        &PlanInput {
            title: "selected lookup".into(),
            objective: "resolve exact member without weakening ordinary lookup".into(),
            packages: vec![
                ("one".into(), TaskClass::BoundedBugFix),
                ("two".into(), TaskClass::CodeReview),
            ],
        },
        AT,
    )
    .unwrap();
    let mut sibling = graph.variants[0].clone();
    sibling.id = VariantId::from_seed(&format!("{seed}:sibling"));
    graph.variants.push(sibling);
    graph
        .variants
        .sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    ledger.put_graph(&graph).unwrap();
    graph
}

fn resolve<L: Ledger>(
    ledger: &mut L,
    package: &bullet_domain::WorkPackageId,
    variant: &VariantId,
) -> Result<CurrentPackage, LedgerError> {
    ledger.with_lease_transport(|txn| txn.resolve_variant(package, variant))
}

fn assert_membership<L: Ledger>(ledger: &mut L, seed: &str) -> StoredGraph {
    let graph = graph(ledger, seed);
    let package = graph.packages[0].id.clone();
    let members: Vec<_> = graph
        .variants
        .iter()
        .filter(|row| row.work_package_id == package)
        .cloned()
        .collect();
    assert_eq!(members.len(), 2);
    for member in &members {
        assert_eq!(
            resolve(ledger, &package, &member.id).unwrap().variant,
            *member
        );
    }
    let ordinary = ledger
        .with_lease_transport(|txn| txn.resolve_package(&package))
        .unwrap_err();
    assert_eq!(ordinary.reason_code(), "STORE_FAILURE");
    assert_eq!(
        resolve(ledger, &package, &VariantId::from_seed("absent"))
            .unwrap_err()
            .reason_code(),
        "STALE_AUTHORITY"
    );
    let other = graph
        .variants
        .iter()
        .find(|row| row.work_package_id != package)
        .unwrap();
    assert_eq!(
        resolve(ledger, &package, &other.id)
            .unwrap_err()
            .reason_code(),
        "STALE_AUTHORITY"
    );
    graph
}

#[test]
fn memory_resolves_exact_members_and_preserves_ordinary_ambiguity_refusal() {
    assert_membership(&mut MemoryLedger::new(), "memory-selected");
}

#[test]
fn sqlite_reopen_resolves_the_same_exact_members() {
    let directory = support::private_tempdir();
    let path = directory.path().join("selected.sqlite3");
    let graph = assert_membership(&mut SqliteLedger::open(&path).unwrap(), "sqlite-selected");
    let mut reopened = SqliteLedger::open(&path).unwrap();
    for variant in graph
        .variants
        .iter()
        .filter(|row| row.work_package_id == graph.packages[0].id)
    {
        assert_eq!(
            resolve(&mut reopened, &graph.packages[0].id, &variant.id)
                .unwrap()
                .variant,
            *variant
        );
    }
}

fn duplicate_identity_refuses<L: Ledger>(ledger: &mut L, seed: &str) {
    let mut graph = graph(ledger, seed);
    let selected: Variant = graph
        .variants
        .iter()
        .find(|row| row.work_package_id == graph.packages[0].id)
        .unwrap()
        .clone();
    graph.variants.push(selected.clone());
    ledger.put_graph(&graph).unwrap();
    let error = resolve(ledger, &graph.packages[0].id, &selected.id).unwrap_err();
    assert_eq!(error.reason_code(), "STORE_FAILURE");
}

#[test]
fn duplicate_selected_identity_refuses_on_both_ledgers() {
    duplicate_identity_refuses(&mut MemoryLedger::new(), "memory-duplicate");
    let directory = support::private_tempdir();
    duplicate_identity_refuses(
        &mut SqliteLedger::open(directory.path().join("duplicate.sqlite3")).unwrap(),
        "sqlite-duplicate",
    );
}

fn cross_package_duplicate_identity_refuses<L: Ledger + ProjectionReader>(
    ledger: &mut L,
    seed: &str,
) {
    let mut graph = graph(ledger, seed);
    let selected = graph
        .variants
        .iter()
        .find(|row| row.work_package_id == graph.packages[0].id)
        .unwrap()
        .clone();
    let mut duplicate = selected.clone();
    duplicate.work_package_id = graph.packages[1].id.clone();
    graph.variants.push(duplicate);
    ledger.put_graph(&graph).unwrap();
    let events = ledger.list_events().unwrap();
    let attempts = ledger.list_attempts(&graph.mission.id).unwrap();
    let ready = ledger.ready_rows().unwrap();
    let outbox = ledger.outbox_all().unwrap();
    let error = resolve(ledger, &graph.packages[0].id, &selected.id).unwrap_err();
    assert_eq!(error.reason_code(), "STORE_FAILURE");
    assert_eq!(ledger.list_events().unwrap(), events);
    assert_eq!(ledger.list_attempts(&graph.mission.id).unwrap(), attempts);
    assert_eq!(ledger.ready_rows().unwrap(), ready);
    assert_eq!(ledger.outbox_all().unwrap(), outbox);
    assert!(ledger.list_leases().unwrap().is_empty());
}

#[test]
fn cross_package_duplicate_selected_identity_refuses_after_sqlite_reopen() {
    cross_package_duplicate_identity_refuses(
        &mut MemoryLedger::new(),
        "memory-cross-package-duplicate",
    );
    let directory = support::private_tempdir();
    let path = directory.path().join("cross-package-duplicate.sqlite3");
    cross_package_duplicate_identity_refuses(
        &mut SqliteLedger::open(&path).unwrap(),
        "sqlite-cross-package-duplicate",
    );
    let mut reopened = SqliteLedger::open(&path).unwrap();
    let mission = reopened.list_missions().unwrap().pop().unwrap();
    let graph = reopened.get_graph(&mission.id).unwrap().unwrap();
    let events = reopened.list_events().unwrap();
    let attempts = reopened.list_attempts(&mission.id).unwrap();
    let ready = reopened.ready_rows().unwrap();
    let outbox = reopened.outbox_all().unwrap();
    let selected = graph
        .variants
        .iter()
        .find(|row| row.work_package_id == graph.packages[0].id)
        .unwrap();
    let error = resolve(&mut reopened, &graph.packages[0].id, &selected.id).unwrap_err();
    assert_eq!(error.reason_code(), "STORE_FAILURE");
    assert_eq!(reopened.list_events().unwrap(), events);
    assert_eq!(reopened.list_attempts(&mission.id).unwrap(), attempts);
    assert_eq!(reopened.ready_rows().unwrap(), ready);
    assert_eq!(reopened.outbox_all().unwrap(), outbox);
    assert_eq!(
        reopened.get_graph(&mission.id).unwrap().unwrap().variants,
        graph.variants
    );
    assert!(reopened.list_leases().unwrap().is_empty());
}

#[test]
fn sqlite_selected_acquire_replays_after_reopen_then_admits_the_second_lane() {
    let directory = support::private_tempdir();
    let path = directory.path().join("selected-acquire.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let graph = materialize_synthetic_selection(
        &mut ledger,
        "sqlite-selected-acquire",
        &PlanInput {
            title: "durable pair".into(),
            objective: "strict row-first replay across reopen".into(),
            packages: vec![("one".into(), TaskClass::BoundedBugFix)],
        },
        AT,
    )
    .unwrap();
    let kernel = KernelLeaseTransport::generate().unwrap();
    let mut body = SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("sqlite-selected-runner-a"),
        runner_epoch: 1,
        idempotency_key: "sqlite-selected-a".into(),
        ttl_seconds: 15,
    };
    let error = kernel
        .acquire(&mut ledger, &body, 1_700_000_000_000)
        .unwrap_err();
    assert_eq!(error.reason_code(), "STORE_FAILURE");
    assert!(ledger.list_leases().unwrap().is_empty());
    let first = kernel
        .acquire_selected_variant(&mut ledger, &body, &graph.variants[0].id, 1_700_000_000_001)
        .unwrap();
    drop(ledger);

    let mut reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        kernel
            .acquire(&mut reopened, &body, 1_700_000_000_002)
            .unwrap(),
        first
    );
    assert_eq!(
        kernel
            .readback(&mut reopened, &body, 1_700_000_000_003)
            .unwrap(),
        first
    );
    kernel
        .release(
            &mut reopened,
            &SignedReleaseBody {
                work_package_id: body.work_package_id.clone(),
                runner_id: body.runner_id.clone(),
                runner_epoch: body.runner_epoch,
                idempotency_key: body.idempotency_key.clone(),
                call: ReleaseRequest {
                    variant_id: first.lease.variant_id.clone(),
                    attempt_id: first.attempt.id.clone(),
                    final_state: AttemptState::Superseded,
                    requeue: true,
                },
            },
            1_700_000_000_004,
        )
        .unwrap();
    body.runner_id = RunnerId::from_seed("sqlite-selected-runner-b");
    body.idempotency_key = "sqlite-selected-b".into();
    let second = kernel
        .acquire_selected_variant(
            &mut reopened,
            &body,
            &graph.variants[1].id,
            1_700_000_000_005,
        )
        .unwrap();
    assert_ne!(first.attempt.id, second.attempt.id);
    assert_eq!((first.attempt.fence, second.attempt.fence), (1, 1));
    drop(reopened);

    let mut final_read = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        final_read.list_leases().unwrap(),
        vec![second.lease.clone()]
    );
    assert_eq!(
        kernel
            .readback(&mut final_read, &body, 1_700_000_000_006)
            .unwrap(),
        second
    );
}
