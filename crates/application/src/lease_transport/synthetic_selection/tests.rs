use super::*;
use crate::lease_transport::{SignedAdvanceBody, SignedHeartbeatBody, SignedReleaseBody};
use crate::materializer::{materialize_synthetic_selection, PlanInput};
use crate::records::{HeartbeatRequest, ReleaseRequest};
use crate::store::ProjectionReader;
use crate::MemoryLedger;
use bullet_domain::{AttemptState, RunnerId, TaskClass, VariantId};
#[cfg(feature = "test-seams")]
use bullet_domain::{Digest, WorkPackageId};

const NOW: u64 = 1_700_000_000_000;

fn fixture() -> (
    MemoryLedger,
    KernelLeaseTransport,
    SignedAcquireBody,
    Vec<VariantId>,
) {
    let mut ledger = MemoryLedger::new();
    let at = ledger.simulation_time();
    let graph = materialize_synthetic_selection(
        &mut ledger,
        "synthetic-lease",
        &PlanInput {
            title: "pair".into(),
            objective: "selected acquisition".into(),
            packages: vec![("one".into(), TaskClass::BoundedBugFix)],
        },
        &at,
    )
    .unwrap();
    let body = SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("synthetic-runner-a"),
        runner_epoch: 1,
        idempotency_key: "synthetic-a".into(),
        ttl_seconds: 15,
    };
    let variants = graph.variants.iter().map(|row| row.id.clone()).collect();
    (
        ledger,
        KernelLeaseTransport::generate().unwrap(),
        body,
        variants,
    )
}

#[cfg(feature = "test-seams")]
fn selected_request(ttl_seconds: i64) -> SyntheticSelectedAcquireBody {
    let (_, _, body, variants) = fixture();
    SyntheticSelectedAcquireBody::new(
        Digest::of(b"synthetic-selection-plan"),
        body.work_package_id,
        body.runner_id,
        body.runner_epoch,
        variants[0].clone(),
        ttl_seconds,
    )
    .unwrap()
}

#[cfg(feature = "test-seams")]
#[test]
fn selected_wrapper_is_canonical_bound_and_farmd_call_ready() {
    let (mut ledger, kernel, body, variants) = fixture();
    let selected = SyntheticSelectedAcquireBody::new(
        Digest::of(b"synthetic-selection-plan"),
        body.work_package_id,
        body.runner_id,
        body.runner_epoch,
        variants[0].clone(),
        body.ttl_seconds,
    )
    .unwrap();
    let replay = selected_request(15);
    assert_eq!(selected, replay);
    assert_eq!(
        selected.selection_digest(),
        &Digest::of(b"synthetic-selection-plan")
    );
    assert_eq!(selected.selected_variant_id(), &variants[0]);
    assert_eq!(selected.binding_digest().len(), 64);
    assert!(selected
        .binding_digest()
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        selected.inner().idempotency_key,
        format!("{SELECTED_KEY_PREFIX}{}", selected.binding_digest())
    );
    selected.validate_binding().unwrap();

    let grant = kernel
        .acquire_selected_variant(
            &mut ledger,
            selected.inner(),
            selected.selected_variant_id(),
            NOW,
        )
        .unwrap();
    assert_eq!(grant.attempt.variant_id, variants[0]);
}

#[cfg(feature = "test-seams")]
#[test]
fn selected_wrapper_binding_covers_every_authority_field() {
    let base = selected_request(15);
    let package = base.inner().work_package_id.clone();
    let runner = base.inner().runner_id.clone();
    let variant = base.selected_variant_id().clone();
    let selection = *base.selection_digest();
    let cases = [
        SyntheticSelectedAcquireBody::new(
            Digest::of(b"changed-selection-plan"),
            package.clone(),
            runner.clone(),
            1,
            variant.clone(),
            15,
        )
        .unwrap(),
        SyntheticSelectedAcquireBody::new(
            selection,
            WorkPackageId::from_seed("changed-package"),
            runner.clone(),
            1,
            variant.clone(),
            15,
        )
        .unwrap(),
        SyntheticSelectedAcquireBody::new(
            selection,
            package.clone(),
            RunnerId::from_seed("changed-runner"),
            1,
            variant.clone(),
            15,
        )
        .unwrap(),
        SyntheticSelectedAcquireBody::new(
            selection,
            package.clone(),
            runner.clone(),
            2,
            variant.clone(),
            15,
        )
        .unwrap(),
        SyntheticSelectedAcquireBody::new(
            selection,
            package.clone(),
            runner.clone(),
            1,
            VariantId::from_seed("changed-variant"),
            15,
        )
        .unwrap(),
        SyntheticSelectedAcquireBody::new(selection, package, runner, 1, variant, 14).unwrap(),
    ];
    for changed in cases {
        assert_ne!(changed.binding_digest(), base.binding_digest());
        assert_ne!(
            changed.inner().idempotency_key,
            base.inner().idempotency_key
        );
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn serialized_selected_wrapper_refuses_tampered_fields_and_key() {
    let base = serde_json::to_value(selected_request(15)).unwrap();
    let mut cases = Vec::new();
    for (path, replacement) in [
        ("schema_version", serde_json::json!("v2")),
        (
            "selection_digest",
            serde_json::json!(Digest::of(b"changed").to_hex()),
        ),
        (
            "selected_variant_id",
            serde_json::json!(VariantId::from_seed("changed")),
        ),
        ("binding_digest", serde_json::json!("a".repeat(64))),
    ] {
        let mut changed = base.clone();
        changed[path] = replacement;
        cases.push(changed);
    }
    for (path, replacement) in [
        (
            "work_package_id",
            serde_json::json!(WorkPackageId::from_seed("changed")),
        ),
        (
            "runner_id",
            serde_json::json!(RunnerId::from_seed("changed")),
        ),
        ("runner_epoch", serde_json::json!(2)),
        ("ttl_seconds", serde_json::json!(14)),
        ("idempotency_key", serde_json::json!("caller-selected-key")),
    ] {
        let mut changed = base.clone();
        changed["inner"][path] = replacement;
        cases.push(changed);
    }
    for changed in cases {
        let decoded: SyntheticSelectedAcquireBody = serde_json::from_value(changed).unwrap();
        assert_eq!(
            decoded.validate_binding().unwrap_err().reason_code(),
            "LEASE_TRANSPORT_INVALID"
        );
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn selected_wrapper_refuses_unknown_fields_and_out_of_bounds_subjects() {
    let base = serde_json::to_value(selected_request(15)).unwrap();
    let mut outer = base.clone();
    outer["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SyntheticSelectedAcquireBody>(outer).is_err());
    let mut nested = base;
    nested["inner"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SyntheticSelectedAcquireBody>(nested).is_err());

    let (_, _, body, variants) = fixture();
    for ttl in [0, 16] {
        let error = SyntheticSelectedAcquireBody::new(
            Digest::of(b"selection"),
            body.work_package_id.clone(),
            body.runner_id.clone(),
            body.runner_epoch,
            variants[0].clone(),
            ttl,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), "INVALID_LEASE_TTL");

        let mut serialized = serde_json::to_value(selected_request(15)).unwrap();
        serialized["inner"]["ttl_seconds"] = serde_json::json!(ttl);
        let decoded: SyntheticSelectedAcquireBody = serde_json::from_value(serialized).unwrap();
        assert_eq!(
            decoded.validate_binding().unwrap_err().reason_code(),
            "INVALID_LEASE_TTL"
        );
    }
    for (digest, epoch) in [
        (Digest::from_hex(&"0".repeat(64)).unwrap(), 1),
        (Digest::of(b"selection"), 9_007_199_254_740_992),
    ] {
        let error = SyntheticSelectedAcquireBody::new(
            digest,
            body.work_package_id.clone(),
            body.runner_id.clone(),
            epoch,
            variants[0].clone(),
            15,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), "LEASE_TRANSPORT_INVALID");
    }
}

#[test]
fn ambiguous_acquire_refuses_but_selected_grant_replays_normally() {
    let (mut ledger, kernel, body, variants) = fixture();
    let events = ledger.list_events().unwrap();
    let error = kernel.acquire(&mut ledger, &body, NOW).unwrap_err();
    assert_eq!(error.reason_code(), "STORE_FAILURE");
    assert!(ledger.list_leases().unwrap().is_empty());
    assert_eq!(ledger.list_events().unwrap(), events);
    assert!(ledger.transport_grant_rows_mut().is_empty());

    let first = kernel
        .acquire_selected_variant(&mut ledger, &body, &variants[0], NOW + 1)
        .unwrap();
    assert_eq!(first.attempt.variant_id, variants[0]);
    assert_eq!(first.attempt.fence, 1);
    assert_eq!(kernel.acquire(&mut ledger, &body, NOW + 2).unwrap(), first);
    assert_eq!(kernel.readback(&mut ledger, &body, NOW + 3).unwrap(), first);
    assert_eq!(ledger.list_leases().unwrap().len(), 1);
}

#[test]
fn selection_requires_membership_and_each_lane_gets_fence_one() {
    let (mut ledger, kernel, mut body, variants) = fixture();
    let missing = VariantId::from_seed("not-a-member");
    let error = kernel
        .acquire_selected_variant(&mut ledger, &body, &missing, NOW)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_UNKNOWN");
    let first = kernel
        .acquire_selected_variant(&mut ledger, &body, &variants[0], NOW + 1)
        .unwrap();
    let first_body = body.clone();
    kernel
        .release(
            &mut ledger,
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
            NOW + 2,
        )
        .unwrap();
    let gone = kernel
        .heartbeat(
            &mut ledger,
            &SignedHeartbeatBody {
                work_package_id: first_body.work_package_id.clone(),
                idempotency_key: first_body.idempotency_key.clone(),
                call: HeartbeatRequest {
                    variant_id: first.lease.variant_id.clone(),
                    attempt_id: first.attempt.id.clone(),
                    fence: first.lease.fence,
                    runner_id: first.lease.runner_id.clone(),
                    runner_epoch: first.lease.runner_epoch,
                    workspace_nonce: first.lease.workspace_nonce,
                    ttl_seconds: first.lease.ttl_seconds,
                },
            },
            NOW + 3,
        )
        .unwrap_err();
    assert_eq!(gone.reason_code(), "LEASE_NOT_ACTIVE");
    body.runner_id = RunnerId::from_seed("synthetic-runner-b");
    body.idempotency_key = "synthetic-b".into();
    let second = kernel
        .acquire_selected_variant(&mut ledger, &body, &variants[1], NOW + 4)
        .unwrap();
    assert_ne!(first.attempt.id, second.attempt.id);
    assert_eq!(second.attempt.variant_id, variants[1]);
    assert_eq!((first.attempt.fence, second.attempt.fence), (1, 1));
}

#[test]
fn incarnation_operation_refuses_a_key_not_bound_to_the_attempt_workspace() {
    let (mut ledger, kernel, body, variants) = fixture();
    let grant = kernel
        .acquire_selected_variant(&mut ledger, &body, &variants[0], NOW)
        .unwrap();
    let wrong_key = "different-acquire-key";
    let error = kernel
        .heartbeat(
            &mut ledger,
            &SignedHeartbeatBody {
                work_package_id: body.work_package_id.clone(),
                idempotency_key: wrong_key.into(),
                call: HeartbeatRequest {
                    variant_id: grant.lease.variant_id.clone(),
                    attempt_id: grant.attempt.id.clone(),
                    fence: grant.lease.fence,
                    runner_id: grant.lease.runner_id.clone(),
                    runner_epoch: grant.lease.runner_epoch,
                    workspace_nonce: grant.lease.workspace_nonce,
                    ttl_seconds: grant.lease.ttl_seconds,
                },
            },
            NOW + 1,
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_SUBJECT_MISMATCH");
    let error = kernel
        .advance(
            &mut ledger,
            &SignedAdvanceBody {
                work_package_id: body.work_package_id.clone(),
                runner_id: body.runner_id.clone(),
                runner_epoch: body.runner_epoch,
                idempotency_key: wrong_key.into(),
                attempt_id: grant.attempt.id.clone(),
                state: AttemptState::Running,
            },
            NOW + 2,
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_SUBJECT_MISMATCH");
    let error = kernel
        .release(
            &mut ledger,
            &SignedReleaseBody {
                work_package_id: body.work_package_id,
                runner_id: body.runner_id,
                runner_epoch: body.runner_epoch,
                idempotency_key: wrong_key.into(),
                call: ReleaseRequest {
                    variant_id: grant.lease.variant_id.clone(),
                    attempt_id: grant.attempt.id.clone(),
                    final_state: AttemptState::Failed,
                    requeue: false,
                },
            },
            NOW + 3,
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), "LEASE_TRANSPORT_SUBJECT_MISMATCH");
    assert_eq!(ledger.list_leases().unwrap().len(), 1);
}

#[test]
fn replay_validates_body_and_row_key_before_using_the_recorded_variant() {
    use super::super::mint::idempotency_digest;

    let (mut ledger, kernel, body, variants) = fixture();
    kernel
        .acquire_selected_variant(&mut ledger, &body, &variants[0], NOW)
        .unwrap();

    let mut changed = body.clone();
    changed.runner_id = RunnerId::from_seed("changed-runner");
    for error in [
        kernel.acquire(&mut ledger, &changed, NOW + 1).unwrap_err(),
        kernel
            .acquire_selected_variant(&mut ledger, &body, &variants[1], NOW + 2)
            .unwrap_err(),
    ] {
        assert_eq!(error.reason_code(), "IDEMPOTENCY_CONFLICT");
    }

    let original = idempotency_digest(&body.idempotency_key).unwrap();
    let row = ledger.transport_grant_rows_mut()[&original].clone();
    let mut transplanted = body;
    transplanted.idempotency_key = "transplanted-key".into();
    let target = idempotency_digest(&transplanted.idempotency_key).unwrap();
    ledger.transport_grant_rows_mut().insert(target, row);
    let error = kernel
        .readback(&mut ledger, &transplanted, NOW + 3)
        .unwrap_err();
    assert_eq!(error.reason_code(), "STORE_FAILURE");
}
