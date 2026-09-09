use super::candidate::{
    apply_proposal_params, parse_candidate_receipt, parse_preservation_receipt,
    prepare_candidate_params, require_prefixed, tagged_git_oid, validate_checkpoint_binding,
};
use super::session::{next_request_id, validate_response_envelope};
use super::*;
use bullet_harness_core::{PatchMutation, PatchOperation, PatchProposal, Preimage};
use serde_json::json;
use std::path::Path;

#[test]
fn provider_proposal_is_nested_exactly_once_without_legacy_flattening() {
    let proposal = PatchProposal {
        schema_version: 1,
        proposal_id: format!("cnt_{}", "1".repeat(64)),
        producing_attempt_id: format!("atm_{}", "2".repeat(64)),
        base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
        base_checkpoint_digest: "4".repeat(64),
        operations: vec![PatchOperation {
            path: "PONG.txt".into(),
            preimage: Preimage::Absent,
            mutation: PatchMutation::Write {
                content_utf8: "PONG\n".into(),
            },
        }],
        gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
        intent_summary: "model narrative".into(),
        claims: vec!["not evidence".into()],
        uncertainties: vec![],
        done: true,
    };
    let params = apply_proposal_params(&proposal).unwrap();
    assert_eq!(params.as_object().unwrap().len(), 1);
    let wire = &params["proposal"];
    assert_eq!(wire["operations"][0]["mutation"]["kind"], "write");
    for forbidden in [
        "patches",
        "changes",
        "contents_hex",
        "intent_summary",
        "claims",
        "uncertainties",
        "done",
    ] {
        assert!(params.get(forbidden).is_none());
        assert!(wire.get(forbidden).is_none());
    }
}

#[test]
fn malformed_daemon_checkpoint_bindings_fail_closed() {
    assert!(
        validate_checkpoint_binding(&format!("ckp_{}", "a".repeat(64)), &"b".repeat(64)).is_ok()
    );
    for (id, digest) in [
        (format!("ckp_{}", "A".repeat(64)), "b".repeat(64)),
        (format!("ckp_{}", "a".repeat(63)), "b".repeat(64)),
        (format!("bad_{}", "a".repeat(64)), "b".repeat(64)),
        (format!("ckp_{}", "a".repeat(64)), "b".repeat(63)),
    ] {
        assert!(validate_checkpoint_binding(&id, &digest).is_err());
    }

    assert!(validate_response_envelope(&json!({"id": 1, "ok": {}}), 1, "clone").is_ok());
    for malformed in [
        json!({"ok": {}}),
        json!({"id": 2, "ok": {}}),
        json!({"id": "1", "ok": {}}),
        json!({"id": 1}),
        json!({"id": 1, "ok": {}, "err": {"code": "X"}}),
    ] {
        assert!(validate_response_envelope(&malformed, 1, "clone").is_err());
    }
    assert_eq!(next_request_id(0).unwrap(), 1);
    assert!(next_request_id(u64::MAX).is_err());
}

#[test]
fn prepare_candidate_encodes_change_and_provenance_never_legacy_seeds() {
    let request = PrepareCandidateRequest {
        change: ChangeRequest {
            id: format!("chg_{}", "1".repeat(64)),
            mission: format!("mis_{}", "2".repeat(64)),
            acceptance_root: "3".repeat(64),
        },
        provenance: CandidateProvenanceRequest {
            schema_version: 1,
            repository_id: format!("rep_{}", "4".repeat(64)),
            producing_attempt_id: format!("atm_{}", "5".repeat(64)),
            attempt_fence: 1,
            work_package_id: format!("wpk_{}", "6".repeat(64)),
            variant_id: format!("var_{}", "7".repeat(64)),
            plan_revision_id: format!("pln_{}", "8".repeat(64)),
            graph_revision_id: format!("grf_{}", "9".repeat(64)),
            base_checkpoint_id: format!("ckp_{}", "a".repeat(64)),
            base_commit: format!("sha1:{}", "b".repeat(40)),
            parent_candidate_ids: vec![],
            granted_scope: vec!["src".into()],
            context_capsule_id: format!("cnt_{}", "c".repeat(64)),
            configuration_snapshot_id: format!("cnt_{}", "d".repeat(64)),
            policy_snapshot_id: format!("cnt_{}", "e".repeat(64)),
            routing_snapshot_id: format!("cnt_{}", "f".repeat(64)),
            environment_digest: "1".repeat(64),
            toolchain_digest: "2".repeat(64),
        },
        candidate_preparation_grant: bullet_harness_core::SignedCandidatePreparationGrantV1 {
            schema_version: "v1alpha1".into(),
            issuer: "kernel-local".into(),
            key_id: "candidate-preparation-1".into(),
            paseto: "v4.public.test-carrier".into(),
        },
    };
    let params = prepare_candidate_params(&request).expect("encode");
    assert!(params.get("change_seed").is_none());
    assert!(params.get("mission").is_none());
    assert_eq!(params["change"]["id"], request.change.id);
    assert_eq!(
        params["provenance"]["producing_attempt_id"],
        request.provenance.producing_attempt_id
    );
    assert_eq!(
        params["candidate_preparation_grant"]["key_id"],
        "candidate-preparation-1"
    );
    assert_eq!(params.as_object().map(|object| object.len()), Some(3));
}

#[test]
fn nested_candidate_receipt_is_required_and_legacy_flat_shape_is_refused() {
    let ok = json!({
        "id": format!("can_{}", "1".repeat(64)),
        "content_id": format!("cnt_{}", "2".repeat(64)),
        "prepared_at": "2026-08-25T00:00:00Z",
        "manifest": {
            "base_commit": format!("sha1:{}", "a".repeat(40)),
            "head_commit": format!("sha1:{}", "b".repeat(40)),
            "tree_oid": format!("sha1:{}", "c".repeat(40)),
            "patch_digest": "d".repeat(64),
            "actual_scope": ["src/lib.rs"]
        }
    });
    let receipt = parse_candidate_receipt(ok).expect("nested");
    assert_eq!(receipt.tree_hash, format!("sha1:{}", "c".repeat(40)));
    assert_eq!(receipt.actual_scope, vec!["src/lib.rs"]);

    let legacy = json!({
        "id": format!("can_{}", "1".repeat(64)),
        "base_commit": "a".repeat(40),
        "head_commit": "b".repeat(40),
        "tree_hash": "c".repeat(40),
        "patch_hash": "d".repeat(64),
        "change_seed": "atm_x",
        "mission": "synthetic"
    });
    assert!(parse_candidate_receipt(legacy).is_err());
}

#[test]
fn cleanup_and_preserve_refuse_bundle_path_and_require_sealed_token() {
    let preserve = json!({
        "preservation_receipt": "sealed-token",
        "preservation_receipt_digest": "a".repeat(64),
        "artifact_digest": "b".repeat(64),
        "destination": "/tmp/preserve"
    });
    let receipt = parse_preservation_receipt(preserve, Path::new("/tmp/preserve")).expect("ok");
    assert_eq!(receipt.token, "sealed-token");

    let legacy = json!({"bundle_path": "/tmp/bundle"});
    assert!(parse_preservation_receipt(legacy, Path::new("/tmp/x")).is_err());
}

#[test]
fn malformed_candidate_subjects_are_refused_instead_of_synthesized() {
    assert!(require_prefixed("change_id", "chg", "").is_err());
    assert!(require_prefixed("graph_revision_id", "grf", "").is_err());
    assert_eq!(
        tagged_git_oid(&"a".repeat(40)).unwrap(),
        format!("sha1:{}", "a".repeat(40))
    );
}
