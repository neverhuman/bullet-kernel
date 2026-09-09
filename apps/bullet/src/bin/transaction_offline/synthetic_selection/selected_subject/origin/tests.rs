use super::*;
use bullet_domain::{Attempt, AttemptState};
use serde_json::json;

const PLAN_DIGEST: &str = "4a1cfc34791033f74f6a1062446db556dc1d97828566173bd64499d3b2bfa3d7";

struct Fixture {
    bytes: Vec<u8>,
    selected: SelectedCandidateSubject,
}

#[test]
fn retained_origin_refuses_rebound_handle_and_unknown_nested_field() {
    let fixture = fixture();
    fixture
        .selected
        .validate_origin_receipt(&fixture.bytes)
        .expect("exact retained origin");

    let mut rebound_envelope: Value = decode_canonical(&fixture.bytes).expect("decode fixture");
    let other_handle = rebound_envelope["body"]["selection"]["blinded_views"]
        .as_array()
        .unwrap()
        .iter()
        .map(|view| view["blinded_handle"].as_str().unwrap())
        .find(|handle| *handle != fixture.selected.selection.selected_handle)
        .unwrap()
        .to_owned();
    rebound_envelope["body"]["selection"]["decision"]["selected_handle"] =
        json!(other_handle.clone());
    let (rebound_bytes, rebound_body) = recanonicalize(rebound_envelope);
    let mut rebound = fixture.selected.clone();
    rebound.selection.receipt_digest = hash_framed_bytes(RECEIPT_DOMAIN, &rebound_bytes).unwrap();
    rebound.selection.body_digest = rebound_body;
    rebound.selection.selected_handle = other_handle;
    assert!(rebound.validate().is_ok());
    assert!(rebound.validate_origin_receipt(&rebound_bytes).is_err());

    let mut unknown_envelope: Value = decode_canonical(&fixture.bytes).expect("decode fixture");
    unknown_envelope["body"]["simulator"]["unknown"] = json!(false);
    let (unknown_bytes, unknown_body) = recanonicalize(unknown_envelope);
    let mut unknown = fixture.selected.clone();
    unknown.selection.receipt_digest = hash_framed_bytes(RECEIPT_DOMAIN, &unknown_bytes).unwrap();
    unknown.selection.body_digest = unknown_body;
    assert!(unknown.validate().is_ok());
    assert!(unknown.validate_origin_receipt(&unknown_bytes).is_err());

    let mut duplicate_envelope: Value = decode_canonical(&fixture.bytes).expect("decode fixture");
    let first = duplicate_envelope["body"]["selection"]["unblinding"][0].clone();
    duplicate_envelope["body"]["selection"]["unblinding"][1] = first;
    let (duplicate_bytes, duplicate_body) = recanonicalize(duplicate_envelope);
    let mut duplicate = fixture.selected;
    duplicate.selection.receipt_digest =
        hash_framed_bytes(RECEIPT_DOMAIN, &duplicate_bytes).unwrap();
    duplicate.selection.body_digest = duplicate_body;
    assert!(duplicate.validate().is_ok());
    assert!(duplicate.validate_origin_receipt(&duplicate_bytes).is_err());
}

fn fixture() -> Fixture {
    let lanes = fixed_lanes();
    let salt = [7_u8; 32];
    let views_by_lane = [view(&lanes[0], &salt), view(&lanes[1], &salt)];
    let mut blinded_views = views_by_lane.to_vec();
    blinded_views.sort_by(|left, right| left.blinded_handle.cmp(&right.blinded_handle));
    let decision = select_exact_pair(views_by_lane.clone()).expect("selection");
    let mut unblinding = lanes
        .iter()
        .zip(views_by_lane.iter())
        .map(|(lane, view)| {
            json!({
                "blinded_handle": view.blinded_handle,
                "candidate_id": lane.candidate.id,
                "binding_digest": unblinding_digest(
                    &salt,
                    &view.blinded_handle,
                    lane.candidate.id.as_str(),
                ).unwrap(),
            })
        })
        .collect::<Vec<_>>();
    unblinding.sort_by(|left, right| {
        left["blinded_handle"]
            .as_str()
            .cmp(&right["blinded_handle"].as_str())
    });
    let selected_candidate_id = lanes
        .iter()
        .zip(views_by_lane.iter())
        .find(|(_, view)| view.blinded_handle == decision.selected_handle)
        .map(|(lane, _)| lane.candidate.id.to_string())
        .unwrap();
    let authority = &lanes[0].authority;
    let body = json!({
        "evidence_class": "COMPONENT_PROOF",
        "signing_trust": "UNSIGNED_FIXTURE",
        "execution_schedule": "SEQUENTIAL",
        "simulator": {
            "provider": "sim", "version": bullet_harness_sim::SIM_VERSION,
            "live_credentials_used": false, "external_effects": false,
        },
        "shared": {
            "plan_digest": PLAN_DIGEST,
            "mission_id": authority.mission_id,
            "plan_revision_id": authority.plan_revision_id,
            "repository_id": authority.repository_id,
            "work_package_id": authority.work_package_id,
            "selection_group_id": authority.selection_group_id,
            "base_oid": lanes[0].candidate.base_sha,
            "scope_paths": ["PONG.txt"], "gate_ids": [REPOSITORY_GATE_ID],
        },
        "selection": {
            "decision": decision,
            "input_digest": hash_canonical("bullet.synthetic-selection.input.v1", &blinded_views).unwrap(),
            "blinded_views": blinded_views,
            "selected_candidate_id": selected_candidate_id,
            "revealed_run_salt": lower_hex(&salt),
            "unblinding": unblinding,
        },
        "lanes": [lane_receipt(&lanes[0], 0), lane_receipt(&lanes[1], 1)],
        "eligibility": {
            "team_recipe_eligible": false, "evolution_profile_eligible": false,
            "provider_certification_eligible": false, "independent_evidence_eligible": false,
            "transaction_gate_eligible": false, "release_gate_eligible": false,
            "live_eligible": false, "routing_activation_eligible": false,
            "comparative_claim_eligible": false,
        },
    });
    let body_bytes = canonical_json(&body).unwrap();
    let envelope = json!({
        "schema_version": RECEIPT_SCHEMA,
        "body_digest": hash_framed_bytes(BODY_DOMAIN, &body_bytes).unwrap(),
        "body": body,
    });
    let bytes = canonical_json(&envelope).unwrap();
    let selected = seal_facts(&bytes, lanes).expect("seal fixture");
    Fixture { bytes, selected }
}

fn fixed_lanes() -> [LaneFacts; 2] {
    let mut variants = [
        VariantId::from_seed("df-dog1-two-lane:synthetic-selection:0"),
        VariantId::from_seed("df-dog1-two-lane:synthetic-selection:1"),
    ];
    variants.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    std::array::from_fn(|index| {
        let runner = RunnerId::from_seed(if index == 0 {
            "df-dog1-runner-a"
        } else {
            "df-dog1-runner-b"
        });
        let package = WorkPackageId::from_seed("df-dog1-two-lane:wp:0");
        let acquire = SyntheticSelectedAcquireBody::new(
            Digest::from_hex(PLAN_DIGEST).unwrap(),
            package.clone(),
            runner.clone(),
            1,
            variants[index].clone(),
            15,
        )
        .unwrap();
        let attempt_id = AttemptId::from_seed(&acquire.inner().idempotency_key);
        let (workspace_id, workspace_nonce) = workspace_for_key(&acquire.inner().idempotency_key);
        let attempt = Attempt {
            id: attempt_id.clone(),
            variant_id: variants[index].clone(),
            work_package_id: package.clone(),
            fence: 1,
            runner_id: runner.clone(),
            runner_epoch: 1,
            workspace_id: workspace_id.clone(),
            workspace_nonce,
            scope_revision: 1,
            context_revision: 1,
            state: AttemptState::Superseded,
        };
        let authority = AuthorityToken {
            organization_id: OrganizationId::from_seed("df-dog1-two-lane"),
            repository_id: RepositoryId::from_seed("df-dog1-two-lane"),
            mission_id: MissionId::from_seed("df-dog1-two-lane"),
            acceptance_contract_id: AcceptanceContractId::from_seed("df-dog1-two-lane"),
            plan_revision_id: PlanRevisionId::from_seed("df-dog1-two-lane"),
            graph_sequence: 1,
            work_package_id: package,
            selection_group_id: SelectionGroupId::from_seed("df-dog1-two-lane:synthetic-selection"),
            variant_id: variants[index].clone(),
            attempt_id,
            attempt_fence: 1,
            runner_id: runner,
            runner_epoch: 1,
            workspace_id,
            workspace_nonce,
            scope_revision: 1,
            context_revision: 1,
            config_snapshot_hash: Digest::of(b"cfg"),
            policy_snapshot_hash: Digest::of(b"pol"),
            routing_policy_hash: Digest::of(b"route"),
            credential_profile_id: None,
            credential_generation: None,
        };
        LaneFacts {
            variant_id: variants[index].to_string(),
            attempt: attempt.clone(),
            authority,
            candidate: Candidate {
                id: CandidateId::from_seed(&format!("origin-candidate-{index}")),
                attempt_id: attempt.id,
                base_sha: format!("sha1:{}", "1".repeat(40)),
                head_sha: format!("sha1:{}", if index == 0 { "2" } else { "3" }.repeat(40)),
                tree_sha: format!("sha1:{}", if index == 0 { "4" } else { "5" }.repeat(40)),
                patch_digest: Digest::of(format!("patch-{index}").as_bytes()),
            },
            repository: PathBuf::from(format!("/tmp/lane-{index}/repository")),
        }
    })
}

fn lane_receipt(lane: &LaneFacts, index: usize) -> Value {
    let acquire = SyntheticSelectedAcquireBody::new(
        Digest::from_hex(PLAN_DIGEST).unwrap(),
        lane.attempt.work_package_id.clone(),
        lane.attempt.runner_id.clone(),
        1,
        lane.attempt.variant_id.clone(),
        15,
    )
    .unwrap();
    let acquire_digest = acquire.inner().request_digest().unwrap();
    let release = LeaseSettlementRequest::Release(ReleaseSettlementRequest {
        acquire_request_digest: acquire_digest.clone(),
        work_package_id: lane.attempt.work_package_id.clone(),
        runner_id: lane.attempt.runner_id.clone(),
        runner_epoch: 1,
        idempotency_key: acquire.inner().idempotency_key.clone(),
        variant_id: lane.attempt.variant_id.clone(),
        attempt_id: lane.attempt.id.clone(),
        attempt_fence: 1,
        expected_state: AttemptState::Preparing,
        final_state: AttemptState::Superseded,
        requeue: true,
    });
    let release_digest = release.digest().unwrap();
    json!({
        "runner_id": lane.attempt.runner_id, "runner_epoch": 1,
        "variant_id": lane.attempt.variant_id, "attempt_id": lane.attempt.id,
        "attempt_fence": 1, "workspace_id": lane.attempt.workspace_id,
        "authority_digest": lane.authority.digest().unwrap().to_hex(),
        "candidate_id": lane.candidate.id,
        "candidate_base_oid": lane.candidate.base_sha,
        "candidate_head_oid": lane.candidate.head_sha,
        "candidate_tree_oid": lane.candidate.tree_sha,
        "candidate_patch_blake3": lane.candidate.patch_digest.to_hex(),
        "candidate_row_digest": hash_canonical(
            "bullet.synthetic-selection.candidate-row.v1", &lane.candidate,
        ).unwrap(),
        "repository_relative": format!("lane-{index}/repository"),
        "raw_artifact_relative": format!("lane-{index}/raw.json"),
        "raw_artifact_blake3": Digest::of(format!("raw-{index}").as_bytes()).to_hex(),
        "journal_relative": format!("lane-{index}/journal.jsonl"),
        "journal_blake3": Digest::of(format!("journal-{index}").as_bytes()).to_hex(),
        "recovery_relative": format!("data/lane-{index}-recovery.json"),
        "recovery_blake3": Digest::of(format!("recovery-{index}").as_bytes()).to_hex(),
        "acquire_request_digest": acquire_digest,
        "settlement_id": format!("lts_{release_digest}"),
        "settlement_request_digest": release_digest,
        "terminal_state": "Superseded", "requeue": true,
    })
}

fn view(lane: &LaneFacts, salt: &[u8; 32]) -> BlindedCandidateView {
    super::super::super::selector::blinded_view(
        salt,
        lane.candidate.id.as_str(),
        lane.candidate.base_sha.clone(),
        lane.candidate.head_sha.clone(),
        lane.candidate.tree_sha.clone(),
        lane.candidate.patch_digest.to_hex(),
        vec![REPOSITORY_GATE_ID.into()],
        true,
    )
    .unwrap()
}

fn recanonicalize(mut envelope: Value) -> (Vec<u8>, String) {
    let body = canonical_json(&envelope["body"]).unwrap();
    let body_digest = hash_framed_bytes(BODY_DOMAIN, &body).unwrap();
    envelope["body_digest"] = json!(body_digest.clone());
    (canonical_json(&envelope).unwrap(), body_digest)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
