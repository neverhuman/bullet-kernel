use super::*;
use bullet_harness_core::{PatchMutation, PatchOperation, PatchProposal, Preimage};

fn bound_capsule() -> Capsule {
    Capsule {
        objective: "test".into(),
        scope_prefixes: vec!["PONG.txt".into()],
        base_sha: "a".repeat(40),
        producing_attempt_id: format!("atm_{}", "2".repeat(64)),
        base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
        base_checkpoint_digest: "4".repeat(64),
        admitted_gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
    }
}

fn proposal() -> PatchProposal {
    let capsule = bound_capsule();
    PatchProposal {
        schema_version: 1,
        proposal_id: format!("cnt_{}", "1".repeat(64)),
        producing_attempt_id: capsule.producing_attempt_id,
        base_checkpoint_id: capsule.base_checkpoint_id,
        base_checkpoint_digest: capsule.base_checkpoint_digest,
        operations: vec![PatchOperation {
            path: "PONG.txt".into(),
            preimage: Preimage::Absent,
            mutation: PatchMutation::Write {
                content_utf8: "PONG\n".into(),
            },
        }],
        gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
        intent_summary: String::new(),
        claims: vec![],
        uncertainties: vec![],
        done: true,
    }
}

#[test]
fn stale_binding_is_refused_before_the_workspace_port() {
    let capsule = bound_capsule();
    let mut stale = proposal();
    stale.base_checkpoint_digest = "5".repeat(64);
    let refusal = pre_apply_refusal(&capsule, &stale).expect("binding refusal");
    assert_eq!(refusal.stage, "proposal_binding_refused");
    assert!(refusal.prompt.contains("Nothing was applied"));
}

#[test]
fn exact_binding_and_sealed_gate_reach_the_workspace_boundary() {
    assert!(pre_apply_refusal(&bound_capsule(), &proposal()).is_none());
    let mut wrong_gate = proposal();
    wrong_gate.gate_ids = vec![format!("gat_{}", "7".repeat(64))];
    assert_eq!(
        pre_apply_refusal(&bound_capsule(), &wrong_gate)
            .expect("gate refusal")
            .stage,
        "gate_selection_refused"
    );
}

#[test]
fn product_authority_guard_precedes_gitd_workspace_startup() {
    let source = include_str!("../attempt.rs");
    let guard = source
        .find("let heartbeat = match begin_attempt_heartbeat")
        .expect("product Attempt starts its authority guard");
    let gitd = source
        .find("let mut gitd = match GitdSession::spawn")
        .expect("product Attempt has an admitted Gitd boundary");
    assert!(
        guard < gitd,
        "the monotonic self-kill/heartbeat guard must start before Gitd"
    );
}
