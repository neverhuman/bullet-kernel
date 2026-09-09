use super::*;
use serde_json::{json, Value};

fn checkpoint() -> CheckpointBinding {
    CheckpointBinding {
        id: format!("ckp_{}", "3".repeat(64)),
        digest: "4".repeat(64),
    }
}

fn proposal() -> Value {
    json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "create PONG.txt containing PONG",
        "operations": [{
            "path": "PONG.txt",
            "preimage": { "kind": "absent" },
            "mutation": { "kind": "write", "content_utf8": "PONG\n" }
        }],
        "gate_ids": [REPOSITORY_GATE_ID],
        "claims": [],
        "uncertainties": [],
        "done": true
    })
}

fn raw(payload: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "kind": "turn.completed",
        "payload": payload,
    }))
    .expect("event");
    bytes.push(b'\n');
    bytes
}

#[test]
fn exact_terminal_proposal_binds_checkpoint() {
    let bytes = raw(json!({ "proposal": proposal(), "text": "done" }));
    require_raw_proposal(&bytes, &format!("atm_{}", "2".repeat(64)), &checkpoint())
        .expect("exact raw proposal");
}

#[test]
fn checkpoint_drift_and_extra_terminal_fields_refuse() {
    let mut drift = proposal();
    drift["base_checkpoint_digest"] = Value::String("5".repeat(64));
    let drift = raw(json!({ "proposal": drift, "text": "done" }));
    assert!(
        require_raw_proposal(&drift, &format!("atm_{}", "2".repeat(64)), &checkpoint(),).is_err()
    );

    let extra = raw(json!({
        "proposal": proposal(),
        "text": "done",
        "desired_winner": "lane-a"
    }));
    assert!(
        require_raw_proposal(&extra, &format!("atm_{}", "2".repeat(64)), &checkpoint(),).is_err()
    );
}
