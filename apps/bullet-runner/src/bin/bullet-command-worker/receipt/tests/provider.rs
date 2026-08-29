//! Simulator-provider receipt and retained-transcript hostiles.

use super::*;

pub(super) fn fixture(artifacts: &Path, attempt: &str) -> Value {
    let directory = artifacts.join("provider-artifacts");
    private_dir(&directory);
    let session_id = format!("cnt_{}", Digest::of(attempt.as_bytes()).to_hex());
    let proposal_id = format!("cnt_{}", "8".repeat(64));
    let checkpoint_id = format!("ckp_{}", "9".repeat(64));
    let checkpoint_digest = "a".repeat(64);
    let proposal = json!({
        "schema_version":1,"proposal_id":proposal_id,"producing_attempt_id":attempt,
        "base_checkpoint_id":checkpoint_id,"base_checkpoint_digest":checkpoint_digest,
        "operations":[{"path":"f","preimage":{"kind":"digest","digest":Digest::of(b"base\n").to_hex()},
            "mutation":{"kind":"write","content_utf8":"head\n"}}],
        "gate_ids":[REPOSITORY_GATE_ID],"intent_summary":"fixture","claims":[],
        "uncertainties":[],"done":true
    });
    let raw = format!(
        "{}\n",
        json!({"kind":"turn.completed","payload":{"proposal":proposal,"text":"done"}})
    );
    let relative = format!("artifacts/provider-artifacts/{session_id}.raw.jsonl");
    let path = artifacts.parent().unwrap().join(&relative);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(raw.as_bytes()).unwrap();
    json!({
        "adapter":"sim","version":bullet_harness_sim::SIM_VERSION,"session_id":session_id,
        "proposal_id":proposal_id,"producing_attempt_id":attempt,
        "base_checkpoint_id":checkpoint_id,"base_checkpoint_digest":checkpoint_digest,
        "gate_ids":[REPOSITORY_GATE_ID],"raw_artifact_relative":relative,
        "raw_artifact_blake3":Digest::of(raw.as_bytes()).to_hex(),"credential_free":true,
        "transaction_gate_eligible":false
    })
}

#[tokio::test]
async fn provider_record_and_raw_transcript_are_closed_and_subject_exact() {
    let fixture = Fixture::new(false).await;
    for (pointer, replacement) in [
        ("/provider_execution/adapter", json!("claude")),
        ("/provider_execution/credential_free", json!(false)),
        ("/provider_execution/transaction_gate_eligible", json!(true)),
        (
            "/provider_execution/session_id",
            json!(format!("cnt_{}", "b".repeat(64))),
        ),
        (
            "/provider_execution/proposal_id",
            json!(format!("cnt_{}", "c".repeat(64))),
        ),
        (
            "/provider_execution/producing_attempt_id",
            fixture.value["attempt_second"].clone(),
        ),
        ("/provider_execution/gate_ids", json!([])),
        (
            "/provider_execution/raw_artifact_relative",
            json!("artifacts/source/f"),
        ),
    ] {
        let mut value = fixture.value.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        fixture.rewrite(&value);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID"
        );
    }
    let mut value = fixture.value.clone();
    value["provider_execution"]["unknown"] = json!(true);
    fixture.rewrite(&value);
    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );
}

#[tokio::test]
async fn provider_transcript_drift_truncation_open_shape_and_symlink_refuse() {
    for mutation in ["subject", "truncated", "open"] {
        let fixture = Fixture::new(false).await;
        let relative = fixture.value["provider_execution"]["raw_artifact_relative"]
            .as_str()
            .unwrap();
        let path = fixture.run.join(relative);
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut event: Value = serde_json::from_str(raw.trim_end()).unwrap();
        let bytes = match mutation {
            "subject" => {
                event["payload"]["proposal"]["proposal_id"] =
                    json!(format!("cnt_{}", "d".repeat(64)));
                format!("{event}\n").into_bytes()
            }
            "open" => {
                event["unknown"] = json!(true);
                format!("{event}\n").into_bytes()
            }
            _ => raw.trim_end_matches('\n').as_bytes().to_vec(),
        };
        std::fs::write(&path, &bytes).unwrap();
        let mut value = fixture.value.clone();
        value["provider_execution"]["raw_artifact_blake3"] = json!(Digest::of(&bytes).to_hex());
        fixture.rewrite(&value);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID"
        );
    }

    let fixture = Fixture::new(false).await;
    let relative = fixture.value["provider_execution"]["raw_artifact_relative"]
        .as_str()
        .unwrap();
    let path = fixture.run.join(relative);
    let replacement = path.with_extension("replacement");
    std::fs::rename(&path, &replacement).unwrap();
    std::os::unix::fs::symlink(&replacement, &path).unwrap();
    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );
}

#[tokio::test]
async fn self_consistent_provider_operation_substitutions_refuse() {
    for (pointer, replacement) in [
        (
            "/payload/proposal/operations/0/mutation/content_utf8",
            json!("other\n"),
        ),
        ("/payload/proposal/operations/0/path", json!("PONG.txt")),
        (
            "/payload/proposal/operations/0/preimage/digest",
            json!("0".repeat(64)),
        ),
        (
            "/payload/proposal/operations/0/mutation",
            json!({"kind":"delete"}),
        ),
    ] {
        let fixture = Fixture::new(false).await;
        let relative = fixture.value["provider_execution"]["raw_artifact_relative"]
            .as_str()
            .unwrap();
        let path = fixture.run.join(relative);
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut event: Value = serde_json::from_str(raw.trim_end()).unwrap();
        *event.pointer_mut(pointer).unwrap() = replacement;
        let bytes = format!("{event}\n").into_bytes();
        std::fs::write(&path, &bytes).unwrap();
        let mut value = fixture.value.clone();
        value["provider_execution"]["raw_artifact_blake3"] = json!(Digest::of(&bytes).to_hex());
        fixture.rewrite(&value);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID"
        );
    }
}
