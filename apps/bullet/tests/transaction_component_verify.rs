#![cfg(target_os = "linux")]

use bullet_harness_core::transaction_proof::{
    SignedTransactionComponent, TransactionComponentSigningKey, TransactionComponentSubject,
    TRANSACTION_COMPONENT_CLASS, TRANSACTION_COMPONENT_SCHEMA_VERSION, TRANSACTION_COMPONENT_TRUST,
};
use serde_json::{json, Value};
use std::fs::{hard_link, write};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output};

const MAX_RECEIPT_BYTES: usize = 1024 * 1024;

#[test]
fn component_receipt_verifier_is_bounded_strict_and_never_promotes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let receipt = directory.path().join("component.json");
    let proof = signed_component();
    write_receipt(&receipt, &proof);

    let verified = invoke(&receipt, None);
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert!(verified.stderr.is_empty());
    let observation: Value = serde_json::from_slice(&verified.stdout).expect("observation JSON");
    let object = observation.as_object().expect("observation object");
    assert_eq!(object.len(), 7, "no release-shaped fields may appear");
    assert_eq!(observation["evidence_class"], "COMPONENT_PROOF");
    assert_eq!(
        observation["component_signing_trust"],
        "EPHEMERAL_SELF_SIGNED"
    );
    assert_eq!(observation["verification_trust"], "UNSIGNED_DIAGNOSTIC");
    assert_eq!(observation["integrity"], "VERIFIED");
    assert_eq!(observation["transaction_gate_eligible"], false);
    assert_eq!(observation["release_profile_eligible"], false);
    let digest = observation["subject_digest"].as_str().expect("digest");
    assert!(digest.starts_with("blake3:"));
    assert_eq!(digest.len(), 71);
    for forbidden in [
        "gate_id",
        "gate_outcome",
        "profile",
        "evidence",
        "proof_bundle",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "forbidden field {forbidden}"
        );
    }

    let missing_json = Command::new(env!("CARGO_BIN_EXE_transaction_component_verify"))
        .args(["--receipt"])
        .arg(&receipt)
        .output()
        .expect("missing-json process");
    assert_refused(missing_json);
    let unknown_option = Command::new(env!("CARGO_BIN_EXE_transaction_component_verify"))
        .args(["--receipt"])
        .arg(&receipt)
        .args(["--json", "--profile", "self-hosted-v1"])
        .output()
        .expect("unknown-option process");
    assert_refused(unknown_option);

    let relative = invoke(Path::new("component.json"), Some(directory.path()));
    assert_refused(relative);
    let dotted = directory.path().join("nested/../component.json");
    std::fs::create_dir(directory.path().join("nested")).expect("nested");
    assert_refused(invoke(&dotted, None));

    let link = directory.path().join("component-link.json");
    symlink(&receipt, &link).expect("symlink");
    assert_refused(invoke(&link, None));
    let linked_parent = directory.path().join("linked-parent");
    symlink(directory.path(), &linked_parent).expect("parent symlink");
    assert_refused(invoke(&linked_parent.join("component.json"), None));
    let hard = directory.path().join("component-hard.json");
    hard_link(&receipt, &hard).expect("hardlink");
    assert_refused(invoke(&receipt, None));
    std::fs::remove_file(&hard).expect("remove hardlink");

    let empty = directory.path().join("empty.json");
    write(&empty, []).expect("empty");
    assert_refused(invoke(&empty, None));
    let directory_path = directory.path().join("not-regular");
    std::fs::create_dir(&directory_path).expect("directory fixture");
    assert_refused(invoke(&directory_path, None));
    let oversized = directory.path().join("oversized.json");
    write(&oversized, vec![b'x'; MAX_RECEIPT_BYTES + 1]).expect("oversized");
    assert_refused(invoke(&oversized, None));

    for (name, bytes) in json_hostiles(&proof) {
        let path = directory.path().join(name);
        write(&path, bytes).expect("hostile JSON");
        assert_refused(invoke(&path, None));
    }

    for (name, value) in semantic_hostiles(&proof) {
        let path = directory.path().join(name);
        write(
            &path,
            serde_json::to_vec_pretty(&value).expect("hostile encode"),
        )
        .expect("hostile receipt");
        assert_refused(invoke(&path, None));
    }
}

fn signed_component() -> SignedTransactionComponent {
    let subject = TransactionComponentSubject {
        schema_version: TRANSACTION_COMPONENT_SCHEMA_VERSION.into(),
        evidence_class: TRANSACTION_COMPONENT_CLASS.into(),
        signing_trust: TRANSACTION_COMPONENT_TRUST.into(),
        transaction_gate_eligible: false,
        fence_first: 41,
        fence_second: 42,
        attempt_first: "atm_component_first".into(),
        attempt_second: "atm_component_second".into(),
        candidate_id: "can_component".into(),
        verifier_outcome: "FAIL".into(),
        writer_proof_refused: true,
        effect_unknown: "OUTCOME_UNKNOWN".into(),
        effect_settled: "COMMITTED".into(),
        stale_refused: true,
        gitd_fixture: true,
        command_id: "cmd_component".into(),
        command_phase: "pending".into(),
    };
    TransactionComponentSigningKey::generate("kernel-demo", "txn-component-1")
        .expect("signing key")
        .sign(&subject)
        .expect("signed component")
}

fn write_receipt(path: &Path, proof: &SignedTransactionComponent) {
    write(
        path,
        serde_json::to_vec_pretty(proof).expect("receipt encode"),
    )
    .expect("receipt write");
}

fn invoke(receipt: &Path, current_dir: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_transaction_component_verify"));
    command.args(["--receipt"]).arg(receipt).arg("--json");
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    command.output().expect("verifier process")
}

fn assert_refused(output: Output) {
    assert!(!output.status.success(), "unexpected success");
    assert!(output.stdout.is_empty(), "refusal wrote stdout");
    let frame: Value = serde_json::from_slice(&output.stderr).expect("typed refusal");
    assert_eq!(
        frame["reason_code"],
        "TRANSACTION_COMPONENT_RECEIPT_REFUSED",
        "{}",
        stderr(&output)
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json_hostiles(proof: &SignedTransactionComponent) -> Vec<(String, Vec<u8>)> {
    let compact = serde_json::to_string(proof).expect("compact receipt");
    let duplicate = compact.replacen('{', "{\"schema_version\":\"v1alpha1\",", 1);
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(compact.as_bytes());
    vec![
        ("duplicate.json".into(), duplicate.into_bytes()),
        (
            "trailing.json".into(),
            format!("{compact}{{}}").into_bytes(),
        ),
        ("bom.json".into(), bom),
        ("malformed.json".into(), b"{\"schema_version\":".to_vec()),
    ]
}

fn semantic_hostiles(proof: &SignedTransactionComponent) -> Vec<(String, Value)> {
    let original = serde_json::to_value(proof).expect("receipt value");
    let mut cases = Vec::new();
    cases.push(mutate(&original, "unknown.json", |value| {
        value["unexpected"] = json!(true);
    }));
    cases.push(mutate(&original, "schema.json", |value| {
        value["schema_version"] = json!("v2");
    }));
    cases.push(mutate(&original, "envelope-class.json", |value| {
        value["evidence_class"] = json!("TRANSACTION_PROOF");
    }));
    cases.push(mutate(&original, "issuer-footer.json", |value| {
        value["issuer"] = json!("different-issuer");
    }));
    cases.push(mutate(&original, "issuer-label.json", |value| {
        value["issuer"] = json!("invalid issuer label");
    }));
    cases.push(mutate(&original, "key-label.json", |value| {
        value["key_id"] = json!("invalid key label");
    }));
    cases.push(mutate(&original, "public-key-uppercase.json", |value| {
        let public = value["public_hex"].as_str().expect("public key");
        value["public_hex"] = json!(public.to_ascii_uppercase());
    }));
    cases.push(mutate(&original, "public-key.json", |value| {
        value["public_hex"] = json!("00".repeat(32));
    }));
    cases.push(mutate(&original, "paseto.json", |value| {
        let token = value["paseto"].as_str().expect("token");
        value["paseto"] = json!(format!("{token}a"));
    }));
    cases.push(mutate(&original, "subject-class.json", |value| {
        value["subject"]["evidence_class"] = json!("TRANSACTION_PROOF");
    }));
    cases.push(mutate(&original, "subject-trust.json", |value| {
        value["subject"]["signing_trust"] = json!("EXTERNAL_TRUST_ROOT");
    }));
    cases.push(mutate(&original, "gate-promotion.json", |value| {
        value["subject"]["transaction_gate_eligible"] = json!(true);
    }));
    cases.push(mutate(&original, "painted-success.json", |value| {
        value["subject"]["command_phase"] = json!("verified");
    }));
    cases
}

fn mutate(original: &Value, name: &str, change: impl FnOnce(&mut Value)) -> (String, Value) {
    let mut value = original.clone();
    change(&mut value);
    (name.into(), value)
}
