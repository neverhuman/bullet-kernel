//! Exact Candidate-lineage admission hostiles.

use super::*;
use serde_json::json;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Eq, PartialEq)]
struct ArtifactEntry {
    path: String,
    mode: u32,
    device: u64,
    inode: u64,
    links: u64,
    contents: Vec<u8>,
}

#[tokio::test]
async fn syntactically_valid_candidate_mismatch_refuses_without_artifact_mutation() {
    let fixture = Fixture::new(false).await;
    let before = artifact_snapshot(&fixture);
    let mut value = fixture.value.clone();
    value["product_runner_candidate_id"] =
        json!(CandidateId::from_seed("different-product-runner-candidate"));
    fixture.rewrite(&value);

    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );
    assert_eq!(artifact_snapshot(&fixture), before);
}

#[tokio::test]
async fn preservation_subject_substitutions_refuse_without_artifact_mutation() {
    let fixture = Fixture::new(false).await;
    for (field, replacement) in [
        (
            "candidate_id",
            json!(CandidateId::from_seed("other-preserved")),
        ),
        ("attempt_id", json!(format!("atm_{}", "d".repeat(64)))),
        ("fence", json!(9)),
        ("head_commit", json!(format!("sha1:{}", "e".repeat(40)))),
        ("tree_hash", json!(format!("sha1:{}", "f".repeat(40)))),
        ("patch_hash", json!("0".repeat(64))),
    ] {
        let before = artifact_snapshot(&fixture);
        let mut value = fixture.value.clone();
        value["product_runner_preservation"][field] = replacement;
        fixture.rewrite(&value);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID",
            "accepted substituted preservation {field}"
        );
        assert_eq!(artifact_snapshot(&fixture), before, "mutated {field}");
    }
}

#[tokio::test]
async fn preservation_receipt_substitution_and_unknown_field_refuse() {
    let fixture = Fixture::new(false).await;
    for field in ["destination", "digest", "artifact_digest", "unknown"] {
        let mut value = fixture.value.clone();
        value["product_runner_preservation"]["receipt"][field] = match field {
            "destination" => json!(fixture.run.join("artifacts/source")),
            "unknown" => json!(true),
            _ => json!("0".repeat(64)),
        };
        fixture.rewrite(&value);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID",
            "accepted substituted preservation receipt {field}"
        );
    }
}

#[tokio::test]
async fn preservation_token_state_artifact_and_cleanup_substitutions_refuse() {
    for (field, replacement) in [
        ("tag", "f".repeat(64)),
        ("state_digest", "0".repeat(64)),
        ("artifact_digest", "1".repeat(64)),
        ("cleanup_target", "/tmp/substituted-cleanup-target".into()),
    ] {
        let fixture = Fixture::new(false).await;
        let before = artifact_snapshot(&fixture);
        let mut value = fixture.value.clone();
        preservation_fixture::substitute_token(&mut value, field, &replacement);
        fixture.rewrite(&value);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID",
            "accepted substituted preservation token {field}"
        );
        assert_eq!(artifact_snapshot(&fixture), before);
    }
}

#[tokio::test]
async fn retained_state_and_artifact_byte_substitutions_refuse() {
    let fixture = Fixture::new(false).await;
    preservation_fixture::substitute_state(&fixture.run.join("artifacts/preserve"));
    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );

    let fixture = Fixture::new(false).await;
    let mut bundle = std::fs::OpenOptions::new()
        .append(true)
        .open(fixture.run.join("artifacts/preserve/repository.bundle"))
        .unwrap();
    std::io::Write::write_all(&mut bundle, b"substitution").unwrap();
    bundle.sync_all().unwrap();
    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );
}

#[tokio::test]
async fn cleanup_target_and_every_tombstone_subject_are_exact() {
    let fixture = Fixture::new(false).await;
    let attempt = fixture.value["attempt_first"].as_str().unwrap();
    private_dir(
        &fixture
            .run
            .join("artifacts/runner-execution/work")
            .join(attempt),
    );
    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );

    for (field, replacement) in [
        ("attempt_id", format!("atm_{}", "0".repeat(64))),
        ("variant_id", format!("var_{}", "0".repeat(64))),
        ("nonce_hex", "0".repeat(64)),
        ("artifact_digest", "0".repeat(64)),
        ("destination", "/tmp/substituted-preservation".into()),
        ("receipt_digest", "0".repeat(64)),
    ] {
        let fixture = Fixture::new(false).await;
        let attempt = fixture.value["attempt_first"].as_str().unwrap();
        preservation_fixture::substitute_tombstone(&fixture.run, attempt, field, &replacement);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID",
            "accepted substituted cleanup tombstone {field}"
        );
    }
}

#[tokio::test]
async fn effect_authority_attempt_must_differ_from_the_author() {
    let fixture = Fixture::new(false).await;
    let mut value = fixture.value.clone();
    value["attempt_second"] = value["attempt_first"].clone();
    fixture.rewrite(&value);
    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );
}

fn artifact_snapshot(fixture: &Fixture) -> Vec<ArtifactEntry> {
    let mut entries = Vec::new();
    for path in [
        &fixture.source,
        &fixture.run.join("artifacts/preserve"),
        &fixture.run.join("artifacts/runner-execution"),
        &fixture.forge,
    ] {
        collect(&fixture.run, path, &mut entries);
    }
    collect(
        &fixture.run,
        &fixture.run.join("data/ledger.sqlite"),
        &mut entries,
    );
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn collect(base: &Path, path: &Path, entries: &mut Vec<ArtifactEntry>) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    let contents = if metadata.is_file() {
        std::fs::read(path).unwrap()
    } else if metadata.file_type().is_symlink() {
        std::fs::read_link(path)
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec()
    } else {
        Vec::new()
    };
    entries.push(ArtifactEntry {
        path: path.strip_prefix(base).unwrap().display().to_string(),
        mode: metadata.mode(),
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        contents,
    });
    if metadata.is_dir() {
        let mut children = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            collect(base, &child, entries);
        }
    }
}
