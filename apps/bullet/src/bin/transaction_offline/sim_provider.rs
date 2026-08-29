//! Credential-free simulator lifecycle for the offline component bridge.

use super::support::{content_id, fail, private_dir};
use bullet_harness_core::PatchProposal;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MAX_RAW_ARTIFACT_BYTES: u64 = 1_048_576;

pub(super) struct SimProviderExecution {
    pub(super) proposal: PatchProposal,
    pub(super) session_id: String,
    pub(super) raw_artifact_name: String,
    pub(super) raw_artifact_blake3: String,
}

impl SimProviderExecution {
    pub(super) fn into_receipt(self) -> serde_json::Value {
        serde_json::json!({
            "adapter": "sim",
            "version": bullet_harness_sim::SIM_VERSION,
            "session_id": self.session_id,
            "proposal_id": self.proposal.proposal_id,
            "producing_attempt_id": self.proposal.producing_attempt_id,
            "base_checkpoint_id": self.proposal.base_checkpoint_id,
            "base_checkpoint_digest": self.proposal.base_checkpoint_digest,
            "gate_ids": self.proposal.gate_ids,
            "raw_artifact_relative": format!(
                "artifacts/provider-artifacts/{}",
                self.raw_artifact_name
            ),
            "raw_artifact_blake3": self.raw_artifact_blake3,
            "credential_free": true,
            "transaction_gate_eligible": false
        })
    }
}

/// Admit the transcript emitted by the actual product Runner invocation.
///
/// The retained copy uses the existing public receipt layout, but its bytes
/// come from the Runner's own adapter session rather than a parallel session.
pub(super) fn admit_product_runner_transcript(
    source: &Path,
    expected_attempt_id: &str,
    artifact_dir: &Path,
) -> Result<SimProviderExecution, String> {
    let raw = read_protected_transcript(source)?;
    let proposal = decode_terminal_proposal(&raw)?;
    if proposal.producing_attempt_id != expected_attempt_id
        || proposal.gate_ids != [bullet_domain::REPOSITORY_GATE_ID]
    {
        return Err(fail(
            "SIM_PROVIDER_SUBJECT_MISMATCH: Runner transcript differs from its author Attempt",
        ));
    }

    let artifact_dir = private_dir(artifact_dir)?;
    let session_id = content_id(expected_attempt_id);
    let raw_artifact_name = format!("{session_id}.raw.jsonl");
    let retained = artifact_dir.join(&raw_artifact_name);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&retained)
        .map_err(|error| fail(format!("create retained Runner transcript: {error}")))?;
    output
        .write_all(&raw)
        .and_then(|()| output.sync_all())
        .map_err(|error| fail(format!("persist retained Runner transcript: {error}")))?;
    drop(output);
    if read_protected_transcript(&retained)? != raw {
        return Err(fail(
            "SIM_PROVIDER_RAW_ARTIFACT_INVALID: retained Runner transcript changed",
        ));
    }
    Ok(SimProviderExecution {
        raw_artifact_blake3: bullet_domain::Digest::of(&raw).to_hex(),
        proposal,
        session_id,
        raw_artifact_name,
    })
}

fn read_protected_transcript(path: &Path) -> Result<Vec<u8>, String> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| fail(format!("inspect Runner transcript: {error}")))?;
    if !path.is_absolute()
        || !before.file_type().is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.permissions().mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_RAW_ARTIFACT_BYTES
        || path.canonicalize().ok().as_deref() != Some(path)
    {
        return Err(fail(
            "SIM_PROVIDER_RAW_ARTIFACT_INVALID: Runner transcript custody",
        ));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| fail(format!("open Runner transcript: {error}")))?;
    let mut file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|error| fail(format!("inspect open Runner transcript: {error}")))?;
    if metadata_identity(&before) != metadata_identity(&opened) {
        return Err(fail(
            "SIM_PROVIDER_RAW_ARTIFACT_INVALID: Runner transcript identity changed",
        ));
    }
    let mut raw = Vec::new();
    (&mut file)
        .take(MAX_RAW_ARTIFACT_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| fail(format!("read Runner transcript: {error}")))?;
    let after = std::fs::symlink_metadata(path)
        .map_err(|error| fail(format!("reinspect Runner transcript: {error}")))?;
    if raw.len() as u64 != before.len()
        || metadata_identity(&before) != metadata_identity(&after)
        || metadata_identity(&before)
            != metadata_identity(
                &file
                    .metadata()
                    .map_err(|error| fail(format!("reinspect open Runner transcript: {error}")))?,
            )
    {
        return Err(fail(
            "SIM_PROVIDER_RAW_ARTIFACT_INVALID: Runner transcript changed while reading",
        ));
    }
    Ok(raw)
}

fn metadata_identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, u64, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.nlink(),
        metadata.mode(),
    )
}

#[cfg(test)]
fn replay_raw_artifact(raw: &[u8], expected: &PatchProposal) -> Result<(), String> {
    let raw_proposal = decode_terminal_proposal(raw)?;
    if &raw_proposal != expected {
        return Err(fail(
            "SIM_PROVIDER_RAW_PROPOSAL_MISMATCH: raw terminal differs from admitted proposal",
        ));
    }
    Ok(())
}

fn decode_terminal_proposal(raw: &[u8]) -> Result<PatchProposal, String> {
    if raw.is_empty() || raw.last() != Some(&b'\n') {
        return Err(fail(
            "SIM_PROVIDER_RAW_ARTIFACT_TRUNCATED: transcript must end with LF",
        ));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| fail("SIM_PROVIDER_RAW_ARTIFACT_INVALID: transcript is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    let mut completed = None;
    for (index, line) in lines.iter().enumerate() {
        let value = bullet_harness_core::strict_json::decode_strict_json(line)
            .map_err(|error| fail(format!("SIM_PROVIDER_RAW_ARTIFACT_INVALID: {error}")))?;
        let object = value
            .as_object()
            .filter(|object| {
                object.len() == 2 && object.contains_key("kind") && object.contains_key("payload")
            })
            .ok_or_else(|| fail("SIM_PROVIDER_RAW_ARTIFACT_INVALID: closed event shape"))?;
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("turn.completed") if index + 1 == lines.len() && completed.is_none() => {
                completed = object
                    .get("payload")
                    .and_then(|payload| payload.get("proposal"))
                    .cloned();
            }
            Some("turn.completed" | "turn.failed") => {
                return Err(fail(
                    "SIM_PROVIDER_RAW_TERMINAL_INVALID: terminal must be one last completion",
                ));
            }
            Some(_) => {}
            None => return Err(fail("SIM_PROVIDER_RAW_ARTIFACT_INVALID: kind")),
        }
    }
    completed
        .as_ref()
        .ok_or_else(|| fail("SIM_PROVIDER_RAW_TERMINAL_INVALID: completion proposal missing"))
        .and_then(|value| {
            PatchProposal::from_value(value)
                .map_err(|error| fail(format!("SIM_PROVIDER_RAW_PROPOSAL_INVALID: {error}")))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_harness_core::{PatchMutation, PatchOperation, Preimage};
    use serde_json::{json, Value};

    fn id(prefix: &str, nibble: char) -> String {
        format!("{prefix}{}", nibble.to_string().repeat(64))
    }

    fn proposal() -> PatchProposal {
        PatchProposal {
            schema_version: 1,
            proposal_id: id("cnt_", '1'),
            producing_attempt_id: id("atm_", '2'),
            base_checkpoint_id: id("ckp_", '3'),
            base_checkpoint_digest: "4".repeat(64),
            operations: vec![PatchOperation {
                path: "PONG.txt".into(),
                preimage: Preimage::Absent,
                mutation: PatchMutation::Write {
                    content_utf8: "PONG\n".into(),
                },
            }],
            gate_ids: vec![bullet_domain::REPOSITORY_GATE_ID.into()],
            intent_summary: String::new(),
            claims: Vec::new(),
            uncertainties: Vec::new(),
            done: false,
        }
    }

    fn completed(proposal: &PatchProposal) -> String {
        json!({"kind": "turn.completed", "payload": {"proposal": proposal}}).to_string()
    }

    #[test]
    fn raw_replay_refuses_truncation_duplicate_keys_terminal_drift_and_subject_mismatch() {
        let expected = proposal();
        let valid = format!("{}\n", completed(&expected));
        replay_raw_artifact(valid.as_bytes(), &expected).expect("valid transcript");

        let duplicate = format!(
            "{{\"kind\":\"turn.completed\",\"kind\":\"turn.completed\",\"payload\":{{\"proposal\":{}}}}}\n",
            serde_json::to_string(&expected).expect("proposal")
        );
        let trailing = format!(
            "{}\n{}\n",
            completed(&expected),
            json!({"kind": "usage", "payload": {}})
        );
        let mut different = expected.clone();
        different.proposal_id = id("cnt_", '9');
        let cases: [(&str, Vec<u8>, &str); 4] = [
            (
                "missing final LF",
                valid.trim_end_matches('\n').as_bytes().to_vec(),
                "SIM_PROVIDER_RAW_ARTIFACT_TRUNCATED",
            ),
            (
                "duplicate event key",
                duplicate.into_bytes(),
                "SIM_PROVIDER_RAW_ARTIFACT_INVALID",
            ),
            (
                "event follows terminal",
                trailing.into_bytes(),
                "SIM_PROVIDER_RAW_TERMINAL_INVALID",
            ),
            (
                "proposal subject differs",
                format!("{}\n", completed(&different)).into_bytes(),
                "SIM_PROVIDER_RAW_PROPOSAL_MISMATCH",
            ),
        ];
        for (label, raw, reason) in cases {
            let error = replay_raw_artifact(&raw, &expected).expect_err(label);
            assert!(error.contains(reason), "{label}: {error}");
        }

        let mut open_shape: Value = serde_json::from_str(valid.trim()).expect("event");
        open_shape["extra"] = true.into();
        let raw = format!("{open_shape}\n");
        let error = replay_raw_artifact(raw.as_bytes(), &expected).expect_err("open shape");
        assert!(error.contains("SIM_PROVIDER_RAW_ARTIFACT_INVALID"));
    }
}
