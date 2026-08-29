//! Exact preservation and cleanup read-back for one synthetic lane.

use super::fail;
use bullet_domain::Digest;
use bullet_runner_core::{AcquireGrant, AttemptOutcome};
use serde::{de::DeserializeOwned, Deserialize};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const MAX_RECORD_BYTES: u64 = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservationSubject {
    schema_version: u32,
    attempt_id: String,
    attempt_fence: u64,
    workspace_nonce_hex: String,
    generation: u64,
    git_tree: String,
    generation_digest: String,
    dirty_untracked: Vec<serde_json::Value>,
    journal_start: u64,
    journal_end: u64,
    journal_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupTombstone {
    schema_version: u32,
    attempt_id: String,
    variant_id: String,
    nonce_hex: String,
    deleted_at: String,
    preservation_receipt_digest: String,
    preservation_artifact_digest: String,
    preservation_destination: String,
}

struct Expected<'a> {
    attempt_id: &'a str,
    variant_id: &'a str,
    fence: u64,
    nonce_hex: String,
    tree: &'a str,
    prepared_at: &'a str,
    receipt_digest: &'a str,
    artifact_digest: &'a str,
    destination: &'a str,
}

pub(super) fn admit(
    workspace_root: &Path,
    destination: &Path,
    grant: &AcquireGrant,
    outcome: &AttemptOutcome,
) -> Result<PathBuf, String> {
    outcome
        .preservation
        .validate_against(&outcome.candidate, &grant.attempt.id, grant.attempt.fence)
        .map_err(|error| fail(format!("synthetic preservation binding: {error}")))?;
    let receipt = &outcome.preservation.receipt;
    if receipt.destination != destination {
        return Err(fail("preservation destination differs from admitted lane"));
    }
    require_token_digest(&receipt.token, &receipt.digest)?;
    require_private_directory(destination, "preservation destination")?;
    require_absent(&workspace_root.join("work").join(grant.attempt.id.as_str()))?;

    let destination_text = destination
        .to_str()
        .ok_or_else(|| fail("preservation destination is not UTF-8"))?;
    let expected = Expected {
        attempt_id: grant.attempt.id.as_str(),
        variant_id: grant.attempt.variant_id.as_str(),
        fence: grant.attempt.fence,
        nonce_hex: lower_hex_bytes(&grant.attempt.workspace_nonce),
        tree: &outcome.candidate.tree_hash,
        prepared_at: &outcome.candidate.prepared_at,
        receipt_digest: &receipt.digest,
        artifact_digest: &receipt.artifact_digest,
        destination: destination_text,
    };
    let subject: PreservationSubject = read_closed(&destination.join("subject.json"), "subject")?;
    subject.validate(&expected)?;

    let runtime = workspace_root
        .join("runtime")
        .join(grant.attempt.id.as_str());
    require_private_directory(&runtime, "cleanup runtime")?;
    let tombstone: CleanupTombstone =
        read_closed(&runtime.join("tombstone.json"), "cleanup tombstone")?;
    tombstone.validate(&expected)?;

    let repository = destination.join("generation/repo");
    require_private_directory(&repository, "preserved Candidate repository")?;
    Ok(repository)
}

impl PreservationSubject {
    fn validate(&self, expected: &Expected<'_>) -> Result<(), String> {
        let exact = self.schema_version == 1
            && self.attempt_id == expected.attempt_id
            && self.attempt_fence == expected.fence
            && self.workspace_nonce_hex == expected.nonce_hex
            && self.generation == 2
            && self.git_tree == expected.tree
            && lower_hex(&self.generation_digest, 64)
            && self.dirty_untracked.is_empty()
            && self.journal_start == 1
            && self.journal_end == 1
            && lower_hex(&self.journal_root, 64);
        exact
            .then_some(())
            .ok_or_else(|| fail("preserved subject differs from exact lane"))
    }
}

impl CleanupTombstone {
    fn validate(&self, expected: &Expected<'_>) -> Result<(), String> {
        let exact = self.schema_version == 1
            && self.attempt_id == expected.attempt_id
            && self.variant_id == expected.variant_id
            && self.nonce_hex == expected.nonce_hex
            && self.deleted_at == expected.prepared_at
            && self.preservation_receipt_digest == expected.receipt_digest
            && self.preservation_artifact_digest == expected.artifact_digest
            && self.preservation_destination == expected.destination;
        exact
            .then_some(())
            .ok_or_else(|| fail("cleanup tombstone differs from exact preservation"))
    }
}

fn require_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(fail(format!("inspect cleaned workspace: {error}"))),
        Ok(_) => Err(fail(
            "original workspace survived preservation-gated cleanup",
        )),
    }
}

fn require_private_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| fail(format!("inspect {label}: {error}")))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(fail(format!("{label} is not an ordinary directory")));
    }
    let canonical =
        fs::canonicalize(path).map_err(|error| fail(format!("canonicalize {label}: {error}")))?;
    if canonical != path {
        return Err(fail(format!("{label} contains symlink traversal")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(fail(format!("{label} is not caller-owned mode 0700")));
        }
    }
    #[cfg(not(unix))]
    return Err(fail(format!("{label} lacks audited directory custody")));
    Ok(())
}

fn require_token_digest(token: &str, recorded: &str) -> Result<(), String> {
    (Digest::of(token.as_bytes()).to_hex() == recorded)
        .then_some(())
        .ok_or_else(|| fail("preservation token digest differs from receipt"))
}

fn read_closed<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, String> {
    let bytes = super::super::private_artifact::read(path, MAX_RECORD_BYTES, label)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| fail(format!("{label} is not UTF-8")))?;
    let value = bullet_harness_core::strict_json::decode_strict_json(text)
        .map_err(|error| fail(format!("strict {label} decode: {error}")))?;
    serde_json::from_value(value).map_err(|error| fail(format!("closed {label} decode: {error}")))
}

fn lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lower_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    fn expected() -> Expected<'static> {
        Expected {
            attempt_id: "attempt",
            variant_id: "variant",
            fence: 1,
            nonce_hex: "1".repeat(64),
            tree: "sha1:2222222222222222222222222222222222222222",
            prepared_at: "2026-08-28T00:00:00Z",
            receipt_digest: "3".repeat(64).leak(),
            artifact_digest: "4".repeat(64).leak(),
            destination: "/tmp/preserved",
        }
    }

    fn subject() -> PreservationSubject {
        PreservationSubject {
            schema_version: 1,
            attempt_id: "attempt".into(),
            attempt_fence: 1,
            workspace_nonce_hex: "1".repeat(64),
            generation: 2,
            git_tree: "sha1:2222222222222222222222222222222222222222".into(),
            generation_digest: "5".repeat(64),
            dirty_untracked: Vec::new(),
            journal_start: 1,
            journal_end: 1,
            journal_root: "6".repeat(64),
        }
    }

    #[test]
    fn subject_and_tombstone_drift_refuse() {
        let expected = expected();
        subject().validate(&expected).expect("exact subject");
        let mut drift = subject();
        drift.generation = 1;
        assert!(drift.validate(&expected).is_err());
        let tombstone = CleanupTombstone {
            schema_version: 1,
            attempt_id: "attempt".into(),
            variant_id: "variant".into(),
            nonce_hex: "1".repeat(64),
            deleted_at: "2026-08-28T00:00:00Z".into(),
            preservation_receipt_digest: "3".repeat(64),
            preservation_artifact_digest: "4".repeat(64),
            preservation_destination: "/tmp/preserved".into(),
        };
        tombstone.validate(&expected).expect("exact tombstone");
        let mut drift = tombstone;
        drift.deleted_at.push('x');
        assert!(drift.validate(&expected).is_err());
    }

    #[test]
    fn cleanup_and_directory_custody_refuse_substitution() {
        let root = tempfile::tempdir().expect("root");
        let directory = root.path().join("private");
        fs::create_dir(&directory).expect("directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("mode");
        require_private_directory(&directory, "test").expect("private directory");
        let alias = root.path().join("alias");
        symlink(&directory, &alias).expect("alias");
        assert!(require_private_directory(&alias, "test").is_err());
        let absent = root.path().join("absent");
        require_absent(&absent).expect("absent");
        fs::write(&absent, b"present").expect("present");
        assert!(require_absent(&absent).is_err());
    }

    #[test]
    fn strict_records_and_token_digest_refuse_drift() {
        let exact = Digest::of(b"token").to_hex();
        require_token_digest("token", &exact).expect("exact digest");
        assert!(require_token_digest("drift", &exact).is_err());
        let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
        let path = tempfile::NamedTempFile::new().expect("record");
        fs::write(path.path(), duplicate).expect("duplicate");
        fs::set_permissions(path.path(), fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(read_closed::<PreservationSubject>(path.path(), "subject").is_err());
    }
}
