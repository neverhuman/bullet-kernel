//! Sealed public-command claim admission for the offline component harness.

use bullet_application::{CommandDispatchClaim, CommandDispatchDisposition};
use bullet_domain::Digest;
use bullet_harness_core::launch_grant::canonical_json;
use serde::Serialize;
use std::fs::File;
use std::io::Read;

const CLAIM_FD_ENV: &str = "BULLET_COMMAND_CLAIM_FD";
const MANIFEST_DIGEST_ENV: &str = "BULLET_COMMAND_BINARY_MANIFEST_DIGEST";
const MAX_CLAIM_BYTES: u64 = 64 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommandDispatchBinding {
    source: &'static str,
    claim_id: Option<String>,
    command_id: Option<String>,
    request_digest: Option<String>,
    runner_id: Option<String>,
    runner_epoch: Option<u64>,
    canonical_claim_blake3: Option<String>,
    binary_manifest_sha256: Option<String>,
    transaction_gate_eligible: bool,
    independent_evidence_eligible: bool,
}

impl CommandDispatchBinding {
    fn local_fixture() -> Self {
        Self {
            source: "LOCAL_FIXTURE",
            claim_id: None,
            command_id: None,
            request_digest: None,
            runner_id: None,
            runner_epoch: None,
            canonical_claim_blake3: None,
            binary_manifest_sha256: None,
            transaction_gate_eligible: false,
            independent_evidence_eligible: false,
        }
    }
}

pub(super) fn admit_command_input() -> Result<CommandDispatchBinding, String> {
    let Some(fd_text) = std::env::var_os(CLAIM_FD_ENV) else {
        if std::env::var_os(MANIFEST_DIGEST_ENV).is_some() {
            return Err(refusal(
                "manifest digest exists without a sealed command claim",
            ));
        }
        return Ok(CommandDispatchBinding::local_fixture());
    };
    let fd_text = fd_text
        .into_string()
        .map_err(|_| refusal("claim descriptor must be a canonical decimal integer"))?;
    let fd = fd_text
        .parse::<i32>()
        .map_err(|_| refusal("claim descriptor must be a canonical decimal integer"))?;
    if fd < 3 || fd.to_string() != fd_text {
        return Err(refusal(
            "claim descriptor must be a canonical decimal integer greater than two",
        ));
    }
    let manifest_digest = std::env::var(MANIFEST_DIGEST_ENV)
        .map_err(|_| refusal("sealed command input requires the binary manifest digest"))?;
    decode_claim_fd(fd, &manifest_digest)
}

fn decode_claim_fd(fd: i32, manifest_digest: &str) -> Result<CommandDispatchBinding, String> {
    if !lower_hex(manifest_digest, 64) {
        return Err(refusal("binary manifest digest must be lowercase SHA-256"));
    }
    let path = format!("/proc/self/fd/{fd}");
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| refusal(format!("open inherited claim descriptor: {error}")))?;
    let seals = rustix::fs::fcntl_get_seals(&descriptor)
        .map_err(|error| refusal(format!("read inherited claim seals: {error}")))?;
    let required = rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::SEAL;
    if !seals.contains(required) {
        return Err(refusal(
            "claim descriptor is not write/grow/shrink/seal sealed",
        ));
    }
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| refusal(format!("inspect inherited claim: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_CLAIM_BYTES {
        return Err(refusal("claim descriptor is not a bounded regular memfd"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CLAIM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refusal(format!("read inherited claim: {error}")))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_CLAIM_BYTES {
        return Err(refusal(
            "claim descriptor length changed or exceeded its bound",
        ));
    }
    let claim: CommandDispatchClaim = serde_json::from_slice(&bytes)
        .map_err(|error| refusal(format!("decode closed command claim: {error}")))?;
    claim
        .validate()
        .map_err(|error| refusal(format!("validate command claim: {error}")))?;
    if claim.disposition != CommandDispatchDisposition::Claimed || claim.request.kind != "run_demo"
    {
        return Err(refusal("only a CLAIMED run_demo command is executable"));
    }
    let canonical = canonical_json(&claim)
        .map_err(|error| refusal(format!("canonicalize command claim: {error}")))?;
    if canonical != bytes {
        return Err(refusal("claim descriptor is not exact canonical JSON"));
    }
    Ok(CommandDispatchBinding {
        source: "SEALED_CLAIM",
        claim_id: Some(claim.claim_id),
        command_id: Some(claim.command_id.to_string()),
        request_digest: Some(claim.request_digest.to_hex()),
        runner_id: Some(claim.runner_id.to_string()),
        runner_epoch: Some(claim.runner_epoch),
        canonical_claim_blake3: Some(format!("blake3:{}", Digest::of(&canonical).to_hex())),
        binary_manifest_sha256: Some(manifest_digest.into()),
        transaction_gate_eligible: false,
        independent_evidence_eligible: false,
    })
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn refusal(detail: impl AsRef<str>) -> String {
    format!("COMMAND_CLAIM_ADMISSION_REFUSED: {}", detail.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::CommandRequest;
    use bullet_domain::RunnerId;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    fn claim() -> CommandDispatchClaim {
        let request = CommandRequest::new("worker-command", "run_demo", &serde_json::json!({}))
            .expect("request");
        CommandDispatchClaim {
            schema_version: "bullet.command-dispatch-claim.v1".into(),
            claim_id: format!("dcl_{}", "a".repeat(64)),
            command_id: request.id(),
            outbox_sequence: 1,
            request_digest: request.digest(),
            request,
            runner_id: RunnerId::from_seed("worker"),
            runner_epoch: 1,
            authority_epoch: 1,
            freeze_generation: 0,
            restore_epoch: 0,
            disposition: CommandDispatchDisposition::Claimed,
            completion_digest: None,
            claimed_at: "2026-08-27T13:00:00.000Z".into(),
            updated_at: "2026-08-27T13:00:00.000Z".into(),
        }
    }

    fn claim_memfd(bytes: &[u8], sealed: bool) -> File {
        let fd =
            rustix::fs::memfd_create("command-claim-test", rustix::fs::MemfdFlags::ALLOW_SEALING)
                .expect("memfd");
        let mut file = File::from(fd);
        file.write_all(bytes).expect("write claim");
        file.seek(SeekFrom::Start(0)).expect("rewind");
        if sealed {
            rustix::fs::fcntl_add_seals(
                &file,
                rustix::fs::SealFlags::WRITE
                    | rustix::fs::SealFlags::GROW
                    | rustix::fs::SealFlags::SHRINK
                    | rustix::fs::SealFlags::SEAL,
            )
            .expect("seal");
        }
        file
    }

    #[test]
    fn sealed_canonical_claim_binds_every_public_command_subject() {
        let claim = claim();
        let bytes = canonical_json(&claim).unwrap();
        let file = claim_memfd(&bytes, true);
        let binding = decode_claim_fd(file.as_raw_fd(), &"b".repeat(64)).unwrap();
        assert_eq!(binding.source, "SEALED_CLAIM");
        assert_eq!(binding.claim_id.as_deref(), Some(claim.claim_id.as_str()));
        assert_eq!(
            binding.command_id.as_deref(),
            Some(claim.command_id.as_str())
        );
        assert_eq!(
            binding.request_digest.as_deref(),
            Some(claim.request_digest.to_hex().as_str())
        );
        assert_eq!(binding.runner_id.as_deref(), Some(claim.runner_id.as_str()));
        assert_eq!(binding.runner_epoch, Some(claim.runner_epoch));
        assert_eq!(
            binding.canonical_claim_blake3.as_deref(),
            Some(format!("blake3:{}", Digest::of(&bytes).to_hex()).as_str())
        );
        assert_eq!(
            binding.binary_manifest_sha256.as_deref(),
            Some(&*"b".repeat(64))
        );
        assert!(!binding.transaction_gate_eligible);
        assert!(!binding.independent_evidence_eligible);
    }

    #[test]
    fn unsealed_writable_noncanonical_and_unknown_claims_refuse() {
        let claim = claim();
        let canonical = canonical_json(&claim).unwrap();
        let unsealed = claim_memfd(&canonical, false);
        assert!(decode_claim_fd(unsealed.as_raw_fd(), &"b".repeat(64)).is_err());

        let pretty = serde_json::to_vec_pretty(&claim).unwrap();
        let noncanonical = claim_memfd(&pretty, true);
        assert!(decode_claim_fd(noncanonical.as_raw_fd(), &"b".repeat(64)).is_err());

        let mut value = serde_json::to_value(&claim).unwrap();
        value["unknown"] = serde_json::json!(true);
        let unknown = claim_memfd(&serde_json::to_vec(&value).unwrap(), true);
        assert!(decode_claim_fd(unknown.as_raw_fd(), &"b".repeat(64)).is_err());

        let mut nested = serde_json::to_value(&claim).unwrap();
        nested["request"]["unknown"] = serde_json::json!(true);
        let nested = claim_memfd(&canonical_json(&nested).unwrap(), true);
        assert!(decode_claim_fd(nested.as_raw_fd(), &"b".repeat(64)).is_err());
    }

    #[test]
    fn wrong_subject_disposition_and_oversize_refuse() {
        let mut off_subject = claim();
        off_subject.command_id = bullet_domain::CommandId::from_seed("other");
        let file = claim_memfd(&canonical_json(&off_subject).unwrap(), true);
        assert!(decode_claim_fd(file.as_raw_fd(), &"b".repeat(64)).is_err());

        let mut off_digest = claim();
        off_digest.request_digest = Digest::of(b"other-request");
        let file = claim_memfd(&canonical_json(&off_digest).unwrap(), true);
        assert!(decode_claim_fd(file.as_raw_fd(), &"b".repeat(64)).is_err());

        let mut wrong_disposition = claim();
        wrong_disposition.disposition = CommandDispatchDisposition::Invalidated;
        let file = claim_memfd(&canonical_json(&wrong_disposition).unwrap(), true);
        assert!(decode_claim_fd(file.as_raw_fd(), &"b".repeat(64)).is_err());

        let mut wrong_kind = claim();
        wrong_kind.request.kind = "other_command".into();
        wrong_kind.request_digest = wrong_kind.request.digest();
        let file = claim_memfd(&canonical_json(&wrong_kind).unwrap(), true);
        assert!(decode_claim_fd(file.as_raw_fd(), &"b".repeat(64)).is_err());

        let huge = claim_memfd(&vec![b'x'; MAX_CLAIM_BYTES as usize + 1], true);
        assert!(decode_claim_fd(huge.as_raw_fd(), &"b".repeat(64)).is_err());

        let empty = claim_memfd(&[], true);
        assert!(decode_claim_fd(empty.as_raw_fd(), &"b".repeat(64)).is_err());
        let valid = claim_memfd(&canonical_json(&claim()).unwrap(), true);
        assert!(decode_claim_fd(valid.as_raw_fd(), &"B".repeat(64)).is_err());
    }

    #[test]
    fn every_required_memfd_seal_is_mandatory() {
        let canonical = canonical_json(&claim()).unwrap();
        for seals in [
            rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::SEAL,
            rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::SEAL,
            rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SEAL,
            rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SHRINK,
        ] {
            let fd = rustix::fs::memfd_create(
                "command-claim-partially-sealed-test",
                rustix::fs::MemfdFlags::ALLOW_SEALING,
            )
            .expect("memfd");
            let mut file = File::from(fd);
            file.write_all(&canonical).expect("write claim");
            file.seek(SeekFrom::Start(0)).expect("rewind");
            rustix::fs::fcntl_add_seals(&file, seals).expect("partial seals");
            assert!(decode_claim_fd(file.as_raw_fd(), &"b".repeat(64)).is_err());
        }
    }

    #[test]
    fn local_fixture_binding_is_explicit_empty_and_hard_false() {
        let binding = CommandDispatchBinding::local_fixture();
        let value = serde_json::to_value(binding).unwrap();
        assert_eq!(value["source"], "LOCAL_FIXTURE");
        for field in [
            "claim_id",
            "command_id",
            "request_digest",
            "runner_id",
            "runner_epoch",
            "canonical_claim_blake3",
            "binary_manifest_sha256",
        ] {
            assert!(value[field].is_null(), "{field} must be absent");
        }
        assert_eq!(value["transaction_gate_eligible"], false);
        assert_eq!(value["independent_evidence_eligible"], false);
    }
}
