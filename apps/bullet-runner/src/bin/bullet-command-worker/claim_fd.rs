use super::error::{WorkerContext, WorkerError};
use bullet_application::CommandDispatchClaim;
use bullet_harness_core::launch_grant::canonical_json;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

pub(super) struct SealedClaim(File);

impl SealedClaim {
    pub(super) fn create(claim: &CommandDispatchClaim) -> Result<Self, WorkerError> {
        let bytes = canonical_json(claim)
            .worker("COMMAND_CLAIM_SEAL_FAILED", "canonicalize command claim")?;
        let fd = rustix::fs::memfd_create(
            "bullet-command-claim",
            rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .worker("COMMAND_CLAIM_SEAL_FAILED", "create claim memfd")?;
        let mut file = File::from(fd);
        file.write_all(&bytes)
            .worker("COMMAND_CLAIM_SEAL_FAILED", "write claim memfd")?;
        file.seek(SeekFrom::Start(0))
            .worker("COMMAND_CLAIM_SEAL_FAILED", "rewind claim memfd")?;
        let required = rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::SEAL;
        rustix::fs::fcntl_add_seals(&file, required)
            .worker("COMMAND_CLAIM_SEAL_FAILED", "seal claim memfd")?;
        if !rustix::fs::fcntl_get_seals(&file)
            .worker("COMMAND_CLAIM_SEAL_FAILED", "read claim seals")?
            .contains(required)
        {
            return Err(WorkerError::input(
                "COMMAND_CLAIM_SEAL_FAILED",
                "claim memfd lacks mandatory seals",
            ));
        }
        Ok(Self(file))
    }

    pub(super) fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::{CommandDispatchDisposition, CommandRequest};
    use bullet_domain::RunnerId;

    fn claim() -> CommandDispatchClaim {
        let request =
            CommandRequest::new("sealed-worker-claim", "run_demo", &serde_json::json!({})).unwrap();
        CommandDispatchClaim {
            schema_version: "bullet.command-dispatch-claim.v1".into(),
            claim_id: format!("dcl_{}", "a".repeat(64)),
            command_id: request.id(),
            outbox_sequence: 1,
            request_digest: request.digest(),
            request,
            runner_id: RunnerId::from_seed("sealed-worker"),
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

    #[test]
    fn entire_canonical_claim_is_inherited_and_mandatorily_sealed() {
        let claim = claim();
        let sealed = SealedClaim::create(&claim).unwrap();
        let file = std::fs::File::open(format!("/proc/self/fd/{}", sealed.fd())).unwrap();
        let observed = rustix::fs::fcntl_get_seals(&file).unwrap();
        let required = rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::SEAL;
        assert!(observed.contains(required));
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{}", sealed.fd())).unwrap(),
            canonical_json(&claim).unwrap()
        );
        if let Ok(mut writable) = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/self/fd/{}", sealed.fd()))
        {
            assert!(std::io::Write::write_all(&mut writable, b"x").is_err());
        }
    }
}
