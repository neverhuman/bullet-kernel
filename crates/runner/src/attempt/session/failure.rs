//! Private failed-run artifacts are retained independently of proposal acceptance.

use crate::RunnerError;
use bullet_harness_core::{AgentEventKind, SessionHandle, TurnHandle};
use serde_json::Value;
use std::path::Path;

pub(super) fn preserve(
    runtime: &Path,
    session: &SessionHandle,
    turn: &TurnHandle,
    close: Option<&(AgentEventKind, Value)>,
) -> Result<RunnerError, RunnerError> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version":1, "session_id":session.session_id,
        "invocation_id":turn.invocation_id, "provider":session.provider,
        "exit_code":turn.exit_code, "timed_out":turn.timed_out,
        "close":close, "disposition":"FAILED_RUN_ARTIFACT_ONLY"
    }))
    .map_err(|e| io(e.to_string()))?;
    // A proposal's worst-case escaped transport plus bounded envelope metadata.
    if bytes.len() > 194 * 1024 * 1024 {
        return Err(io("failed turn exceeds admitted artifact bound".into()));
    }
    let name = format!(
        "failed-turn-{}.json",
        bullet_domain::Digest::of(&bytes).to_hex()
    );
    persist(runtime, &name, &bytes)?;
    Ok(RunnerError::NoProposal(format!(
        "native execution did not complete successfully; retained {name}"
    )))
}

fn io(reason: String) -> RunnerError {
    RunnerError::Io {
        context: "preserve failed native turn".into(),
        reason,
    }
}

#[cfg(target_os = "linux")]
fn persist(runtime: &Path, name: &str, bytes: &[u8]) -> Result<(), RunnerError> {
    use rustix::fs::{openat, openat2, Mode, OFlags, ResolveFlags, ABS};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    let directory = File::from(
        openat2(
            ABS,
            runtime,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|e| io(e.to_string()))?,
    );
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let retained_file = match openat(&directory, name, flags, Mode::RUSR | Mode::WUSR) {
        Ok(fd) => {
            let mut file = File::from(fd);
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| io(e.to_string()))?;
            file
        }
        Err(rustix::io::Errno::EXIST) => {
            let fd = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|e| io(e.to_string()))?;
            let file = File::from(fd);
            check_file(&file, &directory)?;
            let mut retained = Vec::new();
            (&file)
                .take(bytes.len() as u64 + 1)
                .read_to_end(&mut retained)
                .map_err(|e| io(e.to_string()))?;
            if retained != bytes {
                return Err(io("retained artifact collision".into()));
            }
            file.sync_all().map_err(|e| io(e.to_string()))?;
            file
        }
        Err(error) => return Err(io(error.to_string())),
    };
    directory.sync_all().map_err(|e| io(e.to_string()))?;
    check_file(&retained_file, &directory)?;
    let current_directory = File::from(
        openat2(
            ABS,
            runtime,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|e| io(e.to_string()))?,
    );
    let current_file = File::from(
        openat(
            &current_directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| io(e.to_string()))?,
    );
    for (held, current) in [
        (&directory, &current_directory),
        (&retained_file, &current_file),
    ] {
        let held = held.metadata().map_err(|e| io(e.to_string()))?;
        let current = current.metadata().map_err(|e| io(e.to_string()))?;
        if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
            return Err(io("retained artifact path changed".into()));
        }
    }
    check_file(&current_file, &current_directory)
}

#[cfg(target_os = "linux")]
fn check_file(file: &std::fs::File, directory: &std::fs::File) -> Result<(), RunnerError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|e| io(e.to_string()))?;
    let owner = directory.metadata().map_err(|e| io(e.to_string()))?.uid();
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != owner
    {
        return Err(io(
            "retained artifact is not a private singly linked regular file".into(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn persist(_runtime: &Path, _name: &str, _bytes: &[u8]) -> Result<(), RunnerError> {
    Err(io(
        "private failed-turn custody requires an admitted native platform".into(),
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::persist;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn retained_artifacts_require_private_regular_file_custody() {
        let runtime = tempfile::tempdir().unwrap();
        let path = runtime.path().join("failure.json");
        let alias = runtime.path().join("alias.json");
        let bytes = b"original failed proposal";
        persist(runtime.path(), "failure.json", bytes).unwrap();
        persist(runtime.path(), "failure.json", bytes).unwrap();
        assert!(persist(runtime.path(), "failure.json", b"changed proposal").is_err());
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(persist(runtime.path(), "failure.json", bytes).is_err());
        std::fs::remove_file(&alias).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(persist(runtime.path(), "failure.json", bytes).is_err());
        std::fs::rename(&path, &alias).unwrap();
        symlink(&alias, &path).unwrap();
        assert!(persist(runtime.path(), "failure.json", bytes).is_err());
        std::fs::remove_file(&path).unwrap();
        rustix::fs::mkfifoat(rustix::fs::ABS, &path, rustix::fs::Mode::RUSR).unwrap();
        assert!(persist(runtime.path(), "failure.json", bytes).is_err());
        assert_eq!(std::fs::read(alias).unwrap(), bytes);
    }
}
