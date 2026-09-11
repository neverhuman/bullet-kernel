//! Admit Codex/Cursor/Antigravity through the same filesystem + egress
//! consumer the Claude dogfood compose already uses. Never constructs `sim`.

use bullet_harness_core::proposal;
use bullet_harness_egress::{
    EgressPolicy, EgressSandbox, FilesystemFileV0, FilesystemSandboxProfileV0,
};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

const BWRAP: &str = "/usr/bin/bwrap";
const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Run one signed-in argv inside an admitted filesystem + network sandbox.
///
/// # Errors
///
/// `SIGNED_IN_CONTAINMENT_UNAVAILABLE` when tools, profile, or egress cannot
/// be admitted. Relative executables are refused before the sandbox is built.
pub fn run_signed_in(
    provider: &str,
    executable: &Path,
    workdir: &Path,
    artifact_dir: &Path,
    args: &[String],
) -> Result<Output, String> {
    if !executable.is_absolute() {
        return Err(
            "SIGNED_IN_CONTAINMENT_UNAVAILABLE: --signed-in-executable must be an absolute path"
                .into(),
        );
    }
    let policy_provider = match provider {
        "agy" => "antigravity",
        other => other,
    };
    let policy = EgressPolicy::for_provider(policy_provider)
        .map_err(|error| format!("SIGNED_IN_CONTAINMENT_UNAVAILABLE: {error}"))?;
    let bubblewrap = host_file(Path::new(BWRAP))?;
    let ca_bundle = host_file(Path::new(CA_BUNDLE))?;
    let provider_bin = host_file(executable)?;
    let clone = workdir
        .canonicalize()
        .map_err(|error| format!("SIGNED_IN_CONTAINMENT_UNAVAILABLE: workdir: {error}"))?;
    let runtime = private_dir(artifact_dir, "signed-in-runtime")?;
    let schema_path = runtime.join("proposal-schema.json");
    let schema_bytes = proposal::schema_source().as_bytes();
    write_0600(&schema_path, schema_bytes)?;
    let schema = FilesystemFileV0::new(
        &schema_path,
        blake3::hash(schema_bytes).to_hex().to_string(),
    );
    let scratch = private_dir(&runtime, "scratch")?;
    let filesystem = FilesystemSandboxProfileV0::new(
        bubblewrap,
        provider_bin,
        clone,
        schema,
        ca_bundle,
        Vec::new(),
        scratch,
    )
    .prepare()
    .map_err(|error| format!("SIGNED_IN_CONTAINMENT_UNAVAILABLE: {error}"))?;
    let egress_dir = private_dir(&runtime, "egress")?;
    let sandbox = EgressSandbox::prepare(policy, &egress_dir)
        .map_err(|error| format!("SIGNED_IN_CONTAINMENT_UNAVAILABLE: {error}"))?;
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut command = sandbox
        .filesystem_command(&filesystem, &arg_refs)
        .map_err(|error| format!("SIGNED_IN_CONTAINMENT_UNAVAILABLE: {error}"))?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .output()
        .map_err(|error| format!("SIGNED_IN_SPAWN_FAILED: {error}"))
}

fn host_file(path: &Path) -> Result<FilesystemFileV0, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        format!(
            "SIGNED_IN_CONTAINMENT_UNAVAILABLE: {} is not available on this host",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "SIGNED_IN_CONTAINMENT_UNAVAILABLE: {} is not a regular file",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "SIGNED_IN_CONTAINMENT_UNAVAILABLE: read {}: {error}",
            path.display()
        )
    })?;
    Ok(FilesystemFileV0::new(
        path.canonicalize().map_err(|error| {
            format!(
                "SIGNED_IN_CONTAINMENT_UNAVAILABLE: canonicalize {}: {error}",
                path.display()
            )
        })?,
        blake3::hash(&bytes).to_hex().to_string(),
    ))
}

fn private_dir(parent: &Path, name: &str) -> Result<PathBuf, String> {
    let path = parent.join(name);
    if path.exists() {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "SIGNED_IN_CONTAINMENT_UNAVAILABLE: inspect {}: {error}",
                path.display()
            )
        })?;
        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(format!(
                "SIGNED_IN_CONTAINMENT_UNAVAILABLE: {} must be a 0700 directory",
                path.display()
            ));
        }
        return Ok(path);
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| {
            format!(
                "SIGNED_IN_CONTAINMENT_UNAVAILABLE: create {}: {error}",
                path.display()
            )
        })?;
    Ok(path)
}

fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    use std::io::Write;
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|error| {
            format!(
                "SIGNED_IN_CONTAINMENT_UNAVAILABLE: write {}: {error}",
                path.display()
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bwrap_is_typed_unavailable() {
        if Path::new(BWRAP).is_file() {
            return;
        }
        let dir = std::env::temp_dir();
        let error =
            run_signed_in("codex", Path::new("/usr/bin/true"), &dir, &dir, &[]).unwrap_err();
        assert!(
            error.contains("SIGNED_IN_CONTAINMENT_UNAVAILABLE"),
            "{error}"
        );
    }

    #[test]
    fn relative_executable_is_refused() {
        let error = run_signed_in(
            "codex",
            Path::new("true"),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &[],
        )
        .unwrap_err();
        assert!(
            error.contains("SIGNED_IN_CONTAINMENT_UNAVAILABLE"),
            "{error}"
        );
    }
}
