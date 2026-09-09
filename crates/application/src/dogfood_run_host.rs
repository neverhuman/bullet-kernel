use super::*;
use crate::policy_snapshot::{DogfoodAudience, DogfoodBinding, DogfoodOperation};
use bullet_harness_core::{
    inspect_provider_runtime, ProviderRuntimePassportV1, RuntimeFileRoleV1,
    RUNTIME_DEPLOYMENT_PREFIX,
};
use bullet_harness_egress::filesystem::FilesystemRuntimeFileV0;
use bullet_harness_egress::FilesystemFileV0;
use serde::Deserialize;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(super) fn refuse_launch_grant_alpha(issuer: &str, key_id: &str) -> Result<(), DogfoodRunError> {
    if key_id == "launch-grant-alpha"
        || (issuer == "bullet-kernel" && key_id.contains("launch-grant"))
    {
        return Err(failed(
            "DOGFOOD_REFUSES_LIVE_CONFORMANCE_KEY",
            "launch-grant-alpha is not a dogfood issuer key",
        ));
    }
    if issuer.is_empty() || key_id.is_empty() {
        return Ok(());
    }
    Ok(())
}

pub(super) fn load_binding(path: &Path) -> Result<DogfoodBinding, DogfoodRunError> {
    let bytes = read_regular_file(path)?;
    let wire: WireBinding = serde_json::from_slice(&bytes)
        .map_err(|error| failed("INVALID_DOGFOOD_BINDING", error.to_string()))?;
    if wire.schema_version != "v1alpha1"
        || wire.audience != "dogfood-runner"
        || wire.operation != "read-only-propose"
    {
        return Err(failed(
            "INVALID_DOGFOOD_BINDING",
            "dogfood binding must be dogfood-runner / read-only-propose",
        ));
    }
    Ok(DogfoodBinding {
        schema_version: wire.schema_version,
        audience: DogfoodAudience::DogfoodRunner,
        operation: DogfoodOperation::ReadOnlyPropose,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    schema_version: String,
    audience: String,
    operation: String,
}

pub(super) fn budget_micro_usd(
    requested: Option<f64>,
    enrolled_max: u64,
) -> Result<u64, DogfoodRunError> {
    let Some(usd) = requested else {
        return Ok(enrolled_max);
    };
    if !usd.is_finite() || usd <= 0.0 {
        return Err(failed(
            "DOGFOOD_BUDGET",
            "max-budget-usd must be a positive finite number",
        ));
    }
    let micro = (usd * 1_000_000.0).round() as u64;
    if micro > enrolled_max {
        return Err(failed(
            "DOGFOOD_BUDGET",
            "requested budget exceeds the enrolled cap",
        ));
    }
    Ok(micro)
}

pub(super) fn require_absolute(name: &str, path: &Path) -> Result<(), DogfoodRunError> {
    if path.as_os_str().is_empty() {
        return Err(failed(
            "DOGFOOD_INPUT_MISSING",
            format!("{name} is required"),
        ));
    }
    if !path.is_absolute() {
        return Err(failed(
            "DOGFOOD_PATH_NOT_ABSOLUTE",
            format!("{name} must be absolute"),
        ));
    }
    Ok(())
}

pub(super) fn require_host_file(path: &str) -> Result<PathBuf, DogfoodRunError> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err(failed(
            "CONTAINMENT_UNAVAILABLE",
            format!("{} is not available on this host", path.display()),
        ));
    }
    path.canonicalize()
        .map_err(|error| failed("DOGFOOD_HOST_FILE", error.to_string()))
}

pub(super) fn host_file(path: &Path) -> Result<FilesystemFileV0, DogfoodRunError> {
    Ok(FilesystemFileV0::new(path, file_blake3(path)?))
}

pub(super) fn file_blake3(path: &Path) -> Result<String, DogfoodRunError> {
    let bytes =
        fs::read(path).map_err(|error| failed("DOGFOOD_DIGEST", format!("{path:?}: {error}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub(super) fn read_regular_0600(path: &Path) -> Result<Vec<u8>, DogfoodRunError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        failed(
            "DOGFOOD_POLICY_MISSING",
            format!("{} is not a file", path.display()),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(failed(
            "DOGFOOD_POLICY_MISSING",
            "policy must be a regular file",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(failed("DOGFOOD_POLICY_MODE", "policy must be mode 0600"));
    }
    fs::read(path).map_err(|error| failed("DOGFOOD_POLICY_IO", error.to_string()))
}

pub(super) fn read_regular_file(path: &Path) -> Result<Vec<u8>, DogfoodRunError> {
    fs::read(path).map_err(|_| DogfoodRunError {
        code: "DOGFOOD_BINDING_MISSING",
        detail: format!("{} is not a file", path.display()),
    })
}

/// Sandbox mount destinations a runtime file may bind to. Mirrors the egress
/// destination allowlist; files outside these prefixes (licenses, SBOMs,
/// schemas) are custody-verified by the inspector but never mounted.
const RUNTIME_DESTINATION_PREFIXES: [&str; 4] = ["/runtime/bin", "/lib", "/lib64", "/usr/lib"];

/// Facts a verified runtime passport contributes to the compose.
#[derive(Debug)]
pub(super) struct PassportedRuntime {
    pub(super) runtime_files: Vec<FilesystemRuntimeFileV0>,
    pub(super) provider_max_bytes: u64,
}

/// When the executable lives under the frozen deployment prefix, a verified
/// passport is mandatory: it supplies the loader/library mounts a dynamic
/// provider needs (the bwrap base set deliberately binds no /lib or /usr) and
/// the exact provider size bound that replaces the blanket 64 MiB ceiling.
/// Outside the prefix nothing changes. The passport file lives beside the
/// immutable tree at `<deployment_root>.passport.json`.
pub(super) fn passported_runtime(
    executable: &Path,
) -> Result<Option<PassportedRuntime>, DogfoodRunError> {
    let prefix = Path::new(RUNTIME_DEPLOYMENT_PREFIX);
    let Ok(relative) = executable.strip_prefix(prefix) else {
        return Ok(None);
    };
    let mut components = relative.components();
    let (Some(provider), Some(version)) = (components.next(), components.next()) else {
        return Err(failed(
            "DOGFOOD_PASSPORT_LAYOUT",
            "deployment executable must be <prefix>/<provider>/<version>/<entrypoint>",
        ));
    };
    let root = prefix.join(provider).join(version);
    // NOT `with_extension`: it replaces everything after the LAST dot, so a
    // semver directory like `.../claude/2.1.266` became
    // `.../claude/2.1.passport.json` and every passport lookup missed. The
    // documented layout is the sibling file named `<root>.passport.json`.
    let mut passport_name = root
        .file_name()
        .ok_or_else(|| {
            failed(
                "DOGFOOD_PASSPORT_LAYOUT",
                "deployment root has no final segment",
            )
        })?
        .to_os_string();
    passport_name.push(".passport.json");
    let passport_path = root.with_file_name(passport_name);
    let bytes = fs::read(&passport_path).map_err(|error| {
        failed(
            "DOGFOOD_PASSPORT_MISSING",
            format!("{}: {error}", passport_path.display()),
        )
    })?;
    let passport = ProviderRuntimePassportV1::decode(&bytes)
        .map_err(|error| failed("DOGFOOD_PASSPORT_INVALID", error.to_string()))?;
    let expected_id = passport
        .passport_id()
        .map_err(|error| failed("DOGFOOD_PASSPORT_INVALID", error.to_string()))?;
    let inspected = inspect_provider_runtime(&bytes, &expected_id)
        .map_err(|error| failed("DOGFOOD_PASSPORT_REFUSED", error.to_string()))?;
    let entrypoint = root.join(inspected.entrypoint());
    if entrypoint != executable {
        return Err(failed(
            "DOGFOOD_PASSPORT_ENTRYPOINT_MISMATCH",
            format!(
                "passport entrypoint {} is not the admitted executable {}",
                entrypoint.display(),
                executable.display()
            ),
        ));
    }
    let mut provider_max_bytes = None;
    let mut runtime_files = Vec::new();
    for file in &passport.files {
        if file.path == passport.entrypoint {
            provider_max_bytes = Some(file.size);
            continue;
        }
        if matches!(
            file.role,
            RuntimeFileRoleV1::License
                | RuntimeFileRoleV1::Sbom
                | RuntimeFileRoleV1::ProtocolSchema
        ) {
            continue;
        }
        let destination = format!("/{}", file.path);
        if !RUNTIME_DESTINATION_PREFIXES
            .iter()
            .any(|prefix| destination.starts_with(&format!("{prefix}/")))
        {
            continue;
        }
        runtime_files.push(FilesystemRuntimeFileV0::new(
            FilesystemFileV0::new(root.join(&file.path), file.blake3.clone()),
            destination,
        ));
    }
    let provider_max_bytes = provider_max_bytes.ok_or_else(|| {
        failed(
            "DOGFOOD_PASSPORT_INVALID",
            "passport manifest does not list its own entrypoint",
        )
    })?;
    Ok(Some(PassportedRuntime {
        runtime_files,
        provider_max_bytes,
    }))
}

pub(super) fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), DogfoodRunError> {
    fs::write(path, bytes).map_err(|error| failed("DOGFOOD_IO", error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| failed("DOGFOOD_IO", error.to_string()))
}

/// Create-once 0600 write for run evidence. A rerun must never overwrite an
/// earlier run's artifact; the receipt already refuses overwrite and every
/// sibling artifact must hold the same line.
pub(super) fn write_create_once_0600(path: &Path, bytes: &[u8]) -> Result<(), DogfoodRunError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                failed(
                    "DOGFOOD_ARTIFACT_EXISTS",
                    format!("{} already exists; evidence is create-once", path.display()),
                )
            } else {
                failed("DOGFOOD_IO", error.to_string())
            }
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| failed("DOGFOOD_IO", error.to_string()))
}

pub(super) fn ensure_private_dir(path: &Path) -> Result<(), DogfoodRunError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|error| failed("DOGFOOD_DATA_DIR", error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| failed("DOGFOOD_DATA_DIR", error.to_string()))
}

pub(super) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn failed(code: &'static str, detail: impl Into<String>) -> DogfoodRunError {
    DogfoodRunError {
        code,
        detail: detail.into(),
    }
}

pub(super) fn neutral(code: &'static str, detail: impl Into<String>) -> DogfoodRunStatus {
    DogfoodRunStatus::Neutral {
        code,
        detail: detail.into(),
    }
}
