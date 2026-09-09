//! Operator-input producers for the dogfood track (ADR 0015 admission kit).
//!
//! The admission kit deliberately forbids shell-authored artifacts: canonical
//! bytes must come from the shared RFC 8785 implementation, and each producer
//! must prove its output by consuming it through the exact validator the
//! compose itself uses. Every writer here is create-once 0600, and every
//! producer returns the BLAKE3 of the exact bytes written so the operator can
//! record it.
//!
//! Nothing here mints authority: the policy producer only re-encodes an
//! operator-ratified base plus an operator-generated `IssuerKeyV1`; the
//! enrollment is the unsigned v1 record that authenticates nobody (its own
//! module says so); the binding is a constant; the passport describes files
//! the operator already staged.

use crate::live_conformance::{
    enrollment_path, load_provider_enrollment, PROVIDER_ENROLLMENT_SCHEMA,
};
use crate::policy_snapshot::{validate_dogfood_admission, DogfoodBinding, LoadedPolicy};
use bullet_harness_core::launch_grant::canonical_json;
use bullet_harness_core::{ProviderRuntimePassportV1, RuntimeFileRoleV1, RuntimeFileV1};
use serde_json::{json, Map, Value};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Typed producer failure: a stable code plus a non-secret detail.
#[derive(Debug)]
pub struct DogfoodProduceError {
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Non-secret detail.
    pub detail: String,
}

impl std::fmt::Display for DogfoodProduceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

fn produce_failed(code: &'static str, detail: impl Into<String>) -> DogfoodProduceError {
    DogfoodProduceError {
        code,
        detail: detail.into(),
    }
}

/// Write canonical bytes create-once at mode 0600 and return their BLAKE3.
fn write_canonical_once(path: &Path, bytes: &[u8]) -> Result<String, DogfoodProduceError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                produce_failed(
                    "DOGFOOD_PRODUCE_EXISTS",
                    format!(
                        "{} already exists; producers never overwrite",
                        path.display()
                    ),
                )
            } else {
                produce_failed("DOGFOOD_PRODUCE_IO", error.to_string())
            }
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
    // Reopen and require byte equality: what is on disk is what was encoded.
    let reread =
        fs::read(path).map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
    if reread != bytes {
        return Err(produce_failed(
            "DOGFOOD_PRODUCE_READBACK",
            "written bytes differ on read-back",
        ));
    }
    Ok(blake3::hash(bytes).to_hex().to_string())
}

/// Produce the one admitted `DogfoodBindingV1` document.
///
/// # Errors
///
/// Create-once, IO, or read-back failure; or the produced bytes failing the
/// compose's own binding validation.
pub fn produce_binding(out: &Path) -> Result<String, DogfoodProduceError> {
    let value = json!({
        "audience": "dogfood-runner",
        "operation": "read-only-propose",
        "schema_version": "v1alpha1",
    });
    let bytes = canonical_json(&value)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_CANONICAL", error.to_string()))?;
    // Prove by consumption: the same field checks the compose's own binding
    // loader applies, plus the structural live refusal on the typed binding.
    let parsed: Value = serde_json::from_slice(&bytes)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_INVALID", error.to_string()))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| produce_failed("DOGFOOD_PRODUCE_INVALID", "binding is not an object"))?;
    if object.len() != 3
        || object.get("schema_version").and_then(Value::as_str) != Some("v1alpha1")
        || object.get("audience").and_then(Value::as_str) != Some("dogfood-runner")
        || object.get("operation").and_then(Value::as_str) != Some("read-only-propose")
    {
        return Err(produce_failed(
            "DOGFOOD_PRODUCE_INVALID",
            "produced binding does not match the admitted shape",
        ));
    }
    let binding = DogfoodBinding::read_only_propose();
    if crate::policy_snapshot::refuse_dogfood_binding_as_live(&binding).is_ok() {
        return Err(produce_failed(
            "DOGFOOD_PRODUCE_INVALID",
            "produced binding did not yield the structural live refusal",
        ));
    }
    write_canonical_once(out, &bytes)
}

/// Produce the v1alpha2 generation-2 dogfood policy from an operator-ratified
/// base and the `IssuerKeyV1` printed by `authority keygen`.
///
/// Exactly the four mutations the admission kit specifies, with
/// `live_admission_enabled` staying `false` — the dogfood validator refuses
/// `true` twice, so a producer emitting it would be manufacturing a refusal.
///
/// # Errors
///
/// Parse, canonicalization, safety-leaf drift, or the produced bytes failing
/// `validate_dogfood_admission` — the compose's own gate.
pub fn produce_policy(
    base: &Path,
    issuer_key: &Path,
    out: &Path,
) -> Result<String, DogfoodProduceError> {
    let base_bytes =
        fs::read(base).map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
    let mut policy: Map<String, Value> = serde_json::from_slice(&base_bytes)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_BASE_INVALID", error.to_string()))?;
    let key_bytes = fs::read(issuer_key)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
    let key: Value = serde_json::from_slice(&key_bytes)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_KEY_INVALID", error.to_string()))?;

    // The four admitted mutations, nothing else.
    policy.insert("schema_version".into(), Value::String("v1alpha2".into()));
    policy.insert("policy_generation".into(), Value::from(2));
    let keys = policy
        .entry("issuer_keys")
        .or_insert_with(|| Value::Array(Vec::new()));
    keys.as_array_mut()
        .ok_or_else(|| produce_failed("DOGFOOD_PRODUCE_BASE_INVALID", "issuer_keys is not a list"))?
        .push(key);
    if let Some(sandbox) = policy
        .get_mut("sandbox_policy")
        .and_then(Value::as_object_mut)
    {
        // Explicit, not implicit: the flag stays false even if the base ever
        // carried true.
        sandbox.insert("live_admission_enabled".into(), Value::Bool(false));
    }

    let bytes = canonical_json(&policy)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_CANONICAL", error.to_string()))?;

    // Prove by consumption: the compose's own loader and admission validator.
    let loaded = LoadedPolicy::from_bytes(&bytes)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_POLICY_REFUSED", error.to_string()))?;
    let binding = DogfoodBinding::read_only_propose();
    validate_dogfood_admission(loaded.snapshot(), &binding)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_POLICY_REFUSED", error.to_string()))?;

    write_canonical_once(out, &bytes)
}

/// Operator facts for one unsigned provider enrollment.
#[derive(Clone, Debug)]
pub struct EnrollmentFacts {
    /// Provider name (`claude`, `codex`, `cursor`, `antigravity`).
    pub provider: String,
    /// Absolute frozen executable path (the staged deployment entrypoint).
    pub executable: PathBuf,
    /// Exact runtime version the operator observed and confirms.
    pub version: String,
    /// Frozen protocol wire label from the provider table.
    pub protocol: String,
    /// Kernel profile id (`prf_` + 64 lowercase hex).
    pub profile_id: String,
    /// Tightest per-turn cost cap in micro-USD.
    pub budget_micro_usd_max: u64,
    /// Activation instant, Unix ms.
    pub valid_from_unix_ms: u64,
    /// Expiry instant (exclusive), Unix ms.
    pub valid_until_unix_ms: u64,
    /// Free-text author label; fixture identities refused by the loader.
    pub enrolled_by: String,
}

/// Produce `<data-dir>/policy/enrollments/<provider>.json`, computing the
/// executable digest itself, then prove the artifact by loading it through
/// `load_provider_enrollment` — the compose's own loader, which re-verifies
/// the digest and the executable's parent custody.
///
/// # Errors
///
/// IO, create-once, or the produced record failing the real loader.
pub fn produce_enrollment(
    data_dir: &Path,
    facts: &EnrollmentFacts,
    now_unix_ms: u64,
) -> Result<String, DogfoodProduceError> {
    let executable_bytes = fs::read(&facts.executable)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
    let executable_blake3 = blake3::hash(&executable_bytes).to_hex().to_string();
    let record = json!({
        "schema": PROVIDER_ENROLLMENT_SCHEMA,
        "provider": facts.provider,
        "executable": facts.executable,
        "executable_blake3": executable_blake3,
        "protocol": facts.protocol,
        "version": facts.version,
        "profile_id": facts.profile_id,
        "budget_micro_usd_max": facts.budget_micro_usd_max,
        "valid_from_unix_ms": facts.valid_from_unix_ms,
        "valid_until_unix_ms": facts.valid_until_unix_ms,
        "enrolled_by": facts.enrolled_by,
    });
    let bytes = canonical_json(&record)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_CANONICAL", error.to_string()))?;
    let path = enrollment_path(data_dir, &facts.provider);
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(parent)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
    }
    let digest = write_canonical_once(&path, &bytes)?;
    // Prove by consumption. On failure the artifact is removed so a broken
    // record never lingers as if enrolled.
    if let Err(error) = load_provider_enrollment(data_dir, &facts.provider, now_unix_ms) {
        let _ = fs::remove_file(&path);
        return Err(produce_failed(
            "DOGFOOD_PRODUCE_ENROLLMENT_REFUSED",
            error.to_string(),
        ));
    }
    Ok(digest)
}

/// Produce a canonical `ProviderRuntimePassportV1` describing an already
/// staged deployment tree, classifying each file by role. Written to `out`
/// (the operator installs it beside the immutable tree as
/// `<deployment_root>.passport.json`).
///
/// # Errors
///
/// IO, an unclassifiable tree, contract-bound violations from the passport's
/// own `validate()`, or canonical encoding failure.
pub fn produce_passport(
    staged_root: &Path,
    recorded_root: &str,
    provider: &str,
    protocol: &str,
    version: &str,
    entrypoint: &str,
    out: &Path,
) -> Result<String, DogfoodProduceError> {
    let mut files = Vec::new();
    collect_runtime_files(staged_root, staged_root, entrypoint, &mut files)?;
    files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let aggregate_file_count = u32::try_from(files.len())
        .map_err(|_| produce_failed("DOGFOOD_PRODUCE_PASSPORT_INVALID", "too many files"))?;
    let aggregate_size_bytes = files.iter().map(|file| file.size).sum();
    let loader = files
        .iter()
        .find(|file| file.role == RuntimeFileRoleV1::Loader)
        .map(|file| bullet_harness_core::RuntimeLoaderV1::Dynamic {
            path: file.path.clone(),
            blake3: file.blake3.clone(),
        })
        .unwrap_or(bullet_harness_core::RuntimeLoaderV1::Static);
    let passport = ProviderRuntimePassportV1 {
        schema_version: bullet_harness_core::RUNTIME_PASSPORT_SCHEMA_VERSION,
        provider: provider.to_owned(),
        protocol: serde_json::from_value(Value::String(protocol.to_owned())).map_err(|error| {
            produce_failed("DOGFOOD_PRODUCE_PASSPORT_INVALID", error.to_string())
        })?,
        version: version.to_owned(),
        deployment_root: recorded_root.to_owned(),
        entrypoint: entrypoint.to_owned(),
        execution: bullet_harness_core::RuntimeExecutionV1::Native { loader },
        files,
        aggregate_file_count,
        aggregate_size_bytes,
    };
    passport
        .validate()
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_PASSPORT_INVALID", error.to_string()))?;
    let bytes = passport
        .canonical_bytes()
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_CANONICAL", error.to_string()))?;
    write_canonical_once(out, &bytes)
}

fn collect_runtime_files(
    root: &Path,
    directory: &Path,
    entrypoint: &str,
    files: &mut Vec<RuntimeFileV1>,
) -> Result<(), DogfoodProduceError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(produce_failed(
                "DOGFOOD_PRODUCE_PASSPORT_INVALID",
                format!("symlink {} in an immutable deployment", path.display()),
            ));
        }
        if metadata.is_dir() {
            collect_runtime_files(root, &path, entrypoint, files)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| produce_failed("DOGFOOD_PRODUCE_PASSPORT_INVALID", "path escape"))?
            .to_string_lossy()
            .into_owned();
        let bytes = fs::read(&path)
            .map_err(|error| produce_failed("DOGFOOD_PRODUCE_IO", error.to_string()))?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let role = if relative == entrypoint {
            RuntimeFileRoleV1::Entrypoint
        } else if name.starts_with("ld-linux") {
            RuntimeFileRoleV1::Loader
        } else if name.contains(".so") {
            RuntimeFileRoleV1::NativeLibrary
        } else if metadata.permissions().mode() & 0o111 != 0 {
            RuntimeFileRoleV1::Executable
        } else {
            RuntimeFileRoleV1::Resource
        };
        files.push(RuntimeFileV1 {
            path: relative,
            role,
            mode: metadata.mode() & 0o7777,
            size: metadata.len(),
            blake3: blake3::hash(&bytes).to_hex().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_producer_round_trips_the_board_shape() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("binding.json");
        let digest = produce_binding(&out).expect("produce");
        let bytes = fs::read(&out).unwrap();
        assert_eq!(blake3::hash(&bytes).to_hex().to_string(), digest);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 3);
        assert_eq!(object["audience"], "dogfood-runner");
        assert_eq!(object["operation"], "read-only-propose");
        assert_eq!(object["schema_version"], "v1alpha1");
        // JCS: keys in sorted order, no whitespace.
        assert!(bytes.starts_with(b"{\"audience\""));
        // Create-once: a second produce refuses.
        let error = produce_binding(&out).expect_err("overwrite refused");
        assert_eq!(error.code, "DOGFOOD_PRODUCE_EXISTS");
    }

    #[test]
    fn policy_producer_output_passes_the_dogfood_validator_and_stays_offline() {
        let dir = tempfile::tempdir().unwrap();
        // Base: the live-enabled fixture; the producer must force the flag to
        // false and the validator must then accept.
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/policy-v1alpha2-live-enabled.json");
        let mut fixture: serde_json::Value =
            serde_json::from_slice(&fs::read(&base).unwrap()).unwrap();
        let key = fixture["issuer_keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["key_purpose"] == "authority-signing")
            .expect("fixture carries a provider-runner authority key")
            .clone();
        // Simulate the real v1alpha1 base, which carries no issuer keys; the
        // producer appends the operator's one key. (Appending a duplicate is
        // refused by the validator -- proof-by-consumption catches it.)
        fixture["issuer_keys"] = serde_json::Value::Array(Vec::new());
        let stripped_base = dir.path().join("base.json");
        fs::write(&stripped_base, serde_json::to_vec(&fixture).unwrap()).unwrap();
        let key_path = dir.path().join("issuer-key.json");
        fs::write(&key_path, serde_json::to_vec(&key).unwrap()).unwrap();
        let out = dir.path().join("policy.json");
        produce_policy(&stripped_base, &key_path, &out).expect("produce");
        let produced: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_eq!(
            produced["sandbox_policy"]["live_admission_enabled"],
            serde_json::Value::Bool(false),
            "the producer must never emit a live-enabled policy"
        );
        assert_eq!(produced["policy_generation"], 2);
        assert_eq!(produced["schema_version"], "v1alpha2");
    }

    #[test]
    fn passport_producer_describes_a_staged_tree_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("claude").join("9.9.9-test");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("lib64")).unwrap();
        fs::write(root.join("bin/claude"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(root.join("bin/claude"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(root.join("lib64/ld-linux-x86-64.so.2"), b"loader").unwrap();
        fs::set_permissions(
            root.join("lib64/ld-linux-x86-64.so.2"),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        let out = dir.path().join("passport.json");
        produce_passport(
            &root,
            "/usr/lib/bullet/providers/claude/9.9.9-test",
            "claude",
            "claude_stream_json",
            "9.9.9-test",
            "bin/claude",
            &out,
        )
        .expect("produce");
        let bytes = fs::read(&out).unwrap();
        let passport = ProviderRuntimePassportV1::decode(&bytes).expect("canonical decode");
        assert_eq!(passport.aggregate_file_count, 2);
        assert_eq!(passport.entrypoint, "bin/claude");
        assert!(matches!(
            passport.execution,
            bullet_harness_core::RuntimeExecutionV1::Native {
                loader: bullet_harness_core::RuntimeLoaderV1::Dynamic { .. }
            }
        ));
    }
}
