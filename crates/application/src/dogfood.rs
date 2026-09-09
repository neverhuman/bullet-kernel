//! Read-only dogfood intent and create-once receipt (ADR 0015).
//!
//! Not a release receipt kind. Eligibility bits are hard-false and a `true`
//! value is refused. The record is unsigned and mode 0600.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Intent for one read-only dogfood turn.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DogfoodReadOnlyIntentV0 {
    /// Intent schema.
    pub schema_version: String,
    /// Provider wire name. Only `claude` is admitted in v0.
    pub provider: String,
    /// Enrolled runtime version, not the frozen conformance constant.
    pub enrolled_runtime_version: String,
    /// Absolute read-only working directory.
    pub workdir: String,
    /// Prompt for the plan-mode turn.
    pub prompt: String,
    /// Ordered admitted gate identifiers.
    pub gate_ids: Vec<String>,
    /// Cost cap in micro-USD.
    pub max_cost_micro_usd: u64,
}

impl DogfoodReadOnlyIntentV0 {
    pub const SCHEMA_VERSION: &'static str = "v0";

    /// Structural validation.
    ///
    /// # Errors
    ///
    /// `DogfoodError::Refused` for a malformed intent.
    pub fn validate(&self) -> Result<(), DogfoodError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(DogfoodError::Refused("intent schema must be v0"));
        }
        if self.provider != "claude" {
            return Err(DogfoodError::Refused("v0 admits only claude"));
        }
        if self.enrolled_runtime_version.is_empty()
            || self.workdir.is_empty()
            || self.prompt.is_empty()
        {
            return Err(DogfoodError::Refused("intent fields must be non-empty"));
        }
        if !self.workdir.starts_with('/') {
            return Err(DogfoodError::Refused("workdir must be absolute"));
        }
        Ok(())
    }
}

/// Create-once receipt for one read-only dogfood turn.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DogfoodReadOnlyReceiptV0 {
    /// Receipt schema.
    pub schema_version: String,
    /// Purpose-separated kind. Never a release receipt kind.
    pub kind: String,
    /// Class label. Must not match a release receipt kind.
    pub class: String,
    /// Release eligibility. Must be false.
    pub release_eligible: bool,
    /// Transaction eligibility. Must be false.
    pub transaction_eligible: bool,
    /// Live eligibility. Must be false.
    pub live_eligible: bool,
    /// Profile eligibility. Must be false.
    pub profile_eligible: bool,
    /// Candidate eligibility. Must be false.
    pub candidate_eligible: bool,
    /// SCM eligibility. Must be false.
    pub scm_eligible: bool,
    /// Effect eligibility. Must be false.
    pub effect_eligible: bool,
    /// Verification eligibility. Must be false.
    pub verification_eligible: bool,
    /// Custody label for this same-UID host.
    pub custody: String,
    /// BLAKE3 of the validated proposal bytes.
    pub proposal_blake3: String,
    /// Enrolled runtime version observed.
    pub enrolled_runtime_version: String,
    /// Observed wall time in milliseconds.
    pub wall_ms: u64,
    /// Provider-reported cost in micro-USD, when present.
    pub total_cost_micro_usd: Option<u64>,
}

impl DogfoodReadOnlyReceiptV0 {
    pub const SCHEMA_VERSION: &'static str = "v0";
    pub const KIND: &'static str = "DOGFOOD_READ_ONLY_RECEIPT";
    pub const CLASS: &'static str = "DOGFOOD_READ_ONLY";
    pub const CUSTODY: &'static str = "OPERATOR_LOCAL_KEY_SAME_UID";

    const RELEASE_KINDS: [&'static str; 9] = [
        "operations",
        "transaction",
        "forge",
        "containment",
        "provider",
        "rust-toolchain",
        "scanner",
        "artifact",
        "profile-closure",
    ];

    /// Structural validation. Eligibility `true` is refused.
    ///
    /// # Errors
    ///
    /// `DogfoodError::Refused` for a conflicting or unknown-shaped record.
    pub fn validate(&self) -> Result<(), DogfoodError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(DogfoodError::Refused("receipt schema must be v0"));
        }
        if self.kind != Self::KIND {
            return Err(DogfoodError::Refused(
                "receipt kind must be DOGFOOD_READ_ONLY_RECEIPT",
            ));
        }
        if self.class != Self::CLASS || Self::RELEASE_KINDS.contains(&self.class.as_str()) {
            return Err(DogfoodError::Refused("receipt class is a release kind"));
        }
        if self.release_eligible
            || self.transaction_eligible
            || self.live_eligible
            || self.profile_eligible
            || self.candidate_eligible
            || self.scm_eligible
            || self.effect_eligible
            || self.verification_eligible
        {
            return Err(DogfoodError::Refused("eligibility true is refused"));
        }
        if self.custody != Self::CUSTODY {
            return Err(DogfoodError::Refused(
                "custody must be OPERATOR_LOCAL_KEY_SAME_UID",
            ));
        }
        if self.proposal_blake3.len() != 64
            || !self
                .proposal_blake3
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DogfoodError::Refused(
                "proposal digest must be 64 lowercase hex",
            ));
        }
        Ok(())
    }
}

/// Fail-closed dogfood receipt errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DogfoodError {
    /// Structural refusal.
    Refused(&'static str),
    /// Filesystem failure.
    Io(String),
}

impl std::fmt::Display for DogfoodError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(formatter, "DOGFOOD_REFUSED: {reason}"),
            Self::Io(reason) => write!(formatter, "DOGFOOD_IO: {reason}"),
        }
    }
}

impl std::error::Error for DogfoodError {}

/// Write one create-once mode-0600 receipt. Overwrite is refused.
///
/// # Errors
///
/// Validation failure, existing path, or IO.
pub fn write_receipt(
    path: &Path,
    receipt: &DogfoodReadOnlyReceiptV0,
) -> Result<PathBuf, DogfoodError> {
    receipt.validate()?;
    let bytes = serde_json::to_vec(receipt).map_err(|error| DogfoodError::Io(error.to_string()))?;
    if bytes_windows_forbidden(&bytes) {
        return Err(DogfoodError::Refused(
            "serialized receipt contains a signing key",
        ));
    }
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                DogfoodError::Refused("receipt overwrite is refused")
            } else {
                DogfoodError::Io(error.to_string())
            }
        })?;
    write_0600(file, &bytes)?;
    Ok(path.to_path_buf())
}

fn bytes_windows_forbidden(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    ["\"sig\"", "signature", "\"mac\"", "\"seal\""]
        .iter()
        .any(|needle| text.contains(needle))
}

fn write_0600(mut file: File, bytes: &[u8]) -> Result<(), DogfoodError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| DogfoodError::Io(error.to_string()))?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| DogfoodError::Io(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{write_receipt, DogfoodError, DogfoodReadOnlyIntentV0, DogfoodReadOnlyReceiptV0};
    use std::os::unix::fs::PermissionsExt;

    fn valid_receipt() -> DogfoodReadOnlyReceiptV0 {
        DogfoodReadOnlyReceiptV0 {
            schema_version: DogfoodReadOnlyReceiptV0::SCHEMA_VERSION.to_owned(),
            kind: DogfoodReadOnlyReceiptV0::KIND.to_owned(),
            class: DogfoodReadOnlyReceiptV0::CLASS.to_owned(),
            release_eligible: false,
            transaction_eligible: false,
            live_eligible: false,
            profile_eligible: false,
            candidate_eligible: false,
            scm_eligible: false,
            effect_eligible: false,
            verification_eligible: false,
            custody: DogfoodReadOnlyReceiptV0::CUSTODY.to_owned(),
            proposal_blake3: "a".repeat(64),
            enrolled_runtime_version: "2.1.248".into(),
            wall_ms: 12,
            total_cost_micro_usd: Some(100),
        }
    }

    #[test]
    fn eligibility_true_and_unknown_fields_are_refused() {
        let mut receipt = valid_receipt();
        receipt.release_eligible = true;
        assert!(matches!(
            receipt.validate(),
            Err(DogfoodError::Refused("eligibility true is refused"))
        ));
        assert!(serde_json::from_str::<DogfoodReadOnlyReceiptV0>(
            r#"{"schema_version":"v0","kind":"DOGFOOD_READ_ONLY_RECEIPT","class":"DOGFOOD_READ_ONLY","release_eligible":false,"transaction_eligible":false,"live_eligible":false,"profile_eligible":false,"candidate_eligible":false,"scm_eligible":false,"effect_eligible":false,"verification_eligible":false,"custody":"OPERATOR_LOCAL_KEY_SAME_UID","proposal_blake3":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","enrolled_runtime_version":"2.1.248","wall_ms":1,"total_cost_micro_usd":null,"signature":"no"}"#
        )
        .is_err());
        let intent = DogfoodReadOnlyIntentV0 {
            schema_version: DogfoodReadOnlyIntentV0::SCHEMA_VERSION.to_owned(),
            provider: "claude".into(),
            enrolled_runtime_version: "2.1.248".into(),
            workdir: "/tmp".into(),
            prompt: "fix".into(),
            gate_ids: Vec::new(),
            max_cost_micro_usd: 1,
        };
        intent.validate().unwrap();
    }

    #[test]
    fn create_once_mode_0600_and_overwrite_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.json");
        write_receipt(&path, &valid_receipt()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.contains("signature"));
        assert!(!body.contains("\"sig\""));
        assert_eq!(
            write_receipt(&path, &valid_receipt()).unwrap_err(),
            DogfoodError::Refused("receipt overwrite is refused")
        );
    }
}
