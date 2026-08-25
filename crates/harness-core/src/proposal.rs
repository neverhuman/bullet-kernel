//! `PatchProposal`: the only structured output the kernel accepts from a
//! provider turn. Authority-bearing fields mirror the frozen `bullet-wire`
//! schema; model narrative is retained only as non-authoritative metadata and
//! is never serialized to the writer.

use crate::error::HarnessError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

/// Frozen cross-repository schema version.
pub const PATCH_PROPOSAL_SCHEMA_VERSION: u32 = 1;
/// Maximum operations in one proposal.
pub const MAX_OPERATIONS: usize = 1_024;
/// Maximum UTF-8 bytes in one whole-file write.
pub const MAX_CONTENT_BYTES: usize = 1_048_576;
/// Maximum admitted gates in one proposal.
pub const MAX_GATE_IDS: usize = 16;

/// Expected state of a path before one mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Preimage {
    /// The path must not exist.
    Absent,
    /// The path must contain bytes with this exact BLAKE3 digest.
    Digest { digest: String },
}

/// Whole-file mutation. Provider text never becomes shell authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PatchMutation {
    /// Write the exact UTF-8 content.
    Write { content_utf8: String },
    /// Remove an existing regular file.
    Delete,
}

/// One preimage-bound repository mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    /// Canonical repository-relative path.
    pub path: String,
    /// Exact state required before mutation.
    pub preimage: Preimage,
    /// Requested whole-file mutation.
    pub mutation: PatchMutation,
}

/// A provider proposal. The seven authority-bearing fields serialize to the
/// exact `bullet-wire` shape. Narrative fields deserialize for review/UI use
/// but are deliberately skipped when Runner sends the proposal to BulletGit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchProposal {
    /// Frozen proposal schema.
    pub schema_version: u32,
    /// Content-addressed proposal subject.
    pub proposal_id: String,
    /// Attempt that produced this proposal.
    pub producing_attempt_id: String,
    /// Exact base checkpoint subject.
    pub base_checkpoint_id: String,
    /// Exact BLAKE3 digest of the base checkpoint.
    pub base_checkpoint_digest: String,
    /// Preimage-bound whole-file operations.
    pub operations: Vec<PatchOperation>,
    /// Ordered policy-admitted full-width gate identifiers.
    pub gate_ids: Vec<String>,
    /// Provider intent narrative. Never writer authority.
    #[serde(default, skip_serializing)]
    pub intent_summary: String,
    /// Provider assertions. Never evidence or writer authority.
    #[serde(default, skip_serializing)]
    pub claims: Vec<String>,
    /// Provider uncertainties. Never writer authority.
    #[serde(default, skip_serializing)]
    pub uncertainties: Vec<String>,
    /// Provider completion opinion. Deterministic gates decide completion.
    #[serde(default, skip_serializing)]
    pub done: bool,
}

impl PatchProposal {
    /// Parse and validate from a JSON string.
    pub fn parse_json(text: &str) -> Result<Self, HarnessError> {
        let proposal: Self =
            serde_json::from_str(text).map_err(|error| HarnessError::ProposalParse {
                reason: error.to_string(),
            })?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Parse and validate from an already-decoded JSON value.
    pub fn from_value(value: &Value) -> Result<Self, HarnessError> {
        let proposal: Self =
            serde_json::from_value(value.clone()).map_err(|error| HarnessError::ProposalParse {
                reason: error.to_string(),
            })?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Best-effort extraction from free text.
    pub fn extract_from_text(text: &str) -> Result<Self, HarnessError> {
        if let Ok(proposal) = Self::parse_json(text.trim()) {
            return Ok(proposal);
        }
        if let Some(inner) = fenced_block(text, "```json") {
            if let Ok(proposal) = Self::parse_json(inner) {
                return Ok(proposal);
            }
        }
        if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) {
            if start < end {
                if let Ok(proposal) = Self::parse_json(&text[start..=end]) {
                    return Ok(proposal);
                }
            }
        }
        Err(invalid("no JSON candidate parsed as a PatchProposal"))
    }

    /// Serialize only the exact authority-bearing `bullet-wire` subject.
    pub fn authoritative_value(&self) -> Result<Value, HarnessError> {
        self.validate()?;
        serde_json::to_value(self).map_err(|error| invalid(error.to_string()))
    }

    /// Structural and cross-field validation before any Runner write call.
    pub fn validate(&self) -> Result<(), HarnessError> {
        if self.schema_version != PATCH_PROPOSAL_SCHEMA_VERSION {
            return Err(invalid(format!(
                "unsupported schema_version {}; expected {PATCH_PROPOSAL_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        validate_prefixed_id(&self.proposal_id, "cnt_")?;
        validate_prefixed_id(&self.producing_attempt_id, "atm_")?;
        validate_prefixed_id(&self.base_checkpoint_id, "ckp_")?;
        validate_digest(&self.base_checkpoint_digest)?;
        validate_gate_ids(&self.gate_ids)?;
        validate_metadata(self)?;
        validate_operations(&self.operations)
    }
}

/// Validate canonical, bounded, unique full-width gate subjects.
pub fn validate_gate_ids(gate_ids: &[String]) -> Result<(), HarnessError> {
    if gate_ids.is_empty() || gate_ids.len() > MAX_GATE_IDS {
        return Err(invalid(format!(
            "gate_ids must contain 1..={MAX_GATE_IDS} entries"
        )));
    }
    let mut sorted = gate_ids.iter().map(String::as_str).collect::<Vec<_>>();
    for gate in &sorted {
        validate_prefixed_id(gate, "gat_")?;
    }
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("duplicate gate_id"));
    }
    Ok(())
}

/// The hand-written JSON Schema this struct must agree with.
#[must_use]
pub fn schema_source() -> &'static str {
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/schemas/patch-proposal.json"
    ))
}

fn validate_operations(operations: &[PatchOperation]) -> Result<(), HarnessError> {
    if operations.is_empty() || operations.len() > MAX_OPERATIONS {
        return Err(invalid(format!(
            "operations must contain 1..={MAX_OPERATIONS} entries"
        )));
    }
    let mut paths = BTreeMap::<String, &str>::new();
    for operation in operations {
        validate_repo_path(&operation.path)?;
        match (&operation.preimage, &operation.mutation) {
            (Preimage::Absent, PatchMutation::Delete) => {
                return Err(invalid(format!(
                    "delete {} requires a digest preimage",
                    operation.path
                )));
            }
            (Preimage::Digest { digest }, _) => validate_digest(digest)?,
            (Preimage::Absent, PatchMutation::Write { .. }) => {}
        }
        if let PatchMutation::Write { content_utf8 } = &operation.mutation {
            if content_utf8.len() > MAX_CONTENT_BYTES {
                return Err(invalid(format!(
                    "{} exceeds {MAX_CONTENT_BYTES} content bytes",
                    operation.path
                )));
            }
        }
        let key = operation
            .path
            .nfc()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if let Some(existing) = paths.insert(key, &operation.path) {
            return Err(invalid(format!(
                "path collision: {} conflicts with {existing}",
                operation.path
            )));
        }
    }
    let entries = paths.iter().collect::<Vec<_>>();
    for (index, (left_key, left)) in entries.iter().enumerate() {
        for (right_key, right) in &entries[index + 1..] {
            if contains_path(left_key, right_key) || contains_path(right_key, left_key) {
                return Err(invalid(format!(
                    "path conflict: {left} conflicts with {right}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_repo_path(path: &str) -> Result<(), HarnessError> {
    if path.is_empty() || path.len() > 4_096 || path.starts_with('/') || path.contains('\\') {
        return Err(invalid(format!("invalid repository path: {path:?}")));
    }
    if path.nfc().collect::<String>() != path {
        return Err(invalid(format!("path is not NFC normalized: {path:?}")));
    }
    for segment in path.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(invalid(format!("invalid path segment in {path:?}")));
        }
        if segment.eq_ignore_ascii_case(".git") {
            return Err(invalid(format!(".git is outside authority: {path:?}")));
        }
        if segment.contains(':')
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || segment.chars().any(char::is_control)
        {
            return Err(invalid(format!("platform-unsafe path: {path:?}")));
        }
    }
    Ok(())
}

fn validate_metadata(proposal: &PatchProposal) -> Result<(), HarnessError> {
    const MAX_TEXT: usize = 4_096;
    const MAX_ITEMS: usize = 128;
    if proposal.intent_summary.len() > MAX_TEXT
        || proposal.claims.len() > MAX_ITEMS
        || proposal.uncertainties.len() > MAX_ITEMS
        || proposal
            .claims
            .iter()
            .chain(&proposal.uncertainties)
            .any(|item| item.len() > MAX_TEXT)
    {
        return Err(invalid("model metadata exceeds bounded limits"));
    }
    Ok(())
}

fn validate_prefixed_id(raw: &str, prefix: &str) -> Result<(), HarnessError> {
    let body = raw
        .strip_prefix(prefix)
        .ok_or_else(|| invalid(format!("identifier must start with {prefix}")))?;
    validate_lower_hex(body)
}

fn validate_digest(raw: &str) -> Result<(), HarnessError> {
    validate_lower_hex(raw)
}

fn validate_lower_hex(raw: &str) -> Result<(), HarnessError> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("expected 64 lowercase hexadecimal characters"));
    }
    Ok(())
}

fn contains_path(parent: &str, child: &str) -> bool {
    child
        .strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn fenced_block<'a>(text: &'a str, fence: &str) -> Option<&'a str> {
    let start = text.find(fence)? + fence.len();
    let rest = &text[start..];
    let end = rest.find("```")?;
    Some(rest[..end].trim())
}

fn invalid(reason: impl Into<String>) -> HarnessError {
    HarnessError::ProposalParse {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn id(prefix: &str, nibble: char) -> String {
        format!("{prefix}{}", nibble.to_string().repeat(64))
    }

    fn sample() -> PatchProposal {
        PatchProposal {
            schema_version: PATCH_PROPOSAL_SCHEMA_VERSION,
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
            gate_ids: vec![id("gat_", '8')],
            intent_summary: "create PONG.txt".into(),
            claims: vec!["file exists".into()],
            uncertainties: vec![],
            done: true,
        }
    }

    #[test]
    fn parse_and_authoritative_serialization_are_distinct() {
        let mut input = sample().authoritative_value().unwrap();
        input["intent_summary"] = "create PONG.txt".into();
        input["claims"] = serde_json::json!(["file exists"]);
        input["uncertainties"] = serde_json::json!([]);
        input["done"] = true.into();
        let parsed = PatchProposal::from_value(&input).unwrap();
        let wire = parsed.authoritative_value().unwrap();
        assert_eq!(wire["schema_version"], 1);
        assert_eq!(wire["proposal_id"], sample().proposal_id);
        for metadata in ["intent_summary", "claims", "uncertainties", "done"] {
            assert!(wire.get(metadata).is_none(), "serialized {metadata}");
        }
        assert_eq!(PatchProposal::from_value(&wire).unwrap().intent_summary, "");
    }

    #[test]
    fn schema_and_authoritative_struct_agree() {
        let schema: Value = serde_json::from_str(schema_source()).unwrap();
        let required: BTreeSet<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(
            required,
            [
                "schema_version",
                "proposal_id",
                "producing_attempt_id",
                "base_checkpoint_id",
                "base_checkpoint_digest",
                "operations",
                "gate_ids",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["operations"]["maxItems"],
            MAX_OPERATIONS
        );
        assert_eq!(schema["properties"]["gate_ids"]["maxItems"], MAX_GATE_IDS);
    }

    #[test]
    fn rejects_malformed_subjects_and_legacy_shape() {
        for (field, replacement) in [
            ("proposal_id", Value::String(id("cnt_", 'A'))),
            ("producing_attempt_id", Value::String(id("bad_", 'a'))),
            (
                "base_checkpoint_id",
                Value::String(format!("ckp_{}", "a".repeat(63))),
            ),
            ("base_checkpoint_digest", Value::String("f".repeat(63))),
            ("gate_ids", serde_json::json!(["repo.gate.v1"])),
        ] {
            let mut value = sample().authoritative_value().unwrap();
            value[field] = replacement;
            assert!(
                PatchProposal::from_value(&value).is_err(),
                "admitted {field}"
            );
        }
        let legacy = serde_json::json!({
            "intent_summary": "x", "changes": [], "tests_to_run": ["touch PWNED"],
            "claims": [], "uncertainties": [], "done": true
        });
        assert!(PatchProposal::from_value(&legacy).is_err());
    }

    #[test]
    fn paths_collisions_bounds_and_delete_preimages_are_enforced() {
        for path in [
            "/etc/passwd",
            "../up",
            "a/../b",
            "a\\b",
            "a//b",
            ".git/config",
            "A/.GIT/config",
            "bad:/x",
            "trail./x",
            "",
            "cafe\u{301}.txt",
        ] {
            let mut proposal = sample();
            proposal.operations[0].path = path.into();
            assert!(proposal.validate().is_err(), "admitted {path:?}");
        }
        for second in ["pong.TXT", "PONG.txt/child", "pong.txt/child"] {
            let mut proposal = sample();
            let mut operation = proposal.operations[0].clone();
            operation.path = second.into();
            proposal.operations.push(operation);
            assert!(proposal.validate().is_err(), "admitted collision {second}");
        }
        let mut unicode_ancestor = sample();
        unicode_ancestor.operations[0].path = "Étage".into();
        let mut child = unicode_ancestor.operations[0].clone();
        child.path = "étage/file".into();
        unicode_ancestor.operations.push(child);
        assert!(unicode_ancestor.validate().is_err());
        let mut deletion = sample();
        deletion.operations[0].mutation = PatchMutation::Delete;
        assert!(deletion.validate().is_err());
        deletion.operations[0].preimage = Preimage::Digest {
            digest: "d".repeat(64),
        };
        assert!(deletion.validate().is_ok());
        let mut oversized = sample();
        oversized.operations[0].mutation = PatchMutation::Write {
            content_utf8: "x".repeat(MAX_CONTENT_BYTES + 1),
        };
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn extract_from_fenced_text() {
        let mut value = sample().authoritative_value().unwrap();
        value["intent_summary"] = "model note".into();
        let body = value.to_string();
        let text = format!("Here is the plan.\n```json\n{body}\n```\nDone.");
        assert_eq!(
            PatchProposal::extract_from_text(&text)
                .unwrap()
                .intent_summary,
            "model note"
        );
        assert!(PatchProposal::extract_from_text("no json here").is_err());
    }
}
