//! `PatchProposal`: the only structured output the kernel accepts from a
//! provider turn (ADR 0001). Full-file contents per changed path so
//! application is deterministic and order-independent.

use crate::error::HarnessError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Whole-file change operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOp {
    /// New file.
    Create,
    /// Replace an existing file.
    Modify,
    /// Remove an existing file.
    Delete,
}

impl ChangeOp {
    /// All operations in schema order.
    pub const ALL: [ChangeOp; 3] = [ChangeOp::Create, ChangeOp::Modify, ChangeOp::Delete];

    /// Stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Delete => "delete",
        }
    }
}

/// One whole-file change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChange {
    /// Repository-relative path.
    pub path: String,
    /// Operation.
    pub op: ChangeOp,
    /// Complete new file contents; None if and only if op is delete.
    pub contents: Option<String>,
}

/// The provider's proposal. Claims are never evidence; done is not
/// authoritative — the deterministic gate decides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchProposal {
    /// One-paragraph intent.
    pub intent_summary: String,
    /// Whole-file changes.
    pub changes: Vec<FileChange>,
    /// Deterministic gate commands to run.
    pub tests_to_run: Vec<String>,
    /// Provider assertions.
    pub claims: Vec<String>,
    /// Provider uncertainties.
    pub uncertainties: Vec<String>,
    /// Completion claim.
    pub done: bool,
}

impl PatchProposal {
    /// Parse and validate from a JSON string.
    ///
    /// # Errors
    ///
    /// `PROPOSAL_PARSE_FAILED` on malformed JSON or an invalid proposal.
    pub fn parse_json(text: &str) -> Result<Self, HarnessError> {
        let proposal: Self =
            serde_json::from_str(text).map_err(|err| HarnessError::ProposalParse {
                reason: err.to_string(),
            })?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Parse and validate from an already-decoded JSON value.
    ///
    /// # Errors
    ///
    /// `PROPOSAL_PARSE_FAILED` on shape mismatch or an invalid proposal.
    pub fn from_value(value: &Value) -> Result<Self, HarnessError> {
        let proposal: Self =
            serde_json::from_value(value.clone()).map_err(|err| HarnessError::ProposalParse {
                reason: err.to_string(),
            })?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Best-effort extraction from free text: the whole text, a ```json
    /// fence, or the outermost brace span, in that order.
    ///
    /// # Errors
    ///
    /// `PROPOSAL_PARSE_FAILED` when no candidate parses and validates.
    pub fn extract_from_text(text: &str) -> Result<Self, HarnessError> {
        if let Ok(p) = Self::parse_json(text.trim()) {
            return Ok(p);
        }
        if let Some(inner) = fenced_block(text, "```json") {
            if let Ok(p) = Self::parse_json(inner) {
                return Ok(p);
            }
        }
        if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) {
            if start < end {
                if let Ok(p) = Self::parse_json(&text[start..=end]) {
                    return Ok(p);
                }
            }
        }
        Err(HarnessError::ProposalParse {
            reason: "no json candidate in text parsed as a PatchProposal".to_string(),
        })
    }

    /// Structural validation beyond serde shape.
    ///
    /// # Errors
    ///
    /// `PROPOSAL_PARSE_FAILED` on unsafe paths or op/contents disagreement.
    pub fn validate(&self) -> Result<(), HarnessError> {
        for change in &self.changes {
            let path = change.path.as_str();
            if path.is_empty()
                || path.starts_with('/')
                || path.contains('\0')
                || path.split('/').any(|seg| seg == "..")
            {
                return Err(HarnessError::ProposalParse {
                    reason: format!("path invalid: {path:?}"),
                });
            }
            match (change.op, change.contents.is_some()) {
                (ChangeOp::Delete, true) => {
                    return Err(HarnessError::ProposalParse {
                        reason: format!("delete carries contents: {path}"),
                    });
                }
                (ChangeOp::Create | ChangeOp::Modify, false) => {
                    return Err(HarnessError::ProposalParse {
                        reason: format!("{} without contents: {path}", change.op.as_str()),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// The hand-written JSON Schema this struct must agree with.
#[must_use]
pub fn schema_source() -> &'static str {
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/schemas/patch-proposal.json"
    ))
}

fn fenced_block<'a>(text: &'a str, fence: &str) -> Option<&'a str> {
    let start = text.find(fence)? + fence.len();
    let rest = &text[start..];
    let end = rest.find("```")?;
    Some(rest[..end].trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn sample() -> PatchProposal {
        PatchProposal {
            intent_summary: "create PONG.txt".into(),
            changes: vec![FileChange {
                path: "PONG.txt".into(),
                op: ChangeOp::Create,
                contents: Some("PONG\n".into()),
            }],
            tests_to_run: vec!["cat PONG.txt".into()],
            claims: vec!["file exists".into()],
            uncertainties: vec![],
            done: true,
        }
    }

    #[test]
    fn serde_round_trip() {
        let text = serde_json::to_string(&sample()).unwrap();
        let back = PatchProposal::parse_json(&text).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn schema_and_struct_agree() {
        let schema: Value = serde_json::from_str(schema_source()).unwrap();
        let required: BTreeSet<String> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let struct_fields: BTreeSet<String> = [
            "intent_summary",
            "changes",
            "tests_to_run",
            "claims",
            "uncertainties",
            "done",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(required, struct_fields);
        let props: BTreeSet<String> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(props, struct_fields);
        assert_eq!(schema["additionalProperties"], Value::Bool(false));

        let item = &schema["properties"]["changes"]["items"];
        let item_required: BTreeSet<String> = item["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let change_fields: BTreeSet<String> = ["path", "op", "contents"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(item_required, change_fields);
        let ops: Vec<&str> = item["properties"]["op"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let struct_ops: Vec<&str> = ChangeOp::ALL.iter().map(|op| op.as_str()).collect();
        assert_eq!(ops, struct_ops);
    }

    #[test]
    fn traversal_and_absolute_paths_rejected() {
        for path in ["/etc/passwd", "../up", "a/../b", ""] {
            let mut p = sample();
            p.changes[0].path = path.into();
            assert!(p.validate().is_err(), "{path:?}");
        }
    }

    #[test]
    fn op_contents_agreement_enforced() {
        let mut del = sample();
        del.changes[0].op = ChangeOp::Delete;
        assert!(del.validate().is_err());
        del.changes[0].contents = None;
        assert!(del.validate().is_ok());
        let mut create = sample();
        create.changes[0].contents = None;
        assert!(create.validate().is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["extra"] = Value::Bool(true);
        assert!(PatchProposal::from_value(&v).is_err());
    }

    #[test]
    fn extract_from_fenced_text() {
        let body = serde_json::to_string(&sample()).unwrap();
        let text = format!("Here is the plan.\n```json\n{body}\n```\nDone.");
        assert_eq!(PatchProposal::extract_from_text(&text).unwrap(), sample());
        assert!(PatchProposal::extract_from_text("no json here").is_err());
    }
}
