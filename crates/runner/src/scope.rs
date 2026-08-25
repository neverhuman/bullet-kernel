//! Change-intent scope validation. Every proposed path is checked against
//! the granted prefixes BEFORE any apply call (ADR 0001 W4/W5); bullet-gitd
//! re-validates as defence in depth.

use crate::error::RunnerError;
use bullet_harness_core::PatchProposal;

/// Refuse the first out-of-scope path in a proposal.
///
/// # Errors
///
/// Returns typed `SCOPE_DENIED` carrying the offending path.
pub fn validate_proposal(prefixes: &[String], proposal: &PatchProposal) -> Result<(), RunnerError> {
    for operation in &proposal.operations {
        if !path_in_scope(prefixes, &operation.path) {
            return Err(RunnerError::ScopeDenied {
                path: operation.path.clone(),
            });
        }
    }
    Ok(())
}

/// Segment-wise prefix match on normalized relative paths.
#[must_use]
pub fn path_in_scope(prefixes: &[String], path: &str) -> bool {
    let Some(segments) = normalize(path) else {
        return false;
    };
    prefixes.iter().any(|prefix| {
        normalize(prefix).is_some_and(|granted| {
            !granted.is_empty()
                && segments.len() >= granted.len()
                && segments[..granted.len()] == granted[..]
        })
    })
}

fn normalize(path: &str) -> Option<Vec<&str>> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    for segment in &segments {
        if segment.is_empty()
            || *segment == "."
            || *segment == ".."
            || segment.eq_ignore_ascii_case(".git")
        {
            return None;
        }
    }
    Some(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants() -> Vec<String> {
        vec!["src".into(), "PONG.txt".into()]
    }

    #[test]
    fn prefix_match_is_segment_wise() {
        assert!(path_in_scope(&grants(), "src/lib.rs"));
        assert!(path_in_scope(&grants(), "src"));
        assert!(path_in_scope(&grants(), "PONG.txt"));
        assert!(!path_in_scope(&grants(), "srcery/lib.rs"));
        assert!(!path_in_scope(&grants(), "secrets/key.txt"));
    }

    #[test]
    fn hostile_paths_are_rejected() {
        for path in [
            "/etc/passwd",
            "../up.txt",
            "src/../PONG.txt",
            "src/.git/config",
            "src//x",
            "src\\x",
            "",
            ".",
        ] {
            assert!(!path_in_scope(&grants(), path), "{path:?}");
        }
    }

    #[test]
    fn validate_names_the_offending_path() {
        let proposal = PatchProposal {
            schema_version: 1,
            proposal_id: format!("cnt_{}", "1".repeat(64)),
            producing_attempt_id: format!("atm_{}", "2".repeat(64)),
            base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
            base_checkpoint_digest: "4".repeat(64),
            intent_summary: "x".into(),
            operations: vec![bullet_harness_core::PatchOperation {
                path: "secrets/key.txt".into(),
                preimage: bullet_harness_core::Preimage::Absent,
                mutation: bullet_harness_core::PatchMutation::Write {
                    content_utf8: "k".into(),
                },
            }],
            gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
            claims: vec![],
            uncertainties: vec![],
            done: true,
        };
        let err = validate_proposal(&grants(), &proposal).unwrap_err();
        assert_eq!(err.reason_code(), "SCOPE_DENIED");
        assert!(err.to_string().contains("secrets/key.txt"));
    }
}
