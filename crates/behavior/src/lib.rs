//! Planned spec §17 catalog plus non-authoritative detector scaffolds.

pub mod catalog;
pub mod detect;

pub use catalog::{row_by_id, CatalogRow, SPEC_ROWS};
pub use detect::{detect, BehaviorEvent, ObservedAction, DETECTOR_SCAFFOLD_IDS};

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::Enforcement;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_has_every_spec_id_and_correct_titles() {
        let ids: BTreeSet<&str> = SPEC_ROWS.iter().map(|row| row.id).collect();
        assert_eq!(ids.len(), SPEC_ROWS.len());
        assert_eq!(SPEC_ROWS.len(), 84);
        assert_eq!(
            row_by_id("FS001").map(|row| row.title),
            Some("Writes outside assigned workspace")
        );
        assert_eq!(
            row_by_id("FS004").map(|row| row.title),
            Some("Writes runtime/provider configuration into product repository")
        );
        assert_eq!(
            row_by_id("CP001").map(|row| row.title),
            Some("Emits done with dirty workspace")
        );
        assert_eq!(
            row_by_id("CP002").map(|row| row.title),
            Some("Emits done without exact Candidate")
        );
        assert!(
            DETECTOR_SCAFFOLD_IDS
                .iter()
                .all(|id| row_by_id(id).is_some()),
            "every detector scaffold must reference a planned catalog row"
        );
        assert!(DETECTOR_SCAFFOLD_IDS.len() < SPEC_ROWS.len());
    }

    #[test]
    fn detectors_fire_fail_closed() {
        let worktree = detect(&ObservedAction {
            is_worktree: Some(true),
            ..ObservedAction::default()
        });
        assert!(worktree.iter().any(|hit| hit.rule_id == "GT001"));

        let cleanup = detect(&ObservedAction {
            cleanup: true,
            has_preservation_receipt: None,
            observation_kind: Some("unknown".into()),
            ..ObservedAction::default()
        });
        let rules: BTreeSet<&str> = cleanup.iter().map(|hit| hit.rule_id.as_str()).collect();
        assert!(rules.contains("CL001"));
        assert!(rules.contains("CL002"));

        let done = detect(&ObservedAction {
            done: true,
            dirty_workspace: None,
            candidate_id: None,
            ..ObservedAction::default()
        });
        let rules: BTreeSet<&str> = done.iter().map(|hit| hit.rule_id.as_str()).collect();
        assert!(rules.contains("CP001"));
        assert!(rules.contains("CP002"));
        assert_eq!(
            row_by_id("CP002").map(|row| row.action),
            Some(Enforcement::Block)
        );
    }
}
