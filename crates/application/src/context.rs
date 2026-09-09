//! Immutable initial Context Capsules bound to materialized plan packages.

use crate::{LedgerError, StoredGraph};
use bullet_domain::{
    ContextCapsuleId, Digest, MissionId, PlanRevisionId, TaskClass, WorkPackage, WorkPackageId,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Exact schema of the initial, uncompressed plan-derived capsule.
pub const INITIAL_CONTEXT_CAPSULE_SCHEMA: &str = "bullet.context-capsule.initial.v1";

/// Immutable initial context supplied to a package before any provider runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCapsule {
    /// Content-derived capsule identity.
    pub id: ContextCapsuleId,
    /// Mission whose plan created the capsule.
    pub mission_id: MissionId,
    /// Exact work package receiving the context.
    pub work_package_id: WorkPackageId,
    /// Immutable plan revision that supplied the context.
    pub plan_revision_id: PlanRevisionId,
    /// Package-local capsule revision. This slice creates only revision one.
    pub revision: u64,
    /// Declared task class copied from the immutable plan.
    pub task_class: TaskClass,
    /// Mission objective carried into the initial context.
    pub objective: String,
    /// Package title carried into the initial context.
    pub package_title: String,
    /// Digest of every semantic field above except identity and record time.
    pub content_digest: Digest,
    /// Informational record time; never participates in capsule identity.
    pub recorded_at: String,
}

#[derive(Serialize)]
struct InitialContent<'a> {
    schema_version: &'static str,
    mission_id: &'a MissionId,
    work_package_id: &'a WorkPackageId,
    plan_revision_id: &'a PlanRevisionId,
    revision: u64,
    task_class: TaskClass,
    objective: &'a str,
    package_title: &'a str,
}

impl ContextCapsule {
    /// Derive revision one from exact materialized graph truth.
    ///
    /// # Errors
    ///
    /// Refuses a package from another graph or a malformed record time.
    pub fn initial(
        graph: &StoredGraph,
        package: &WorkPackage,
        recorded_at: &str,
    ) -> Result<Self, LedgerError> {
        if package.mission_id != graph.mission.id
            || package.plan_revision_id != graph.plan.id
            || !graph.packages.iter().any(|item| item.id == package.id)
        {
            return Err(LedgerError::Store(
                "context capsule package is not owned by the exact graph".into(),
            ));
        }
        validate_time(recorded_at)?;
        let content_digest = content_digest(
            &graph.mission.id,
            &package.id,
            &graph.plan.id,
            package.task_class,
            &graph.mission.objective,
            &package.title,
        )?;
        Ok(Self {
            id: ContextCapsuleId::from_seed(&content_digest.to_hex()),
            mission_id: graph.mission.id.clone(),
            work_package_id: package.id.clone(),
            plan_revision_id: graph.plan.id.clone(),
            revision: 1,
            task_class: package.task_class,
            objective: graph.mission.objective.clone(),
            package_title: package.title.clone(),
            content_digest,
            recorded_at: recorded_at.to_string(),
        })
    }

    /// Validate identity, content, revision, and record time after persistence.
    ///
    /// # Errors
    ///
    /// Returns a store failure for corrupt or unsupported persisted truth.
    pub fn validate(&self) -> Result<(), LedgerError> {
        validate_time(&self.recorded_at)?;
        if self.revision != 1 {
            return Err(LedgerError::Store(
                "unsupported context capsule revision".into(),
            ));
        }
        let expected = content_digest(
            &self.mission_id,
            &self.work_package_id,
            &self.plan_revision_id,
            self.task_class,
            &self.objective,
            &self.package_title,
        )?;
        if self.content_digest != expected
            || self.id != ContextCapsuleId::from_seed(&expected.to_hex())
        {
            return Err(LedgerError::Store(
                "context capsule identity or content digest is corrupt".into(),
            ));
        }
        Ok(())
    }

    fn same_subject(&self, expected: &Self) -> bool {
        self.id == expected.id
            && self.mission_id == expected.mission_id
            && self.work_package_id == expected.work_package_id
            && self.plan_revision_id == expected.plan_revision_id
            && self.revision == expected.revision
            && self.task_class == expected.task_class
            && self.objective == expected.objective
            && self.package_title == expected.package_title
            && self.content_digest == expected.content_digest
    }
}

/// Derive the complete initial capsule set for one graph.
///
/// # Errors
///
/// Refuses duplicate work-package identities or malformed inputs.
pub fn initial_context_capsules(
    graph: &StoredGraph,
    recorded_at: &str,
) -> Result<Vec<ContextCapsule>, LedgerError> {
    let mut packages = BTreeSet::new();
    let mut capsules = Vec::with_capacity(graph.packages.len());
    for package in &graph.packages {
        if !packages.insert(package.id.as_str()) {
            return Err(LedgerError::Store(
                "graph repeats a context capsule work package".into(),
            ));
        }
        capsules.push(ContextCapsule::initial(graph, package, recorded_at)?);
    }
    Ok(capsules)
}

/// Require exactly one valid revision-one capsule for every graph package.
/// Record times may differ from the caller's observation but semantic subjects may not.
///
/// # Errors
///
/// Missing, extra, duplicate, corrupt, or cross-graph rows fail closed.
pub fn validate_initial_context_set(
    graph: &StoredGraph,
    capsules: &[ContextCapsule],
) -> Result<(), LedgerError> {
    let mut actual = BTreeMap::new();
    for capsule in capsules {
        capsule.validate()?;
        if actual
            .insert(capsule.work_package_id.as_str(), capsule)
            .is_some()
        {
            return Err(LedgerError::Store(
                "context capsule set repeats a work package".into(),
            ));
        }
    }
    if actual.len() != graph.packages.len() {
        return Err(LedgerError::Store(
            "context capsule set is incomplete or contains foreign rows".into(),
        ));
    }
    for package in &graph.packages {
        let stored = actual.get(package.id.as_str()).ok_or_else(|| {
            LedgerError::Store(format!("context capsule missing for {}", package.id))
        })?;
        let expected = ContextCapsule::initial(graph, package, &stored.recorded_at)?;
        if !stored.same_subject(&expected) {
            return Err(LedgerError::Store(format!(
                "context capsule subject differs for {}",
                package.id
            )));
        }
    }
    Ok(())
}

fn content_digest(
    mission_id: &MissionId,
    work_package_id: &WorkPackageId,
    plan_revision_id: &PlanRevisionId,
    task_class: TaskClass,
    objective: &str,
    package_title: &str,
) -> Result<Digest, LedgerError> {
    Digest::of_json(&InitialContent {
        schema_version: INITIAL_CONTEXT_CAPSULE_SCHEMA,
        mission_id,
        work_package_id,
        plan_revision_id,
        revision: 1,
        task_class,
        objective,
        package_title,
    })
    .map_err(Into::into)
}

fn validate_time(recorded_at: &str) -> Result<(), LedgerError> {
    DateTime::parse_from_rfc3339(recorded_at)
        .map(|_| ())
        .map_err(|_| LedgerError::Store("context capsule record time is not RFC 3339".into()))
}
