use super::candidate_store;
use crate::sqlite::{authority as authority_store, context, graph, lease_time, leases};
use bullet_application::candidate_preparation::{
    CandidatePreparationAuthoritySnapshot, CandidatePreparationError, CandidatePreparationSource,
};
use bullet_application::{graph_digest, ActiveLeaseSubject, LeaseService, StoredGraph};
use bullet_domain::{Attempt, AttemptId, Candidate, CandidateId};
use chrono::DateTime;
use rusqlite::Connection;

pub(super) fn authority(
    conn: &Connection,
    attempt_id: &AttemptId,
) -> Result<CandidatePreparationAuthoritySnapshot, CandidatePreparationError> {
    let attempt = graph::get_attempt(conn, attempt_id)?
        .ok_or_else(|| candidate_store("Candidate-preparation Attempt is absent"))?;
    leases::check_active_lease_in(conn, &ActiveLeaseSubject::from_attempt(&attempt))?;
    let lease = leases::get_lease(conn, &attempt.variant_id)?
        .ok_or_else(|| candidate_store("Candidate-preparation lease is absent"))?;
    let graph = graph_for_attempt(conn, &attempt)?;
    context::require_revision(
        conn,
        &graph,
        &attempt.work_package_id,
        attempt.context_revision,
    )?;
    let (context_digest, context_plan): (String, String) = conn
        .query_row(
            "SELECT content_digest, plan_revision_id FROM context_capsules
             WHERE work_package_id = ?1 AND revision = ?2",
            rusqlite::params![
                attempt.work_package_id.as_str(),
                i64::try_from(attempt.context_revision).map_err(candidate_store)?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(candidate_store)?;
    if context_plan != graph.plan.id.as_str() {
        return Err(candidate_store(
            "context capsule plan differs from the durable graph",
        ));
    }
    let normalized = authority_store::current(conn)?;
    let token = LeaseService::token_for(&graph, &attempt)?;
    let now = lease_time::database_time(conn)?;
    Ok(CandidatePreparationAuthoritySnapshot {
        repository_id: graph.mission.repository_id.to_string(),
        mission_id: graph.mission.id.to_string(),
        plan_revision_id: graph.plan.id.to_string(),
        work_package_id: attempt.work_package_id.to_string(),
        variant_id: attempt.variant_id.to_string(),
        attempt_id: attempt.id.to_string(),
        attempt_fence: attempt.fence,
        runner_id: attempt.runner_id.to_string(),
        runner_epoch: attempt.runner_epoch,
        workspace_id: attempt.workspace_id.to_string(),
        scope_grant_digest: normalized.scope_digest().to_owned(),
        scope_revision: attempt.scope_revision,
        context_revision: attempt.context_revision,
        graph_revision_id: format!("grf_{}", graph_digest(&graph).to_hex()),
        context_capsule_id: format!("cnt_{context_digest}"),
        authority_token_digest: token
            .digest()
            .map_err(|error| CandidatePreparationError::Ledger(error.into()))?
            .to_hex(),
        authority_epoch: normalized.authority_epoch(),
        freeze_generation: normalized.freeze_generation(),
        now_unix_ms: unix_ms(&now)?,
        lease_expires_at_unix_ms: unix_ms(&lease.expires_at)?,
    })
}

pub(super) fn require_parents(
    conn: &Connection,
    source: &CandidatePreparationSource,
) -> Result<(), CandidatePreparationError> {
    source.validate()?;
    if source.root_change {
        return Ok(());
    }
    let attempt = graph::get_attempt(conn, &source.attempt_id)?
        .ok_or_else(|| candidate_store("Candidate-preparation Attempt is absent"))?;
    let current = graph_for_attempt(conn, &attempt)?;
    for raw in &source.parent_candidate_ids {
        let id = CandidateId::parse(raw)
            .map_err(|error| CandidatePreparationError::Ledger(error.into()))?;
        let parent: Candidate = graph::get_json_row(conn, "candidates", id.as_str())?
            .ok_or_else(|| CandidatePreparationError::Refused(format!("parent {id} is absent")))?;
        let parent_attempt = graph::get_attempt(conn, &parent.attempt_id)?
            .ok_or_else(|| candidate_store("parent Candidate Attempt is absent"))?;
        let parent_graph = graph_for_attempt(conn, &parent_attempt)?;
        if parent_graph.mission.repository_id != current.mission.repository_id {
            return Err(CandidatePreparationError::Refused(format!(
                "parent {id} belongs to another repository"
            )));
        }
    }
    Ok(())
}

fn graph_for_attempt(
    conn: &Connection,
    attempt: &Attempt,
) -> Result<StoredGraph, CandidatePreparationError> {
    let mut statement = conn
        .prepare("SELECT body FROM graphs ORDER BY mission_id")
        .map_err(candidate_store)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(candidate_store)?;
    let mut matches = Vec::new();
    for row in rows {
        let graph: StoredGraph = crate::sqlite::from_json(&row.map_err(candidate_store)?)?;
        let owns_variant = graph
            .variants
            .iter()
            .any(|item| item.id == attempt.variant_id);
        let owns_package = graph
            .packages
            .iter()
            .any(|item| item.id == attempt.work_package_id);
        if owns_variant && owns_package {
            matches.push(graph);
        }
    }
    match matches.as_slice() {
        [graph] => Ok(graph.clone()),
        [] => Err(candidate_store("Attempt is not owned by a durable graph")),
        _ => Err(candidate_store(
            "Attempt is ambiguously owned by multiple graphs",
        )),
    }
}

fn unix_ms(value: &str) -> Result<u64, CandidatePreparationError> {
    let value = DateTime::parse_from_rfc3339(value)
        .map_err(|_| candidate_store("authority time is not RFC 3339"))?
        .timestamp_millis();
    u64::try_from(value).map_err(|_| candidate_store("authority time precedes the epoch"))
}
