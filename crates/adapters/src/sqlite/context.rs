//! Normalized immutable initial Context Capsules (migration 0011).

use super::{from_json, store};
use bullet_application::{
    initial_context_capsules, validate_initial_context_set, ContextCapsule, LedgerError,
    StoredGraph,
};
use bullet_domain::{
    ContextCapsuleId, Digest, DomainError, MissionId, PlanRevisionId, TaskClass, WorkPackageId,
};
use rusqlite::{params, Connection};

const COLUMNS: &str = "id, mission_id, work_package_id, plan_revision_id, revision, \
                       task_class, objective, package_title, content_digest, recorded_at";

type ContextRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
);

pub(super) fn insert_initial_set(
    conn: &Connection,
    graph: &StoredGraph,
    recorded_at: &str,
) -> Result<(), LedgerError> {
    for capsule in initial_context_capsules(graph, recorded_at)? {
        capsule.validate()?;
        conn.execute(
            "INSERT INTO context_capsules (
               id, mission_id, work_package_id, plan_revision_id, revision,
               task_class, objective, package_title, content_digest, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                capsule.id.to_string(),
                capsule.mission_id.to_string(),
                capsule.work_package_id.to_string(),
                capsule.plan_revision_id.to_string(),
                i64::try_from(capsule.revision).map_err(store)?,
                task_class_name(capsule.task_class)?,
                capsule.objective,
                capsule.package_title,
                capsule.content_digest.to_hex(),
                capsule.recorded_at,
            ],
        )
        .map_err(store)?;
    }
    Ok(())
}

pub(super) fn list_all(conn: &Connection) -> Result<Vec<ContextCapsule>, LedgerError> {
    let capsules = read_many(
        conn,
        &format!("SELECT {COLUMNS} FROM context_capsules ORDER BY work_package_id, revision"),
        [],
    )?;
    let graph_bodies = {
        let mut statement = conn
            .prepare("SELECT body FROM graphs ORDER BY mission_id")
            .map_err(store)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(store)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store)?
    };
    let mut expected_rows = 0usize;
    for body in graph_bodies {
        let graph: StoredGraph = from_json(&body)?;
        let mission_capsules = capsules
            .iter()
            .filter(|capsule| capsule.mission_id == graph.mission.id)
            .cloned()
            .collect::<Vec<_>>();
        validate_initial_context_set(&graph, &mission_capsules)?;
        expected_rows = expected_rows
            .checked_add(graph.packages.len())
            .ok_or_else(|| LedgerError::Store("context capsule row count overflow".into()))?;
    }
    if expected_rows != capsules.len() {
        return Err(LedgerError::Store(
            "context capsule rows exist outside a materialized graph".into(),
        ));
    }
    Ok(capsules)
}

pub(super) fn require_initial_set(
    conn: &Connection,
    graph: &StoredGraph,
) -> Result<(), LedgerError> {
    let capsules = read_many(
        conn,
        &format!(
            "SELECT {COLUMNS} FROM context_capsules
             WHERE mission_id = ?1 ORDER BY work_package_id, revision"
        ),
        [graph.mission.id.as_str()],
    )?;
    validate_initial_context_set(graph, &capsules)
}

pub(super) fn require_revision(
    conn: &Connection,
    graph: &StoredGraph,
    package: &WorkPackageId,
    revision: u64,
) -> Result<(), LedgerError> {
    require_initial_set(conn, graph)?;
    if !graph
        .packages
        .iter()
        .any(|candidate| candidate.id == *package)
    {
        return Err(DomainError::StaleAuthority(format!(
            "context package {package} is not owned by graph {}",
            graph.mission.id
        ))
        .into());
    }
    if revision != 1 {
        return Err(DomainError::StaleAuthority(format!(
            "context revision {revision} is not the current revision 1 for {package}"
        ))
        .into());
    }
    Ok(())
}

fn read_many<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<Vec<ContextCapsule>, LedgerError> {
    let mut statement = conn.prepare(sql).map_err(store)?;
    let rows = statement
        .query_map(params, |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        })
        .map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(from_row(row.map_err(store)?)?);
    }
    Ok(out)
}

fn from_row(row: ContextRow) -> Result<ContextCapsule, LedgerError> {
    let (
        id,
        mission,
        package,
        plan,
        revision,
        task_class,
        objective,
        package_title,
        digest,
        recorded_at,
    ) = row;
    let capsule = ContextCapsule {
        id: ContextCapsuleId::parse(id)?,
        mission_id: MissionId::parse(mission)?,
        work_package_id: WorkPackageId::parse(package)?,
        plan_revision_id: PlanRevisionId::parse(plan)?,
        revision: u64::try_from(revision).map_err(store)?,
        task_class: parse_task_class(&task_class)?,
        objective,
        package_title,
        content_digest: Digest::from_hex(&digest)?,
        recorded_at,
    };
    capsule.validate()?;
    Ok(capsule)
}

fn task_class_name(task_class: TaskClass) -> Result<String, LedgerError> {
    let encoded = serde_json::to_string(&task_class).map_err(store)?;
    serde_json::from_str(&encoded).map_err(store)
}

fn parse_task_class(raw: &str) -> Result<TaskClass, LedgerError> {
    serde_json::from_value(serde_json::Value::String(raw.to_string())).map_err(store)
}
