use super::{encoding, validate_coding_subject, CodingTaskContract, RunCodingTaskPayload};
use bullet_domain::{DomainError, GateId, RepositoryId};
use std::collections::BTreeSet;

pub(super) fn payload(value: &RunCodingTaskPayload) -> Result<(), DomainError> {
    if value.schema_version != super::RUN_CODING_TASK_SCHEMA {
        return Err(encoding("unsupported task schema version"));
    }
    task(&value.task)?;
    let selected = &value.selection;
    crate::run_coding::validate_token("account_id", &selected.account_id, 64)?;
    crate::run_coding::validate_token("model", &selected.model, 128)?;
    if let Some(effort) = &selected.effort {
        crate::run_coding::validate_token("effort", effort, 32)?;
    }
    Ok(())
}

pub(super) fn task(value: &CodingTaskContract) -> Result<(), DomainError> {
    text("title", &value.title, 240, false)?;
    text("objective", &value.objective, 8192, true)?;
    RepositoryId::parse(&value.repository_id)?;
    if !matches!(value.base_commit.len(), 40 | 64)
        || !value
            .base_commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(encoding(
            "base_commit must be an exact lowercase Git object id",
        ));
    }
    strings("scope_paths", &value.scope_paths, 1, 128)?;
    for path in &value.scope_paths {
        text("scope path", path, 512, false)?;
        if path.starts_with('/')
            || path.contains('\\')
            || path.split('/').any(|part| {
                part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case(".git")
            })
        {
            return Err(encoding(
                "scope paths must be normalized and repository-relative",
            ));
        }
    }
    strings("acceptance_criteria", &value.acceptance_criteria, 1, 32)?;
    for criterion in &value.acceptance_criteria {
        text("acceptance criterion", criterion, 1024, true)?;
    }
    strings("gate_ids", &value.gate_ids, 1, 16)?;
    for gate in &value.gate_ids {
        GateId::parse(gate)?;
    }
    strings("dependencies", &value.dependencies, 0, 64)?;
    for dependency in &value.dependencies {
        validate_coding_subject(dependency, "ctr_")?;
    }
    if !(1..=16).contains(&value.budget.max_invocations)
        || !(1..=1_000_000_000).contains(&value.budget.max_cost_microusd)
        || !(1..=super::MAX_CODING_SAFE_INTEGER).contains(&value.deadline_unix_ms)
    {
        return Err(encoding(
            "budget or deadline is outside the supported range",
        ));
    }
    Ok(())
}

fn text(field: &str, value: &str, maximum: usize, multiline: bool) -> Result<(), DomainError> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|c| c.is_control() && !(multiline && matches!(c, '\n' | '\t')))
    {
        return Err(encoding(format!(
            "{field} must contain 1..={maximum} admitted UTF-8 bytes"
        )));
    }
    Ok(())
}

fn strings(
    field: &str,
    values: &[String],
    minimum: usize,
    maximum: usize,
) -> Result<(), DomainError> {
    if !(minimum..=maximum).contains(&values.len())
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(encoding(format!(
            "{field} must contain {minimum}..={maximum} unique entries"
        )));
    }
    Ok(())
}
