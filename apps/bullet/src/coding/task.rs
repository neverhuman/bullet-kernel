//! Task-file admission input and validated owner snapshot consumer.
use super::{credentials::Session, http, journal};
use crate::client::{decode, models, terminal_text};
use bullet_application::coding_tasks::{
    coding_run_id, CodingRuntimeSelection, CodingTaskContract, RunCodingTaskPayload,
    RUN_CODING_TASK_SCHEMA,
};
use std::{io::Read, path::Path};

#[cfg(test)]
mod tests;

pub(super) fn load_contract(path: &Path) -> Result<CodingTaskContract, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "CODING_TASK_FILE_UNREADABLE")?;
    if !file
        .metadata()
        .map_err(|_| "CODING_TASK_FILE_UNREADABLE")?
        .is_file()
    {
        return Err("CODING_TASK_FILE_INVALID: expected a regular JSON file".into());
    }
    let mut bytes = Vec::new();
    file.take(262_145)
        .read_to_end(&mut bytes)
        .map_err(|_| "CODING_TASK_FILE_UNREADABLE")?;
    if bytes.len() > 262_144 {
        return Err("CODING_TASK_FILE_TOO_LARGE".into());
    }
    let contract: CodingTaskContract =
        serde_json::from_slice(&bytes).map_err(|_| "CODING_TASK_FILE_INVALID")?;
    contract
        .canonical_json()
        .map_err(|_| "CODING_TASK_FILE_INVALID")?;
    Ok(contract)
}

pub(super) fn payload(
    task: CodingTaskContract,
    account: &str,
    provider: &str,
    model: &str,
    effort: Option<&str>,
) -> Result<RunCodingTaskPayload, String> {
    if provider == "sim" {
        return Err("COMMAND_CODING_SIM_REFUSED".into());
    }
    let provider = serde_json::from_value(serde_json::json!(provider))
        .map_err(|_| "CODING_PROVIDER_INVALID")?;
    let payload = RunCodingTaskPayload {
        schema_version: RUN_CODING_TASK_SCHEMA.into(),
        task,
        selection: CodingRuntimeSelection {
            account_id: account.into(),
            provider,
            model: model.into(),
            effort: effort.map(str::to_owned),
        },
    };
    payload.validate().map_err(|_| "COMMAND_TASK_INVALID")?;
    Ok(payload)
}

pub(super) fn refusal(response: &http::HttpResponse) -> String {
    match decode::<models::Problem>(&response.body) {
        Ok(problem) if problem.status == u64::from(response.status) => format!(
            "{}: {}",
            terminal_text(&problem.code),
            terminal_text(&problem.repair)
        ),
        _ => format!(
            "FARMD_COMMAND_REFUSED: HTTP {} with invalid problem details",
            response.status
        ),
    }
}

pub(super) fn get(session: &Session, id: &str) -> Result<models::CodingRunSnapshot, String> {
    let id = bullet_domain::CommandId::parse(id).map_err(|_| "COMMAND_ID_INVALID")?;
    let recorded = journal::reconciliation_request(session, id.as_str())?;
    let response = http::request(
        &session.farmd,
        "GET",
        &format!("/api/v1/commands/{id}/coding"),
        &[("Cookie", &session.cookie), ("Origin", &session.origin)],
        None,
    )?;
    if response.status != 200 {
        return Err(refusal(&response));
    }
    let snapshot = validate(response, &id)?;
    if let Some(request) = recorded {
        let command =
            serde_json::to_value(&snapshot.data.command).map_err(|_| "FARMD_MODEL_INVALID")?;
        journal::correlate(&request, &command)?;
        let requested = bullet_application::coding_tasks::task_payload(&request)
            .map_err(|_| "COMMAND_JOURNAL_CORRUPT")?
            .ok_or("FARMD_CODING_SUBJECT_MISMATCH")?;
        if serde_json::to_value(&requested.task).map_err(|_| "COMMAND_JOURNAL_CORRUPT")?
            != serde_json::to_value(&snapshot.data.task).map_err(|_| "FARMD_MODEL_INVALID")?
            || serde_json::to_value(&requested.selection).map_err(|_| "COMMAND_JOURNAL_CORRUPT")?
                != serde_json::to_value(&snapshot.data.selection)
                    .map_err(|_| "FARMD_MODEL_INVALID")?
        {
            return Err("FARMD_CODING_SUBJECT_MISMATCH".into());
        }
    }
    Ok(snapshot)
}

fn validate(
    response: http::HttpResponse,
    id: &bullet_domain::CommandId,
) -> Result<models::CodingRunSnapshot, String> {
    let snapshot: models::CodingRunSnapshot = decode(&response.body)?;
    let accepted = chrono::DateTime::parse_from_rfc3339(&snapshot.data.accepted_at)
        .map_err(|_| "FARMD_CODING_TIME_INVALID")?;
    let observed = chrono::DateTime::parse_from_rfc3339(&snapshot.observed_at)
        .map_err(|_| "FARMD_CODING_TIME_INVALID")?;
    if snapshot.as_of_sequence == 0
        || response.sequence != Some(snapshot.as_of_sequence)
        || snapshot.data.command.id != id.as_str()
        || snapshot.data.command.kind != "run_coding"
        || snapshot.data.run_id != coding_run_id(id)
        || accepted > observed
    {
        return Err("FARMD_CODING_SUBJECT_MISMATCH".into());
    }
    super::command_body(
        serde_json::to_value(&snapshot.data.command).map_err(|_| "FARMD_MODEL_INVALID")?,
    )?;
    let public_payload = serde_json::json!({"schema_version":RUN_CODING_TASK_SCHEMA,"task":snapshot.data.task,"selection":snapshot.data.selection});
    RunCodingTaskPayload::parse(&public_payload.to_string())
        .map_err(|_| "FARMD_CODING_TASK_INVALID")?;
    // Public ingress accepts a JSON map. Reproduce that exact encoding, not
    // Rust struct field order; request digests deliberately exclude the key.
    let request = bullet_application::CommandRequest::new(
        "coding-observation",
        "run_coding",
        &public_payload,
    )
    .map_err(|_| "FARMD_CODING_TASK_INVALID")?;
    if request.digest().to_hex() != snapshot.data.command.payload_digest {
        return Err("FARMD_CODING_SUBJECT_MISMATCH".into());
    }
    Ok(snapshot)
}

pub(super) fn print(snapshot: &models::CodingRunSnapshot, json: bool) {
    if json {
        super::print_json(&serde_json::to_string(snapshot).expect("validated scalar model"));
        return;
    }
    println!("{}", format_task(snapshot));
}

fn format_task(snapshot: &models::CodingRunSnapshot) -> String {
    let run = &snapshot.data;
    let command = serde_json::to_value(&run.command).expect("validated scalar model");
    let mut lines = vec![
        super::render::format_command_card(&command, false),
        format!(
            "{}\nrun {}\ntask {}\n{} / {} / {}",
            terminal_text(&run.task.title),
            run.run_id,
            run.task_revision_id,
            terminal_text(&run.selection.provider),
            terminal_text(&run.selection.account_id),
            terminal_text(&run.selection.model)
        ),
    ];
    for blocker in &run.blockers {
        lines.push(format!(
            "blocked: {}{}",
            terminal_text(&blocker.code),
            blocker
                .subject
                .as_ref()
                .map(|subject| format!(" ({})", terminal_text(subject)))
                .unwrap_or_default()
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
pub(super) fn fixture() -> CodingTaskContract {
    serde_json::from_value(serde_json::json!({
        "title":"Task journal fixture", "objective":"Preserve request identity",
        "repository_id":format!("rep_{}","ab".repeat(32)),"base_commit":"ab".repeat(20),
        "scope_paths":["src/lib.rs"], "acceptance_criteria":["Exact retry"],
        "gate_ids":[format!("gat_{}","cd".repeat(32))],"dependencies":[],
        "budget":{"max_invocations":2,"max_cost_microusd":1000},"deadline_unix_ms":4_102_444_800_000u64
    })).unwrap()
}
