//! Read server-owned command identities without reconstructing or submitting work.
use super::{credentials::Session, http, journal};
use crate::client::{decode, models::CommandDiscoverySnapshot, terminal_text};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::IsTerminal;

pub(super) fn list(session: &Session, after: u64, limit: u32) -> Result<Value, String> {
    if after > 9_007_199_254_740_991 || !(1..=100).contains(&limit) {
        return Err("COMMAND_DISCOVERY_CURSOR_INVALID".into());
    }
    let response = http::request_query(
        &session.farmd,
        "GET",
        "/api/v1/commands",
        &[("after", &after.to_string()), ("limit", &limit.to_string())],
        &[("Cookie", &session.cookie), ("Origin", &session.origin)],
        None,
    )?;
    validate(session, response, after, limit)
}

fn validate(
    session: &Session,
    response: http::HttpResponse,
    after: u64,
    limit: u32,
) -> Result<Value, String> {
    if response.status != 200 {
        return Err(format!(
            "FARMD_COMMAND_DISCOVERY_REFUSED: HTTP {}",
            response.status
        ));
    }
    let page: CommandDiscoverySnapshot = decode(&response.body)?;
    if response.sequence != Some(page.as_of_sequence)
        || page.source != "bullet-kernel/sqlite-ledger"
        || after > page.as_of_sequence
        || page.data.commands.len() > limit as usize
        || page.data.next_after.is_some_and(|next| {
            next <= after || next > page.as_of_sequence || page.data.commands.is_empty()
        })
    {
        return Err("FARMD_COMMAND_DISCOVERY_INCOMPATIBLE".into());
    }
    let mut seen = BTreeSet::new();
    for command in &page.data.commands {
        if !seen.insert(&command.id) {
            return Err("FARMD_COMMAND_DISCOVERY_DUPLICATE".into());
        }
        let body = serde_json::to_value(command).map_err(|_| "FARMD_MODEL_ENCODING_FAILED")?;
        super::command_body(body.clone())?;
        if let Some(request) = journal::reconciliation_request(session, &command.id)? {
            journal::correlate(&request, &body)?;
        }
    }
    Ok(response.body)
}

pub(super) fn print(page: &Value, json: bool) {
    if json || !std::io::stdout().is_terminal() {
        super::print_json(&page.to_string());
        return;
    }
    println!(
        "OPERATOR COMMANDS · as_of_sequence {}",
        page["as_of_sequence"]
    );
    // This value has passed the generated model and semantic checks above.
    for command in page["data"]["commands"].as_array().into_iter().flatten() {
        println!(
            "{}  {}  {}",
            terminal_text(command["id"].as_str().unwrap_or_default()),
            terminal_text(command["kind"].as_str().unwrap_or_default()),
            terminal_text(command["status"].as_str().unwrap_or_default())
        );
    }
    println!("Command phases are server observations; completion receipts are unchecked.");
    if let Some(next) = page["data"]["next_after"].as_u64() {
        println!("Next page: bullet coding list --after {next} (use the same state directory)");
    } else {
        println!("End of this discovery pass.");
    }
}

#[cfg(all(test, unix))]
mod tests;
