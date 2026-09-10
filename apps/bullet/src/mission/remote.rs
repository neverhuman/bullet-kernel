//! Mission views from the same authenticated atomic snapshot as the console.
use crate::client::{models, terminal_text};
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct RemoteArgs {
    /// Private operator session saved by bullet auth login.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Optional endpoint check; must match the saved authenticated destination.
    #[arg(long)]
    farmd: Option<String>,
    /// Print the generated snapshot model as one JSON line.
    #[arg(long)]
    json: bool,
}

#[cfg(unix)]
fn snapshot(args: &RemoteArgs) -> Result<models::OperatorSnapshot, String> {
    let path = crate::auth::state_dir(args.state_dir.clone())?;
    let credentials = crate::auth::store::CredentialStore::open(&path)?
        .load()?
        .ok_or("AUTH_REQUIRED: run bullet auth login")?;
    if args
        .farmd
        .as_ref()
        .is_some_and(|address| address != &credentials.farmd)
    {
        return Err("AUTH_DESTINATION_MISMATCH: use the state directory for this endpoint".into());
    }
    crate::client::operator_snapshot(&credentials)
}

#[cfg(not(unix))]
fn snapshot(_args: &RemoteArgs) -> Result<models::OperatorSnapshot, String> {
    Err("AUTH_PRIVATE_STORE_UNSUPPORTED".into())
}

pub(super) fn list(args: &RemoteArgs) -> Result<(), String> {
    let snapshot = snapshot(args)?;
    if args.json {
        return super::print_line(&models::MissionListSnapshot {
            data: snapshot.data.missions,
            as_of_sequence: sequence(snapshot.as_of_sequence)?,
            observed_at: snapshot.observed_at,
            source: snapshot.source,
        });
    }
    provenance(&snapshot);
    if snapshot.data.graphs.is_empty() {
        println!("No missions in this observed snapshot.");
    }
    for graph in &snapshot.data.graphs {
        println!(
            "{} · {} · {} tasks · {}",
            graph.mission.id,
            terminal_text(&graph.mission.state),
            graph.packages.len(),
            terminal_text(&graph.mission.title)
        );
    }
    Ok(())
}

pub(super) fn status(args: &RemoteArgs, mission: &str) -> Result<(), String> {
    // Reject path/query injection before reading credentials or making a request.
    let mission = bullet_domain::MissionId::parse(mission)
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    let snapshot = snapshot(args)?;
    let graph = snapshot
        .data
        .graphs
        .iter()
        .find(|graph| graph.mission.id == mission.as_str())
        .ok_or_else(|| {
            format!(
                "MISSION_NOT_FOUND: {} absent at sequence {}",
                mission, snapshot.as_of_sequence
            )
        })?;
    if args.json {
        return super::print_line(&models::MissionSnapshot {
            data: graph.clone(),
            as_of_sequence: sequence(snapshot.as_of_sequence)?,
            observed_at: snapshot.observed_at.clone(),
            source: snapshot.source.clone(),
        });
    }
    provenance(&snapshot);
    println!(
        "{} · {} · {}",
        graph.mission.id,
        terminal_text(&graph.mission.state),
        terminal_text(&graph.mission.title)
    );
    println!("Repository: {}", graph.mission.repository_id);
    println!("Objective: {}", terminal_text(&graph.mission.objective));
    println!("{} tasks observed", graph.packages.len());
    for task in &graph.packages {
        println!(
            "{} · {} · {}",
            task.id,
            terminal_text(&task.state),
            terminal_text(&task.title)
        );
    }
    Ok(())
}

fn sequence(value: u64) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| "FARMD_SNAPSHOT_INCOMPATIBLE".into())
}

fn provenance(snapshot: &models::OperatorSnapshot) {
    println!(
        "Mission snapshot {} · observed {} · {}",
        snapshot.as_of_sequence,
        terminal_text(&snapshot.observed_at),
        terminal_text(&snapshot.source)
    );
}
