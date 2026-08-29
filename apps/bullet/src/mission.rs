//! `bullet mission`: materialize one plan revision into the local ledger and
//! read a mission graph back. Both verbs admit `--data-dir` through the same
//! private-directory path as `farm init` and open the ledger only through the
//! SQLite adapter. Every refusal carries a stable reason code before any
//! detail text; success prints exactly one canonical JSON line.

use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, LeaseService, Ledger, LedgerError, PlanInput, StoredGraph,
};
use bullet_domain::{MissionId, TaskClass};
use chrono::Utc;
use clap::{Args, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Most work packages one plan revision may carry through this verb.
const MAX_PACKAGES: usize = 64;
/// Name of the ledger inside an admitted data directory.
const LEDGER_FILE: &str = "ledger.sqlite";

const INPUT_INVALID: &str = "MISSION_INPUT_INVALID";
const CLASS_INVALID: &str = "MISSION_PACKAGE_CLASS_INVALID";
const DATA_DIR_INVALID: &str = "MISSION_DATA_DIR_INVALID";
const LEDGER_ABSENT: &str = "MISSION_LEDGER_ABSENT";
const NOT_FOUND: &str = "MISSION_NOT_FOUND";

/// `bullet mission ...`
#[derive(Subcommand)]
pub(super) enum MissionCommands {
    /// Materialize one plan revision. Replaying the same seed and input prints
    /// the same ids; the same seed with a different input is refused.
    Materialize(MaterializeArgs),
    /// Print the stored graph for one materialized mission.
    Status(StatusArgs),
}

/// Inputs for `mission materialize`.
#[derive(Args)]
pub(super) struct MaterializeArgs {
    /// Absolute, caller-owned 0700 Kernel data directory.
    #[arg(long)]
    data_dir: PathBuf,
    /// Idempotency seed. Every id in the graph derives from it.
    #[arg(long)]
    seed: String,
    /// Mission title.
    #[arg(long)]
    title: String,
    /// Mission objective.
    #[arg(long)]
    objective: String,
    /// Work package as `TITLE:CLASS`; repeatable, at most 64.
    #[arg(long = "package", value_name = "TITLE:CLASS")]
    packages: Vec<String>,
}

/// Inputs for `mission status`.
#[derive(Args)]
pub(super) struct StatusArgs {
    /// Absolute, caller-owned 0700 Kernel data directory.
    #[arg(long)]
    data_dir: PathBuf,
    /// Mission id printed by `mission materialize`.
    #[arg(long)]
    mission: String,
}

/// One JSON line naming every id the materialization produced.
#[derive(Serialize)]
struct MaterializeReceipt<'a> {
    mission_id: &'a MissionId,
    plan_revision_id: &'a bullet_domain::PlanRevisionId,
    canonical_hash: String,
    packages: Vec<PackageReceipt<'a>>,
}

#[derive(Serialize)]
struct PackageReceipt<'a> {
    work_package_id: &'a bullet_domain::WorkPackageId,
    variant_id: &'a bullet_domain::VariantId,
    title: &'a str,
    task_class: TaskClass,
}

pub(super) fn run(command: MissionCommands) -> Result<(), String> {
    match command {
        MissionCommands::Materialize(args) => materialize(&args),
        MissionCommands::Status(args) => status(&args),
    }
}

fn materialize(args: &MaterializeArgs) -> Result<(), String> {
    let input = plan_input(args)?;
    let mut ledger = open_ledger(&args.data_dir)?;
    let now = LeaseService::rfc3339(Utc::now());
    let graph = materialize_plan(&mut ledger, &args.seed, &input, &now).map_err(ledger_failure)?;
    let receipt = MaterializeReceipt {
        mission_id: &graph.mission.id,
        plan_revision_id: &graph.plan.id,
        canonical_hash: graph.plan.canonical_hash.to_hex(),
        packages: graph
            .packages
            .iter()
            .zip(&graph.variants)
            .map(|(package, variant)| PackageReceipt {
                work_package_id: &package.id,
                variant_id: &variant.id,
                title: &package.title,
                task_class: package.task_class,
            })
            .collect(),
    };
    print_line(&receipt)
}

fn status(args: &StatusArgs) -> Result<(), String> {
    let mission_id = MissionId::parse(&args.mission)
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    require_absolute(&args.data_dir)?;
    if !args.data_dir.join(LEDGER_FILE).is_file() {
        return Err(format!(
            "{LEDGER_ABSENT}: no {LEDGER_FILE} under {}; run `mission materialize` first",
            args.data_dir.display()
        ));
    }
    let ledger = open_ledger(&args.data_dir)?;
    let graph: StoredGraph = ledger
        .get_graph(&mission_id)
        .map_err(ledger_failure)?
        .ok_or_else(|| {
            format!(
                "{NOT_FOUND}: mission {} is not materialized under {}",
                mission_id.as_str(),
                args.data_dir.display()
            )
        })?;
    print_line(&graph)
}

fn plan_input(args: &MaterializeArgs) -> Result<PlanInput, String> {
    for (flag, value) in [
        ("--seed", &args.seed),
        ("--title", &args.title),
        ("--objective", &args.objective),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{INPUT_INVALID}: {flag} must not be empty"));
        }
    }
    if args.packages.is_empty() {
        return Err(format!(
            "{INPUT_INVALID}: at least one --package TITLE:CLASS is required"
        ));
    }
    if args.packages.len() > MAX_PACKAGES {
        return Err(format!(
            "{INPUT_INVALID}: {} packages exceed the limit of {MAX_PACKAGES}",
            args.packages.len()
        ));
    }
    let packages = args
        .packages
        .iter()
        .enumerate()
        .map(|(index, raw)| package(index, raw))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PlanInput {
        title: args.title.clone(),
        objective: args.objective.clone(),
        packages,
    })
}

fn package(index: usize, raw: &str) -> Result<(String, TaskClass), String> {
    let Some((title, class)) = raw.rsplit_once(':') else {
        return Err(format!(
            "{INPUT_INVALID}: package {index} {raw:?} is not TITLE:CLASS"
        ));
    };
    if title.trim().is_empty() {
        return Err(format!(
            "{INPUT_INVALID}: package {index} title must not be empty"
        ));
    }
    let task_class = task_class(class).ok_or_else(|| {
        format!(
            "{CLASS_INVALID}: package {index} class {class:?} is not a bullet_domain::TaskClass"
        )
    })?;
    Ok((title.to_owned(), task_class))
}

/// Decode a `TaskClass` by its frozen snake_case wire name and require the
/// exact canonical roundtrip, so only the domain's own spellings are admitted.
fn task_class(raw: &str) -> Option<TaskClass> {
    let wire = serde_json::Value::String(raw.to_owned());
    let class: TaskClass = serde_json::from_value(wire.clone()).ok()?;
    (serde_json::to_value(class).ok()? == wire).then_some(class)
}

fn require_absolute(data_dir: &Path) -> Result<(), String> {
    if data_dir.is_absolute() {
        Ok(())
    } else {
        Err(format!("{DATA_DIR_INVALID}: --data-dir must be absolute"))
    }
}

/// The same admission `farm init` uses: absolute, caller-owned, exact 0700,
/// no symlink; then the ledger opens only through the SQLite adapter.
fn open_ledger(data_dir: &Path) -> Result<SqliteLedger, String> {
    require_absolute(data_dir)?;
    super::ensure_private_data_dir(data_dir)
        .map_err(|error| format!("{DATA_DIR_INVALID}: {error}"))?;
    SqliteLedger::open(data_dir.join(LEDGER_FILE)).map_err(ledger_failure)
}

fn ledger_failure(error: LedgerError) -> String {
    format!("{}: {error}", error.reason_code())
}

fn print_line(value: &impl Serialize) -> Result<(), String> {
    let line = serde_json::to_string(value)
        .map_err(|error| format!("ENCODING_FAILURE: encode mission output: {error}"))?;
    println!("{line}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_class_admits_only_domain_wire_names() {
        assert_eq!(
            task_class("mechanical_code_edit"),
            Some(TaskClass::MechanicalCodeEdit)
        );
        assert_eq!(task_class("code_review"), Some(TaskClass::CodeReview));
        for hostile in [
            "MechanicalCodeEdit",
            "mechanical-code-edit",
            "",
            " code_review",
        ] {
            assert_eq!(task_class(hostile), None, "admitted {hostile:?}");
        }
    }

    #[test]
    fn package_splits_on_the_last_colon() {
        let (title, class) = package(0, "fix: parser:bounded_bug_fix").expect("package");
        assert_eq!(title, "fix: parser");
        assert_eq!(class, TaskClass::BoundedBugFix);
        assert!(package(1, "no-class")
            .expect_err("split")
            .starts_with(INPUT_INVALID));
        assert!(package(2, ":code_review")
            .expect_err("title")
            .starts_with(INPUT_INVALID));
        assert!(package(3, "x:nope")
            .expect_err("class")
            .starts_with(CLASS_INVALID));
    }
}
