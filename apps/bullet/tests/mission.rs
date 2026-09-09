//! `bullet mission materialize` / `bullet mission status` drive the library
//! materializer through the admitted private data-dir path. Every case runs
//! only the `bullet` binary itself under a 0700 temporary directory.

#![cfg(target_os = "linux")]

use bullet_domain::{MissionId, PlanRevisionId};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const SEED: &str = "code7-mission-verb";
const CLASS_A: &str = "mechanical_code_edit";
const CLASS_B: &str = "code_review";

fn private_temp_dir() -> TempDir {
    let directory = TempDir::new().expect("tempdir");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("0700");
    directory
}

fn bullet(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(args)
        .output()
        .expect("spawn bullet")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8 stdout")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn materialize(data_dir: &Path, seed: &str, objective: &str, packages: &[&str]) -> Output {
    let data = data_dir.to_string_lossy().into_owned();
    let mut args = vec![
        "mission",
        "materialize",
        "--data-dir",
        &data,
        "--seed",
        seed,
        "--title",
        "CODE-7 mission verb",
        "--objective",
        objective,
    ];
    for package in packages {
        args.push("--package");
        args.push(package);
    }
    bullet(&args)
}

fn status(data_dir: &Path, mission: &str) -> Output {
    let data = data_dir.to_string_lossy().into_owned();
    bullet(&[
        "mission",
        "status",
        "--data-dir",
        &data,
        "--mission",
        mission,
    ])
}

fn assert_refused(output: &Output, code: &str) -> String {
    assert!(!output.status.success(), "laundered {code} as success");
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(output);
    assert!(
        text.starts_with(&format!("bullet: {code}: ")),
        "expected typed {code}, got {text:?}"
    );
    assert!(stdout(output).is_empty(), "refusal printed on stdout");
    text
}

/// Every value of one string field in a compact JSON line, by exact scanning.
fn field_values(line: &str, field: &str) -> Vec<String> {
    let needle = format!("\"{field}\":\"");
    line.match_indices(&needle)
        .map(|(at, _)| {
            let rest = &line[at + needle.len()..];
            rest[..rest.find('"').expect("closing quote")].to_owned()
        })
        .collect()
}

#[test]
fn same_seed_twice_prints_identical_ids_and_status_reads_the_packages_back() {
    let directory = private_temp_dir();
    let data = directory.path().join("data");
    let lint = format!("lint:{CLASS_A}");
    let review = format!("review:{CLASS_B}");
    let packages = [lint.as_str(), review.as_str()];

    let first = materialize(&data, SEED, "materialize a plan", &packages);
    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(
        fs::metadata(&data).expect("data dir").mode() & 0o7777,
        0o700
    );
    let line = stdout(&first);
    assert_eq!(line.lines().count(), 1, "receipt must be one JSON line");
    assert!(line.ends_with('\n'));
    let mission_id = MissionId::from_seed(SEED);
    assert_eq!(field_values(&line, "mission_id"), [mission_id.as_str()]);
    assert_eq!(
        field_values(&line, "plan_revision_id"),
        [PlanRevisionId::from_seed(SEED).as_str()]
    );
    assert_eq!(field_values(&line, "canonical_hash")[0].len(), 64);
    assert_eq!(field_values(&line, "title"), ["lint", "review"]);
    assert_eq!(field_values(&line, "task_class"), [CLASS_A, CLASS_B]);
    let work_packages = field_values(&line, "work_package_id");
    assert_eq!(work_packages.len(), 2);
    assert!(work_packages.iter().all(|id| id.starts_with("wpk_")));
    let variants = field_values(&line, "variant_id");
    assert_eq!(variants.len(), 2);
    assert!(variants.iter().all(|id| id.starts_with("var_")));

    let second = materialize(&data, SEED, "materialize a plan", &packages);
    assert!(second.status.success(), "{}", stderr(&second));
    assert_eq!(stdout(&second), line, "replay must print the identical ids");

    let read = status(&data, mission_id.as_str());
    assert!(read.status.success(), "{}", stderr(&read));
    let graph = stdout(&read);
    assert_eq!(graph.lines().count(), 1);
    assert!(graph.contains(&format!("\"id\":\"{}\"", mission_id.as_str())));
    assert!(graph.contains("\"objective\":\"materialize a plan\""));
    assert!(graph.contains("\"title\":\"CODE-7 mission verb\""));
    assert_eq!(field_values(&graph, "task_class"), [CLASS_A, CLASS_B]);
    for id in work_packages.iter().chain(&variants) {
        assert!(
            graph.contains(&format!("\"id\":\"{id}\"")),
            "status lost {id}"
        );
    }
    assert_eq!(
        field_values(&graph, "work_package_id"),
        work_packages,
        "each variant must name its work package"
    );
}

#[test]
fn same_seed_with_different_input_is_the_materializer_idempotency_conflict() {
    let directory = private_temp_dir();
    let data = directory.path().join("data");
    let lint = format!("lint:{CLASS_A}");
    let packages = [lint.as_str()];
    let first = materialize(&data, SEED, "original objective", &packages);
    assert!(first.status.success(), "{}", stderr(&first));

    let changed = materialize(&data, SEED, "changed objective", &packages);
    let text = assert_refused(&changed, "IDEMPOTENCY_CONFLICT");
    assert!(text.contains("idempotency conflict"), "{text}");

    let read = status(&data, MissionId::from_seed(SEED).as_str());
    assert!(read.status.success(), "{}", stderr(&read));
    assert!(stdout(&read).contains("\"objective\":\"original objective\""));
    assert!(!stdout(&read).contains("changed objective"));
}

#[test]
fn unknown_package_class_is_refused_before_any_ledger_exists() {
    let directory = private_temp_dir();
    let data = directory.path().join("data");
    let lint = format!("lint:{CLASS_A}");
    let refused = materialize(
        &data,
        SEED,
        "objective",
        &[&lint, "review:MechanicalCodeEdit"],
    );
    let text = assert_refused(&refused, "MISSION_PACKAGE_CLASS_INVALID");
    assert!(text.contains("package 1"), "{text}");
    assert!(!data.exists(), "refused input must not create the data dir");
}

#[test]
fn empty_or_oversized_input_is_refused_before_any_ledger_exists() {
    let directory = private_temp_dir();
    let data = directory.path().join("data");
    let package = format!("lint:{CLASS_A}");

    let empty_objective = materialize(&data, SEED, "   ", &[&package]);
    let text = assert_refused(&empty_objective, "MISSION_INPUT_INVALID");
    assert!(text.contains("--objective"), "{text}");

    let empty_seed = materialize(&data, "", "objective", &[&package]);
    assert!(assert_refused(&empty_seed, "MISSION_INPUT_INVALID").contains("--seed"));

    let no_packages = materialize(&data, SEED, "objective", &[]);
    assert!(assert_refused(&no_packages, "MISSION_INPUT_INVALID").contains("at least one"));

    let untyped = materialize(&data, SEED, "objective", &["lint"]);
    assert!(assert_refused(&untyped, "MISSION_INPUT_INVALID").contains("TITLE:CLASS"));

    let untitled = materialize(&data, SEED, "objective", &[&format!(":{CLASS_A}")[..]]);
    assert!(assert_refused(&untitled, "MISSION_INPUT_INVALID").contains("title"));

    let sixty_five: Vec<String> = (0..65).map(|n| format!("wp{n}:{CLASS_A}")).collect();
    let refs: Vec<&str> = sixty_five.iter().map(String::as_str).collect();
    let too_many = materialize(&data, SEED, "objective", &refs);
    assert!(assert_refused(&too_many, "MISSION_INPUT_INVALID").contains("65 packages"));
    assert!(!data.exists(), "refused input must not create the data dir");

    let sixty_four = materialize(&data, SEED, "objective", &refs[..64]);
    assert!(sixty_four.status.success(), "{}", stderr(&sixty_four));
    assert_eq!(
        field_values(&stdout(&sixty_four), "work_package_id").len(),
        64
    );
}

#[test]
fn status_refuses_invalid_ids_absent_ledgers_and_unknown_missions() {
    let directory = private_temp_dir();
    let data = directory.path().join("data");

    let invalid = status(&data, "junk");
    assert_refused(&invalid, "INVALID_ID");
    assert!(!data.exists());

    let absent_ledger = status(&data, MissionId::from_seed(SEED).as_str());
    assert_refused(&absent_ledger, "MISSION_LEDGER_ABSENT");
    assert!(!data.exists(), "status must not create the data dir");

    let seeded = materialize(&data, SEED, "objective", &[&format!("lint:{CLASS_A}")[..]]);
    assert!(seeded.status.success(), "{}", stderr(&seeded));
    let unknown = status(&data, MissionId::from_seed("someone-else").as_str());
    let text = assert_refused(&unknown, "MISSION_NOT_FOUND");
    assert!(text.contains(MissionId::from_seed("someone-else").as_str()));
}

#[test]
fn data_dir_refusals_are_the_existing_typed_admissions() {
    let directory = private_temp_dir();
    let package = format!("lint:{CLASS_A}");

    let relative = materialize(Path::new("relative/data"), SEED, "objective", &[&package]);
    assert!(assert_refused(&relative, "MISSION_DATA_DIR_INVALID").contains("absolute"));
    assert!(!PathBuf::from("relative/data").exists());

    let target = directory.path().join("symlink-target");
    fs::create_dir(&target).expect("target");
    let linked = directory.path().join("linked-data");
    symlink(&target, &linked).expect("symlink");
    let followed = materialize(&linked, SEED, "objective", &[&package]);
    let text = assert_refused(&followed, "MISSION_DATA_DIR_INVALID");
    assert!(text.contains("without following links"), "{text}");
    assert!(!target.join("ledger.sqlite").exists());

    let loose_ancestor = directory.path().join("group-writable");
    fs::create_dir(&loose_ancestor).expect("ancestor");
    fs::set_permissions(&loose_ancestor, fs::Permissions::from_mode(0o770)).expect("0770");
    let under_loose = loose_ancestor.join("data");
    let unsafe_mode = materialize(&under_loose, SEED, "objective", &[&package]);
    let text = assert_refused(&unsafe_mode, "STORE_FAILURE");
    assert!(text.contains("ancestor"), "{text}");
    assert!(!under_loose.join("ledger.sqlite").exists());
}
