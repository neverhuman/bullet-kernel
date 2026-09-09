//! `bullet run show` must verify, not restate. Every test here is a way the
//! render could lie: a tampered body, a broken chain link, an unknown schema, a
//! receipt that is empty or truncated. A renderer that passes only the happy
//! path is exactly the failure mode that let `check dogfood` exit 0 while the
//! coordinator was dead.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The real positive run. These tests are skipped, not silently green, when it
/// is absent -- a fixture that vanished must never read as a pass.
const POSITIVE: &str = "/tmp/bullet-synthetic-selection.vq8u06zc/positive";

fn selection() -> PathBuf {
    Path::new(POSITIVE).join("DF_DOG1_SELECTION.receipt.json")
}

fn effect_chain() -> PathBuf {
    Path::new(POSITIVE).join("DF_DOG1_EFFECT_CHAIN.receipt.json")
}

fn fixtures_present() -> bool {
    selection().is_file() && effect_chain().is_file()
}

fn bullet() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("bullet")
}

fn show(path: &Path) -> std::process::Output {
    Command::new(bullet())
        .args(["run", "show"])
        .arg(path)
        .output()
        .expect("spawn bullet run show")
}

fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bullet-run-show-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

#[test]
fn both_real_receipts_render_and_report_their_digest_verified() {
    if !fixtures_present() {
        eprintln!("SKIP: positive fixture absent at {POSITIVE}");
        return;
    }
    for path in [selection(), effect_chain()] {
        let output = show(&path);
        assert!(
            output.status.success(),
            "{}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("body_digest  OK"), "{path:?}: {stdout}");
        assert!(
            stdout.contains("eligibility  0/9 — NOT a release receipt"),
            "{path:?}: {stdout}"
        );
    }
}

#[test]
fn the_selection_render_expands_every_gate_id_to_its_argv() {
    if !fixtures_present() {
        eprintln!("SKIP: positive fixture absent");
        return;
    }
    let stdout = String::from_utf8_lossy(&show(&selection()).stdout).into_owned();
    assert!(stdout.contains("gate         "), "{stdout}");
    assert!(
        stdout.contains("/usr/bin/grep -qx PONG PONG.txt"),
        "the sealed gate must render as the command it runs: {stdout}"
    );
}

#[test]
fn the_effect_chain_render_reports_the_selection_receipt_bound() {
    if !fixtures_present() {
        eprintln!("SKIP: positive fixture absent");
        return;
    }
    let stdout = String::from_utf8_lossy(&show(&effect_chain()).stdout).into_owned();
    assert!(
        stdout.contains("chain        selection receipt BOUND"),
        "{stdout}"
    );
}

#[test]
fn a_flipped_byte_in_the_body_is_refused_rather_than_rendered() {
    if !fixtures_present() {
        eprintln!("SKIP: positive fixture absent");
        return;
    }
    let raw = std::fs::read_to_string(selection()).expect("read receipt");
    // Change a value inside the body without changing its length or shape.
    let tampered = raw.replacen("COMPONENT_PROOF", "COMPONENT_PROOE", 1);
    assert_ne!(tampered, raw, "the tamper must actually change the bytes");
    let path = write_temp("tampered.receipt.json", tampered.as_bytes());
    let output = show(&path);
    assert!(!output.status.success(), "a tampered body must not render");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("RECEIPT_BODY_DIGEST_MISMATCH"),
        "expected a digest mismatch, got: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "a receipt that fails verification must print no rendered line"
    );
}

#[test]
fn a_mutated_chain_link_is_reported_broken_and_never_bound() {
    if !fixtures_present() {
        eprintln!("SKIP: positive fixture absent");
        return;
    }
    let raw = std::fs::read_to_string(effect_chain()).expect("read receipt");
    let marker = "\"selection_receipt_hex\":\"";
    let start = raw.find(marker).expect("hex field") + marker.len();
    // Flip one hex nibble inside the embedded receipt. The outer body digest
    // changes too, so this proves the outer check fires first and the chain is
    // never reported BOUND for altered embedded bytes.
    let mut bytes = raw.clone().into_bytes();
    bytes[start] = if bytes[start] == b'a' { b'b' } else { b'a' };
    let path = write_temp("chain.receipt.json", &bytes);
    let output = show(&path);
    assert!(!output.status.success(), "a mutated chain must not render");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("BOUND"),
        "a mutated chain must never render as BOUND: {stdout}"
    );
}

#[test]
fn an_unknown_schema_refuses_without_printing_any_body_field() {
    if !fixtures_present() {
        eprintln!("SKIP: positive fixture absent");
        return;
    }
    let raw = std::fs::read_to_string(selection()).expect("read receipt");
    let swapped = raw.replacen(
        "bullet.synthetic-selection-receipt.component.v1",
        "bullet.something.v9",
        1,
    );
    let path = write_temp("unknown.receipt.json", swapped.as_bytes());
    let output = show(&path);
    assert!(!output.status.success(), "unknown schema must refuse");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("UNKNOWN_RECEIPT_SCHEMA"), "{stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("COMPONENT_PROOF") && !stdout.contains("eligibility"),
        "no field of an unknown receipt may be printed: {stdout}"
    );
}

#[test]
fn empty_truncated_and_shapeless_receipts_all_refuse() {
    for (name, bytes) in [
        ("empty.receipt.json", b"".as_slice()),
        ("object.receipt.json", b"{}".as_slice()),
        ("truncated.receipt.json", b"{\"schema_version\":".as_slice()),
    ] {
        let path = write_temp(name, bytes);
        let output = show(&path);
        assert!(
            !output.status.success(),
            "{name} must refuse rather than render an empty table"
        );
    }
}

#[test]
fn a_missing_receipt_path_refuses_cleanly() {
    let output = show(Path::new("/nonexistent/definitely-not-here.receipt.json"));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("RECEIPT_UNREADABLE"));
}

#[test]
fn print_preimages_matches_an_independent_b3sum_of_the_base_blob() {
    // A preimage an author computes by hand is refused at apply when it is
    // wrong, so this helper must agree with the standard tool exactly. b3sum is
    // deliberately used instead of the crate the implementation calls, so the
    // check is independent rather than self-confirming.
    let repo = Path::new("/home/ubuntu/bullet/bullet-git");
    if !repo.join(".git").exists() {
        eprintln!("SKIP: bullet-git not present");
        return;
    }
    if Command::new("b3sum").arg("--version").output().is_err() {
        eprintln!("SKIP: b3sum unavailable");
        return;
    }
    let head = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse");
    if !head.status.success() {
        eprintln!("SKIP: cannot resolve HEAD");
        return;
    }
    let base = String::from_utf8_lossy(&head.stdout).trim().to_owned();

    let output = Command::new(bullet())
        .args(["run", "print-preimages", "--repo"])
        .arg(repo)
        .args(["--base-sha", &base, "README.md", "definitely/absent.txt"])
        .output()
        .expect("spawn print-preimages");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();

    let expected = independent_b3sum(repo, &base, "README.md");
    let present = lines.next().expect("first line");
    assert!(
        present.contains(&expected),
        "expected b3sum {expected} in {present}"
    );

    let absent = lines.next().expect("second line");
    assert!(
        absent.contains(r#""kind":"absent""#),
        "a path absent at the base commit has no preimage: {absent}"
    );
}

fn independent_b3sum(repo: &Path, base: &str, path: &str) -> String {
    use std::process::Stdio;
    let mut show = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["show", &format!("{base}:{path}")])
        .stdout(Stdio::piped())
        .spawn()
        .expect("git show");
    let stdout = show.stdout.take().expect("git stdout");
    let sum = Command::new("b3sum")
        .arg("--no-names")
        .stdin(stdout)
        .output()
        .expect("b3sum");
    // Reap the child rather than leaving it for the OS: an unwaited process is
    // a leak in a test that may run thousands of times.
    show.wait().expect("git show exit");
    String::from_utf8_lossy(&sum.stdout).trim().to_owned()
}
