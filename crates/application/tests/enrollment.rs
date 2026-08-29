//! Provider enrollment loader (ENROLL-1): every typed refusal, hostile and
//! tampered subjects, the enumerated proof that no committed fixture artifact
//! becomes an enrollment, and the deliberate positive case showing what the
//! record does NOT prove — a same-uid author enrolling an executable it wrote
//! moments earlier, under any label. Nothing here spawns a process.

use bullet_application::live_conformance::{
    enrollment_path, load_provider_enrollment, EnrollmentError, ProviderEnrollmentV1,
    MAX_BUDGET_MICRO_USD, MAX_ENROLLMENT_BYTES, MAX_ENROLLMENT_WINDOW_MS, MAX_LABEL_BYTES,
    PROVIDER_ENROLLMENT_SCHEMA,
};
use bullet_application::policy_snapshot::load_policy;
use bullet_domain::ProfileId;
use bullet_harness_claude::ClaudeAdapter;
use bullet_harness_core::launch_grant::is_lower_hex_64;
use bullet_harness_core::{executable_digest, LiveDispatcher};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const LOADER_SOURCE: &str = include_str!("../src/live_conformance/enrollment.rs");
const OFFLINE_POLICY: &[u8] = include_bytes!("fixtures/policy-v1alpha1.json");
const NOW: u64 = 1_800_000_000_000;
const FROM: u64 = NOW - 60_000;
const UNTIL: u64 = NOW + 60_000;

struct Sandbox {
    _root: tempfile::TempDir,
    data_dir: PathBuf,
    executable: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().canonicalize().unwrap().join("data");
        std::fs::create_dir_all(data_dir.join("policy").join("enrollments")).unwrap();
        chmod(&data_dir, 0o700);
        let executable = data_dir.join("claude");
        write_mode(&executable, b"#!/bin/sh\nexit 0\n", 0o700);
        Self {
            _root: root,
            data_dir,
            executable,
        }
    }

    fn record(&self) -> Value {
        json!({
            "schema": PROVIDER_ENROLLMENT_SCHEMA,
            "provider": "claude",
            "executable": self.executable,
            "executable_blake3": executable_digest(&self.executable).unwrap(),
            "protocol": "claude_stream_json",
            "version": ClaudeAdapter::new().observed_runtime_version(),
            "profile_id": ProfileId::from_seed("claude").as_str(),
            "budget_micro_usd_max": 250_000,
            "valid_from_unix_ms": FROM,
            "valid_until_unix_ms": UNTIL,
            "enrolled_by": "operator@example.test",
        })
    }

    fn enroll(&self, provider: &str, value: &Value) -> PathBuf {
        let path = enrollment_path(&self.data_dir, provider);
        write_mode(&path, serde_json::to_vec(value).unwrap().as_slice(), 0o600);
        path
    }

    fn load(&self, provider: &str) -> Result<(), EnrollmentError> {
        load_provider_enrollment(&self.data_dir, provider, NOW).map(|_| ())
    }

    /// Enroll a mutated valid record and return the refusal code and detail.
    fn refuse(&self, mutate: impl FnOnce(&mut Value)) -> (String, String) {
        let mut value = self.record();
        mutate(&mut value);
        self.enroll("claude", &value);
        let error = self.load("claude").unwrap_err();
        (error.reason_code().to_string(), error.to_string())
    }
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    let _ = std::fs::remove_file(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    chmod(path, mode);
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Every artifact committed under `tests/fixtures/`, by file name and bytes.
fn committed_fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut found: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| {
            let file = entry.unwrap().path();
            let name = file.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&file).unwrap())
        })
        .collect();
    found.sort();
    assert!(found.len() >= 2, "no fixtures under {}", dir.display());
    found
}

/// Every quoted string in a fixture, keys and values alike and in order, so a
/// string value can be read as the token after the key that names it.
fn quoted_strings(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

fn set(value: &mut Value, field: &str, replacement: Value) {
    value[field] = replacement;
}

/// The disclosed limit, exercised on purpose: the sandbox writes a two-line
/// shell script, calls it the provider, labels the record with an operator
/// string of its choosing, and the loader admits it. That is all an unsigned
/// enrollment is worth — self-consistency and executable-byte agreement, and
/// no statement whatever about who authored it.
#[test]
fn a_same_uid_author_can_enroll_an_executable_it_just_wrote() {
    let sandbox = Sandbox::new();
    let record = sandbox.record();
    let path = sandbox.enroll("claude", &record);
    let enrolled = load_provider_enrollment(&sandbox.data_dir, "claude", NOW).unwrap();

    let expected: ProviderEnrollmentV1 = serde_json::from_value(record.clone()).unwrap();
    assert_eq!(enrolled.record(), &expected);
    assert_eq!(enrolled.wire_provider(), "claude");
    assert_eq!(enrolled.profile_id(), &ProfileId::from_seed("claude"));
    assert_eq!(enrolled.max_cost_micro_usd(), 250_000);
    let raw = blake3::hash(&std::fs::read(&path).unwrap());
    assert_eq!(enrolled.enrollment_blake3(), raw.to_hex().as_str());
    // Activation is inclusive; the instant before it is refused.
    assert!(load_provider_enrollment(&sandbox.data_dir, "claude", FROM).is_ok());
    let pre = load_provider_enrollment(&sandbox.data_dir, "claude", FROM - 1);
    assert_eq!(pre.unwrap_err().reason_code(), "ENROLLMENT_WINDOW_INVALID");
}

/// An enrollment is an unsigned operator assertion, never runtime evidence.
/// The complete `EnrolledProvider` surface is pinned to plain fact types, the
/// loader source names no probe/observation/admission type outside comments,
/// and loading a record leaves policy admission exactly as it found it — so
/// neither a conversion nor a policy side effect can appear unnoticed.
#[test]
fn enrolled_provider_yields_no_probe_observation_or_admission_type() {
    let sandbox = Sandbox::new();
    sandbox.enroll("claude", &sandbox.record());
    let enrolled = load_provider_enrollment(&sandbox.data_dir, "claude", NOW).unwrap();
    let _: &ProviderEnrollmentV1 = enrolled.record();
    let _: &str = enrolled.enrollment_blake3();
    let _: &'static str = enrolled.wire_provider();
    let _: &ProfileId = enrolled.profile_id();
    let _: u64 = enrolled.max_cost_micro_usd();

    let forbidden = [
        "RuntimeProbeSnapshot",
        "RuntimeConformanceObservation",
        "ProviderAdmission",
        "EvaluatedAdmission",
        "ProbeResult",
        "ProfileIdentity",
        "HarnessDescriptor",
        "Observation",
        "observe_runtime_conformance",
        "LiveDispatcher",
        "Command",
    ];
    let mut public_methods = 0;
    for line in LOADER_SOURCE.lines() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        for token in forbidden {
            assert!(!code.contains(token), "{token} in loader code: {line}");
        }
        if code.starts_with("pub fn ") {
            public_methods += 1;
        }
    }
    // record, enrollment_blake3, wire_provider, profile_id, max_cost_micro_usd,
    // reason_code, enrollment_path, load_provider_enrollment.
    assert_eq!(public_methods, 8, "public surface changed; re-pin it above");

    // And it cannot enable live admission. With no policy the loader neither
    // creates one nor makes admission reachable; with the committed offline
    // policy installed, generation, digest, and the live-admission answer are
    // identical before and after a successful load.
    let absent = load_policy(&sandbox.data_dir, None).unwrap_err();
    assert_eq!(absent.reason_code(), "POLICY_UNAVAILABLE");
    let policy = sandbox.data_dir.join("policy/policy.json");
    write_mode(&policy, OFFLINE_POLICY, 0o600);
    let before = load_policy(&sandbox.data_dir, None).unwrap();
    load_provider_enrollment(&sandbox.data_dir, "claude", NOW).unwrap();
    let after = load_policy(&sandbox.data_dir, None).unwrap();
    assert_eq!(before, after);
    assert!(!after.live_admission_enabled());
    let refusal = after.require_live_admission().unwrap_err();
    assert_eq!(refusal.reason_code(), "POLICY_LIVE_ADMISSION_DISABLED");
}

#[test]
fn a_missing_enrollment_is_typed_and_names_the_expected_path() {
    let sandbox = Sandbox::new();
    let error = sandbox.load("codex").unwrap_err();
    assert_eq!(error.reason_code(), "ENROLLMENT_MISSING");
    let expected = enrollment_path(&sandbox.data_dir, "codex");
    assert!(error.to_string().contains(&expected.display().to_string()));
}

#[test]
fn malformed_content_is_refused_before_any_executable_is_touched() {
    let sandbox = Sandbox::new();
    let path = enrollment_path(&sandbox.data_dir, "claude");
    let raw: Vec<(&str, Vec<u8>)> = vec![
        ("not json", b"{".to_vec()),
        ("not utf-8", vec![0xff, 0xfe, b'{', b'}']),
        ("duplicate", br#"{"schema":"a","schema":"b"}"#.to_vec()),
        ("trailing", b"{} {}".to_vec()),
        ("oversized", vec![b' '; MAX_ENROLLMENT_BYTES as usize + 1]),
    ];
    for (label, bytes) in raw {
        write_mode(&path, &bytes, 0o600);
        let error = sandbox.load("claude").unwrap_err();
        assert_eq!(error.reason_code(), "ENROLLMENT_MALFORMED", "{label}");
    }
    let upper = sandbox.record()["executable_blake3"]
        .as_str()
        .unwrap()
        .to_ascii_uppercase();
    let fields: Vec<(&str, Value)> = vec![
        ("extra", json!(1)),
        ("schema", json!("v1alpha2")),
        ("budget_micro_usd_max", json!(0)),
        ("budget_micro_usd_max", json!(MAX_BUDGET_MICRO_USD + 1)),
        ("budget_micro_usd_max", json!("0.25")),
        ("budget_micro_usd_max", json!(-1)),
        ("version", json!("")),
        ("version", json!("2.1 beta")),
        ("enrolled_by", json!("x".repeat(MAX_LABEL_BYTES + 1))),
        ("profile_id", json!("prf_short")),
        ("executable_blake3", json!(upper)),
        ("executable_blake3", json!("abc")),
    ];
    for (field, replacement) in fields {
        let label = format!("{field} = {replacement}");
        let (code, detail) = sandbox.refuse(|v| set(v, field, replacement));
        assert_eq!(code, "ENROLLMENT_MALFORMED", "{label}: {detail}");
    }
    let (code, detail) = sandbox.refuse(|v| {
        v.as_object_mut().unwrap().remove("enrolled_by");
    });
    assert_eq!(code, "ENROLLMENT_MALFORMED", "missing field: {detail}");
}

/// The honest form of the old "fixture material is refused by structure"
/// claim, widened until it is a property of every committed artifact rather
/// than of one document: each file under `tests/fixtures/` is tried as the
/// record, as the enrolled executable, as `executable_blake3` (its own digest
/// and every 64-hex string it names) and, for the identities it names, as
/// `enrolled_by`. It does not say fixture material cannot be enrolled by
/// anybody: it separates record classes, and the label half is a denylist.
#[test]
fn no_committed_fixture_artifact_can_become_an_enrollment() {
    let sandbox = Sandbox::new();
    let path = enrollment_path(&sandbox.data_dir, "claude");
    for (name, bytes) in committed_fixtures() {
        // As the record itself: a distinct class with unknown fields refused.
        write_mode(&path, &bytes, 0o600);
        let error = sandbox.load("claude").unwrap_err();
        assert_eq!(error.reason_code(), "ENROLLMENT_MALFORMED", "{name} record");
        // As the enrolled executable, with its committed bytes and mode.
        let copy = sandbox.data_dir.join(&name);
        write_mode(&copy, &bytes, 0o600);
        let own = blake3::hash(&bytes).to_hex().to_string();
        let (code, detail) = sandbox.refuse(|v| {
            set(v, "executable", json!(copy));
            set(v, "executable_blake3", json!(&own));
        });
        assert_eq!(code, "ENROLLMENT_EXECUTABLE_INVALID", "{name}");
        assert!(detail.contains("execute bit"), "{name}: {detail}");
        // As `executable_blake3`: its own digest and every 64-hex string it
        // carries (issuer key material, registry and bundle hashes).
        let quoted = quoted_strings(&bytes);
        let mut digests = quoted.clone();
        digests.retain(|token| is_lower_hex_64(token));
        assert!(!digests.is_empty(), "{name} names no 64-hex string");
        digests.push(own);
        for digest in digests {
            let (code, detail) = sandbox.refuse(|v| set(v, "executable_blake3", json!(&digest)));
            assert_eq!(code, "ENROLLMENT_EXECUTABLE_DIGEST_MISMATCH", "{name}");
            assert!(detail.contains(&digest), "{name}: {detail}");
        }
        // As `enrolled_by`: every issuer and key identity it names.
        let identities: Vec<&String> = quoted
            .windows(2)
            .filter(|pair| pair[0] == "issuer" || pair[0] == "key_id")
            .map(|pair| &pair[1])
            .collect();
        assert!(!identities.is_empty(), "{name} names no issuer or key_id");
        for label in identities {
            let (code, detail) = sandbox.refuse(|v| set(v, "enrolled_by", json!(label)));
            assert_eq!(code, "ENROLLMENT_MALFORMED", "{name}/{label}");
            assert!(detail.contains("fixture-only"), "{name}/{label}: {detail}");
        }
    }
    // The other half: case folding and the `fixture` substring extend the
    // denylist, nothing else does, and every other label is admitted.
    for label in ["Authority-Test-1", "my-fixture-key"] {
        let (code, detail) = sandbox.refuse(|v| set(v, "enrolled_by", json!(label)));
        assert_eq!(code, "ENROLLMENT_MALFORMED", "{label}");
        assert!(detail.contains("fixture-only"), "{label}: {detail}");
    }
    sandbox.enroll("claude", &sandbox.record());
    assert!(sandbox.load("claude").is_ok());
}

#[test]
fn provider_mismatches_are_typed() {
    let sandbox = Sandbox::new();
    let (code, detail) = sandbox.refuse(|v| set(v, "provider", json!("codex")));
    assert_eq!(code, "ENROLLMENT_PROVIDER_MISMATCH");
    assert!(detail.contains("claude.json"), "{detail}");
    let (code, detail) = sandbox.refuse(|v| set(v, "protocol", json!("codex_app_server_jsonl")));
    assert_eq!(code, "ENROLLMENT_PROVIDER_MISMATCH");
    assert!(detail.contains("frozen V1 protocol"), "{detail}");
    // Weakened Claude protocol labels are refused the same way.
    let (code, _) = sandbox.refuse(|v| set(v, "protocol", json!("cursor_stream_json")));
    assert_eq!(code, "ENROLLMENT_PROVIDER_MISMATCH");
    // A record for codex under codex.json is consistent but the codex
    // executable is our claude script: protocol must still match codex.
    let mut codex = sandbox.record();
    set(&mut codex, "provider", json!("codex"));
    sandbox.enroll("codex", &codex);
    assert_eq!(
        sandbox.load("codex").unwrap_err().reason_code(),
        "ENROLLMENT_PROVIDER_MISMATCH"
    );
    // Wire aliases and unknown names are not enrollable providers.
    for name in ["agy", "", "../claude", "CLAUDE"] {
        let error = sandbox.load(name).unwrap_err();
        assert_eq!(
            error.reason_code(),
            "ENROLLMENT_PROVIDER_MISMATCH",
            "{name:?}"
        );
    }
}

#[test]
fn a_tampered_executable_after_enrollment_is_a_digest_mismatch() {
    let sandbox = Sandbox::new();
    sandbox.enroll("claude", &sandbox.record());
    let enrolled = load_provider_enrollment(&sandbox.data_dir, "claude", NOW).unwrap();
    let before = enrolled.record().executable_blake3.clone();
    let mut tampered = std::fs::read(&sandbox.executable).unwrap();
    tampered.extend_from_slice(b"# tampered\n");
    std::fs::write(&sandbox.executable, &tampered).unwrap();
    let error = sandbox.load("claude").unwrap_err();
    assert_eq!(error.reason_code(), "ENROLLMENT_EXECUTABLE_DIGEST_MISMATCH");
    let detail = error.to_string();
    assert!(detail.contains(&before), "{detail}");
    assert!(
        detail.contains(&executable_digest(&sandbox.executable).unwrap()),
        "{detail}"
    );
}

#[test]
fn executable_subjects_that_cannot_be_admitted_are_typed() {
    let sandbox = Sandbox::new();
    let (code, detail) = sandbox.refuse(|v| set(v, "executable", json!("bin/claude")));
    assert_eq!(code, "ENROLLMENT_EXECUTABLE_INVALID", "{detail}");
    let (code, detail) = sandbox.refuse(|v| set(v, "executable", json!("/nonexistent/claude")));
    assert_eq!(code, "ENROLLMENT_EXECUTABLE_INVALID", "{detail}");

    let link = sandbox.data_dir.join("claude-link");
    std::os::unix::fs::symlink(&sandbox.executable, &link).unwrap();
    let (code, detail) = sandbox.refuse(|v| set(v, "executable", json!(link)));
    assert_eq!(code, "ENROLLMENT_EXECUTABLE_INVALID", "{detail}");

    // The record is fixed while the on-disk subject changes underneath it.
    sandbox.enroll("claude", &sandbox.record());
    for (mode, expected) in [
        (0o600, "execute bit"),
        (0o777, "writable"),
        (0o775, "writable"),
        (0o720, "writable"),
    ] {
        chmod(&sandbox.executable, mode);
        let error = sandbox.load("claude").unwrap_err();
        assert_eq!(
            error.reason_code(),
            "ENROLLMENT_EXECUTABLE_INVALID",
            "{mode:o}"
        );
        assert!(error.to_string().contains(expected), "{mode:o}: {error}");
    }
    // Parent hygiene: a group- or world-writable parent is refused even when
    // the executable itself is clean.
    chmod(&sandbox.executable, 0o755);
    for parent_mode in [0o770, 0o1777] {
        chmod(&sandbox.data_dir, parent_mode);
        let error = sandbox.load("claude").unwrap_err();
        assert_eq!(
            error.reason_code(),
            "ENROLLMENT_EXECUTABLE_INVALID",
            "{parent_mode:o}"
        );
        assert!(
            error.to_string().contains("parent"),
            "{parent_mode:o}: {error}"
        );
    }
    chmod(&sandbox.data_dir, 0o700);
    assert!(sandbox.load("claude").is_ok());
}

#[test]
fn validity_windows_are_bounded_and_checked_at_now() {
    let sandbox = Sandbox::new();
    let over = FROM + MAX_ENROLLMENT_WINDOW_MS + 1;
    let cases: Vec<(&str, u64, u64, u64, &str)> = vec![
        ("inverted", UNTIL, FROM, NOW, "must precede"),
        ("empty", NOW, NOW, NOW, "must precede"),
        ("too long", FROM, over, NOW, "exceeds"),
        ("not yet valid", NOW + 1, UNTIL, NOW, "not yet valid"),
        ("expired at until", FROM, NOW, NOW, "expired"),
        ("expired", FROM, NOW - 1, NOW, "expired"),
        ("unsafe integer", FROM, u64::MAX, NOW, "safe integer"),
    ];
    for (label, from, until, now, expected) in cases {
        let mut value = sandbox.record();
        set(&mut value, "valid_from_unix_ms", json!(from));
        set(&mut value, "valid_until_unix_ms", json!(until));
        sandbox.enroll("claude", &value);
        let error = load_provider_enrollment(&sandbox.data_dir, "claude", now).unwrap_err();
        assert_eq!(error.reason_code(), "ENROLLMENT_WINDOW_INVALID", "{label}");
        assert!(error.to_string().contains(expected), "{label}: {error}");
    }
    // The widest admitted window is exactly MAX_ENROLLMENT_WINDOW_MS.
    let mut value = sandbox.record();
    set(&mut value, "valid_from_unix_ms", json!(FROM));
    let widest = FROM + MAX_ENROLLMENT_WINDOW_MS;
    set(&mut value, "valid_until_unix_ms", json!(widest));
    sandbox.enroll("claude", &value);
    assert!(sandbox.load("claude").is_ok());
}

#[test]
fn file_custody_violations_are_typed_and_never_read() {
    let sandbox = Sandbox::new();
    let path = enrollment_path(&sandbox.data_dir, "claude");
    let record = serde_json::to_vec(&sandbox.record()).unwrap();

    for mode in [0o644, 0o640, 0o400, 0o660] {
        write_mode(&path, &record, mode);
        let error = sandbox.load("claude").unwrap_err();
        assert_eq!(error.reason_code(), "ENROLLMENT_FILE_POLICY", "{mode:o}");
        assert!(error.to_string().contains("0600"), "{mode:o}: {error}");
    }

    let aside = sandbox.data_dir.join("aside.json");
    write_mode(&aside, &record, 0o600);
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&aside, &path).unwrap();
    let error = sandbox.load("claude").unwrap_err();
    assert_eq!(error.reason_code(), "ENROLLMENT_FILE_POLICY");
    assert!(error.to_string().contains("symlink"), "{error}");

    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let error = sandbox.load("claude").unwrap_err();
    assert_eq!(error.reason_code(), "ENROLLMENT_FILE_POLICY");
    assert!(error.to_string().contains("regular file"), "{error}");

    let error = load_provider_enrollment(Path::new("relative/data"), "claude", NOW).unwrap_err();
    assert_eq!(error.reason_code(), "ENROLLMENT_FILE_POLICY");
    assert!(error.to_string().contains("absolute"), "{error}");
}
