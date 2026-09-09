//! PROBE-1b: the contained Claude runtime probe against a fake executable.
//! No provider CLI is ever spawned: the "executable" is a tempdir shell
//! script (basename `fake-claude`) that records every invocation in a marker
//! file, so every pre-spawn refusal is proven by the marker's absence.
#![cfg(unix)]

use bullet_harness_claude::{
    probe_claude, probe_deadline_ms, ClaudeAdapter, ProbeContainment, ProbeInput, ProbeRefusal,
    MAX_PROBE_DEADLINE_MS, NO_PROMPT_FREE_HELLO, PROBE_ARGUMENT,
};
use bullet_harness_core::argv::KILL_SWITCH_VAR;
use bullet_harness_core::live::{
    ContainmentClass, ProbeExit, ProbeGrantEvidence, ProtocolHandshake, RuntimeProbeObservation,
    MAX_PROBE_STDOUT_BYTES,
};
use bullet_harness_core::{CanarySecrets, LiveDispatcher};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const NOW: u64 = 1_700_000_000_000;
const TTL_MS: u64 = 5_000;
const VERSION_LINE: &str = "fake-claude 9.9.9 (probe fixture)";
const CANARY: &str = "bullet-host-canary-7f2d9b61";
const FAKE_HELLO: &str = r#"{"type":"system","subtype":"init","fake":true}"#;

/// The kill switch is process-global; every test serializes on this lock.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn hex(ch: char) -> String {
    ch.to_string().repeat(64)
}

fn factory(program: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(program);
    command.args(args).env_clear().process_group(0);
    for (key, value) in env {
        command.env(key, value);
    }
    command
}

struct Fixture {
    dir: TempDir,
    executable: PathBuf,
    marker: PathBuf,
    argv_log: PathBuf,
    blake3: String,
}

impl Fixture {
    /// A fake executable whose body runs after the marker/argv records.
    fn new(body: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let executable = root.join("fake-claude");
        let marker = root.join("spawned.marker");
        let argv_log = root.join("argv.log");
        let mut fixture = Self {
            dir,
            executable,
            marker,
            argv_log,
            blake3: String::new(),
        };
        fixture.write(body);
        fixture
    }

    fn write(&mut self, body: &str) {
        let script = format!(
            "#!/bin/sh\necho spawned >> {}\nprintf '%s\\n' \"$@\" > {}\n{body}\n",
            self.marker.display(),
            self.argv_log.display()
        );
        std::fs::write(&self.executable, script).unwrap();
        std::fs::set_permissions(&self.executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        self.blake3 = bullet_harness_core::executable_digest(&self.executable).unwrap();
    }

    fn grant(&self, expires_at_unix_ms: u64) -> ProbeGrantEvidence {
        ProbeGrantEvidence {
            grant_blake3: hex('1'),
            provider: "claude".into(),
            executable_blake3: self.blake3.clone(),
            containment: ContainmentClass::EgressDenied,
            expires_at_unix_ms,
        }
    }

    fn input<'a>(&self, grant: ProbeGrantEvidence) -> ProbeInput<'a> {
        ProbeInput {
            executable: self.executable.clone(),
            expected_blake3: self.blake3.clone(),
            grant,
            containment: Some(ProbeContainment {
                receipt_blake3: hex('c'),
                command: &factory,
            }),
            canaries: CanarySecrets::new(vec![CANARY.into()]).unwrap(),
            workdir: self.dir.path().to_path_buf(),
            now_unix_ms: NOW,
        }
    }

    fn spawn_count(&self) -> usize {
        std::fs::read_to_string(&self.marker)
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }

    fn recorded_argv(&self) -> Vec<String> {
        std::fs::read_to_string(&self.argv_log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

fn refused(result: Result<RuntimeProbeObservation, ProbeRefusal>, code: &str) -> ProbeRefusal {
    let refusal = result
        .err()
        .unwrap_or_else(|| panic!("expected refusal {code}"));
    assert_eq!(refusal.reason_code(), code, "{refusal}");
    assert_ne!(refusal.reason_code(), "UNKNOWN");
    assert!(refusal.to_string().starts_with(code), "{refusal}");
    refusal
}

fn refused_pre_spawn(fixture: &Fixture, input: &ProbeInput<'_>, code: &str) -> ProbeRefusal {
    let refusal = refused(probe_claude(input), code);
    assert_eq!(fixture.spawn_count(), 0, "{code} must refuse before spawn");
    assert!(!fixture.marker.exists(), "{code} must not touch the marker");
    refusal
}

fn process_running(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, suffix)| suffix.chars().next())
        .is_some_and(|state| state != 'Z')
}

fn assert_dead(pid_file: &Path) {
    let pid: u32 = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for _ in 0..80 {
        if !process_running(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("descendant {pid} survived the probe deadline kill");
}

#[test]
fn happy_path_yields_native_version_exact_argv_and_a_refused_handshake() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let body =
        format!("echo '{VERSION_LINE}'\necho '{FAKE_HELLO}'\nprintf 'home=[%s]\\n' \"$HOME\"");
    let fixture = Fixture::new(&body);
    let input = fixture.input(fixture.grant(NOW + TTL_MS));

    let observation = probe_claude(&input).expect("contained probe");
    let facts = observation.facts();
    assert_eq!(observation.version(), VERSION_LINE);
    assert_eq!(facts.provider, "claude");
    assert_eq!(
        facts.argv,
        [fixture.executable.to_str().unwrap(), PROBE_ARGUMENT]
    );
    assert_eq!(fixture.recorded_argv(), [PROBE_ARGUMENT]);
    assert_eq!(
        fixture.spawn_count(),
        1,
        "exactly one invocation, no hello run"
    );
    assert_eq!(facts.executable.blake3, fixture.blake3);
    assert_eq!(facts.executable.path, fixture.executable.to_str().unwrap());
    let expected_stdout = format!("{VERSION_LINE}\n{FAKE_HELLO}\nhome=[]");
    assert_eq!(facts.native_stdout, expected_stdout, "env is cleared");
    let handshake = ProtocolHandshake::HandshakeRefused {
        reason: NO_PROMPT_FREE_HELLO.to_string(),
    };
    assert_eq!(facts.handshake, handshake, "a fake hello is never credited");
    assert_eq!(facts.handshake.demonstrated_protocol(), None);
    assert!(facts.capabilities.is_empty());
    assert_eq!(facts.exit, ProbeExit::Code { code: 0 });
    assert_eq!(facts.observed_at_unix_ms, NOW);
    assert!(facts.wall_ms < TTL_MS);
    assert_eq!(facts.containment_receipt_blake3, hex('c'));
    assert_eq!(observation.grant_blake3(), hex('1'));
    assert_eq!(observation.containment(), ContainmentClass::EgressDenied);
    let digest = observation.digest().unwrap();
    assert_eq!(digest.len(), 64);
    let bytes = observation.encode().unwrap();
    let decoded = RuntimeProbeObservation::decode(&bytes, &input.grant, NOW + 1).unwrap();
    assert_eq!(decoded, observation);

    // A non-zero exit is a recorded native fact, not a fabricated success.
    let failing = Fixture::new(&format!("echo '{VERSION_LINE}'\nexit 3"));
    let observation = probe_claude(&failing.input(failing.grant(NOW + TTL_MS))).unwrap();
    assert_eq!(observation.facts().exit, ProbeExit::Code { code: 3 });
    assert_eq!(observation.version(), VERSION_LINE);
}

#[test]
fn executable_replaced_after_enrollment_is_refused_before_spawn() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut fixture = Fixture::new(&format!("echo '{VERSION_LINE}'"));
    let enrolled_blake3 = fixture.blake3.clone();
    let enrolled_grant = fixture.grant(NOW + TTL_MS);
    fixture.write("echo 'replaced 0.0.1'");
    assert_ne!(fixture.blake3, enrolled_blake3);

    // Grant and enrollment both name the old bytes: refused against the grant.
    let mut input = fixture.input(enrolled_grant);
    input.expected_blake3 = enrolled_blake3.clone();
    refused_pre_spawn(&fixture, &input, "RUNTIME_PROBE_GRANT_MISMATCH");

    // A grant for the new bytes while the enrollment names the old: drift.
    let mut input = fixture.input(fixture.grant(NOW + TTL_MS));
    input.expected_blake3 = enrolled_blake3.clone();
    let refusal = refused_pre_spawn(&fixture, &input, "RUNTIME_PROBE_EXECUTABLE_DRIFT");
    assert_eq!(
        refusal,
        ProbeRefusal::ExecutableDrift {
            expected: enrolled_blake3,
            observed: fixture.blake3.clone(),
        }
    );

    // The path itself must be an absolute executable regular file.
    let mut input = fixture.input(fixture.grant(NOW + TTL_MS));
    input.executable = fixture.dir.path().join("absent");
    refused_pre_spawn(&fixture, &input, "RUNTIME_PROBE_EXECUTABLE_INVALID");
    let link = fixture.dir.path().join("link");
    std::os::unix::fs::symlink(&fixture.executable, &link).unwrap();
    let mut input = fixture.input(fixture.grant(NOW + TTL_MS));
    input.executable = link;
    refused_pre_spawn(&fixture, &input, "RUNTIME_PROBE_EXECUTABLE_INVALID");
}

#[test]
fn expired_or_mismatched_grant_is_refused_before_spawn() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let fixture = Fixture::new(&format!("echo '{VERSION_LINE}'"));

    for expires in [NOW, NOW - 1, 1] {
        let input = fixture.input(fixture.grant(expires));
        refused_pre_spawn(&fixture, &input, "RUNTIME_PROBE_GRANT_EXPIRED");
    }
    let mut grant = fixture.grant(NOW + TTL_MS);
    grant.provider = "codex".into();
    let refusal = refused_pre_spawn(
        &fixture,
        &fixture.input(grant),
        "RUNTIME_PROBE_GRANT_MISMATCH",
    );
    assert!(refusal.to_string().contains("provider"), "{refusal}");
    let mut grant = fixture.grant(NOW + TTL_MS);
    grant.containment = ContainmentClass::ReadOnlyWorkspaceAbsent;
    let refusal = refused_pre_spawn(
        &fixture,
        &fixture.input(grant),
        "RUNTIME_PROBE_GRANT_MISMATCH",
    );
    assert!(refusal.to_string().contains("containment"), "{refusal}");
    let mut grant = fixture.grant(NOW + TTL_MS);
    grant.executable_blake3 = hex('e');
    let refusal = refused_pre_spawn(
        &fixture,
        &fixture.input(grant),
        "RUNTIME_PROBE_GRANT_MISMATCH",
    );
    assert!(
        refusal.to_string().contains("executable_blake3"),
        "{refusal}"
    );
    for (field, value) in [
        ("grant_blake3", hex('G')),
        ("executable_blake3", "ab".into()),
    ] {
        let mut grant = fixture.grant(NOW + TTL_MS);
        match field {
            "grant_blake3" => grant.grant_blake3 = value,
            _ => grant.executable_blake3 = value,
        }
        refused_pre_spawn(&fixture, &fixture.input(grant), "RUNTIME_PROBE_MALFORMED");
    }

    // The deadline never exceeds the grant's remaining validity or the cap.
    assert_eq!(probe_deadline_ms(NOW + 600, NOW).unwrap(), 600);
    assert_eq!(
        probe_deadline_ms(NOW + 60_000, NOW).unwrap(),
        MAX_PROBE_DEADLINE_MS
    );
    assert_eq!(
        probe_deadline_ms(NOW, NOW).unwrap_err().reason_code(),
        "RUNTIME_PROBE_GRANT_EXPIRED"
    );
}

#[test]
fn kill_switch_refuses_before_spawn() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let fixture = Fixture::new(&format!("echo '{VERSION_LINE}'"));
    let input = fixture.input(fixture.grant(NOW + TTL_MS));
    std::env::set_var(KILL_SWITCH_VAR, "1");
    let refusal = refused_pre_spawn(&fixture, &input, "PROVIDER_KILL_ACTIVE");
    std::env::remove_var(KILL_SWITCH_VAR);
    assert!(matches!(refusal, ProbeRefusal::Harness(_)));
    // Any other value is not the kill switch.
    std::env::set_var(KILL_SWITCH_VAR, "0");
    let observation = probe_claude(&input);
    std::env::remove_var(KILL_SWITCH_VAR);
    assert_eq!(observation.unwrap().version(), VERSION_LINE);
}

#[test]
fn missing_containment_refuses_before_spawn() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let fixture = Fixture::new(&format!("echo '{VERSION_LINE}'"));
    let mut input = fixture.input(fixture.grant(NOW + TTL_MS));
    input.containment = None;
    refused_pre_spawn(&fixture, &input, "RUNTIME_PROBE_CONTAINMENT_MISSING");
    for receipt in ["", "c", &hex('C'), &format!("{}0", hex('c'))] {
        input.containment = Some(ProbeContainment {
            receipt_blake3: receipt.to_string(),
            command: &factory,
        });
        refused_pre_spawn(&fixture, &input, "RUNTIME_PROBE_CONTAINMENT_MISSING");
    }

    // The port cannot carry the inputs and never spawns.
    let error = ClaudeAdapter::new()
        .observe_runtime_probe(&fixture.grant(NOW + TTL_MS))
        .unwrap_err();
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_UNAVAILABLE");
    assert_eq!(fixture.spawn_count(), 0);
}

#[test]
fn oversized_stdout_is_refused_after_one_bounded_spawn() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let lines = MAX_PROBE_STDOUT_BYTES / 1_000 + 1;
    let body = format!("echo '{VERSION_LINE}'\ni=0\nwhile [ $i -lt {lines} ]; do /usr/bin/head -c 999 /dev/zero | /usr/bin/tr '\\0' x; echo; i=$((i+1)); done");
    let fixture = Fixture::new(&body);
    let refusal = refused(
        probe_claude(&fixture.input(fixture.grant(NOW + TTL_MS))),
        "RUNTIME_PROBE_OUTPUT_OVERSIZED",
    );
    assert!(
        refusal
            .to_string()
            .contains(&MAX_PROBE_STDOUT_BYTES.to_string()),
        "{refusal}"
    );
    assert_eq!(fixture.spawn_count(), 1);

    // Exactly at the bound is retained, not truncated.
    let filler = MAX_PROBE_STDOUT_BYTES - VERSION_LINE.len() - 1;
    let body = format!(
        "echo '{VERSION_LINE}'\n/usr/bin/head -c {filler} /dev/zero | /usr/bin/tr '\\0' y; echo"
    );
    let fixture = Fixture::new(&body);
    let observation = probe_claude(&fixture.input(fixture.grant(NOW + TTL_MS))).unwrap();
    assert_eq!(
        observation.facts().native_stdout.len(),
        MAX_PROBE_STDOUT_BYTES
    );
}

#[test]
fn hanging_script_is_refused_at_the_deadline_with_its_process_group_killed() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut fixture = Fixture::new("");
    let pid_file = fixture.dir.path().join("descendant.pid");
    fixture.write(&format!(
        "/usr/bin/sleep 30 & echo $! > {}\necho '{VERSION_LINE}'\nwait",
        pid_file.display()
    ));
    let started = Instant::now();
    let refusal = refused(
        probe_claude(&fixture.input(fixture.grant(NOW + 600))),
        "RUNTIME_PROBE_DEADLINE",
    );
    assert!(started.elapsed() < Duration::from_secs(5), "bounded kill");
    assert_eq!(refusal, ProbeRefusal::Deadline { deadline_ms: 600 });
    assert_eq!(fixture.spawn_count(), 1);
    assert_dead(&pid_file);

    // The deadline is the grant remainder when that is below the cap.
    let slow = Fixture::new(&format!("echo '{VERSION_LINE}'\n/usr/bin/sleep 0.3"));
    let mut input = slow.input(slow.grant(NOW + 100));
    input.now_unix_ms = NOW;
    let refusal = refused(probe_claude(&input), "RUNTIME_PROBE_DEADLINE");
    assert_eq!(refusal, ProbeRefusal::Deadline { deadline_ms: 100 });

    // A signal-terminated child has no exit code; nothing is invented.
    let killed = Fixture::new(&format!("echo '{VERSION_LINE}'\nkill -KILL $$"));
    refused(
        probe_claude(&killed.input(killed.grant(NOW + TTL_MS))),
        "RUNTIME_PROBE_EXIT_UNAVAILABLE",
    );
    assert_eq!(killed.spawn_count(), 1);
}

#[test]
fn control_characters_canaries_and_empty_output_are_refused() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    for body in [
        format!("printf '\\033[1m{VERSION_LINE}\\033[0m\\n'"),
        format!("printf '{VERSION_LINE}\\ttab\\n'"),
        format!("printf 'a\\rb\\n{VERSION_LINE}\\n'"),
        format!("printf '{VERSION_LINE}\\n'; printf 'nul\\0byte\\n'"),
        "printf '\\n\\n'".to_string(),
        format!("printf '\\303\\244 {VERSION_LINE}\\n'"),
    ] {
        let fixture = Fixture::new(&body);
        refused(
            probe_claude(&fixture.input(fixture.grant(NOW + TTL_MS))),
            "RUNTIME_PROBE_MALFORMED",
        );
        assert_eq!(fixture.spawn_count(), 1, "{body}");
    }
    let leaking = Fixture::new(&format!("echo '{VERSION_LINE}'\necho '{CANARY}'"));
    refused(
        probe_claude(&leaking.input(leaking.grant(NOW + TTL_MS))),
        "SECRET_CANARY_EXPOSURE",
    );
    let leaking = Fixture::new(&format!("echo '{VERSION_LINE}'\necho '{CANARY}' >&2"));
    refused(
        probe_claude(&leaking.input(leaking.grant(NOW + TTL_MS))),
        "SECRET_CANARY_EXPOSURE",
    );
    let invalid = Fixture::new(&format!("echo '{VERSION_LINE}'\nprintf '\\377\\n'"));
    refused(
        probe_claude(&invalid.input(invalid.grant(NOW + TTL_MS))),
        "IO_FAILED",
    );
}
