//! Actual binary component proof; no provider process or production authority.
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn daemon_provisions_and_loads_bootstrap_without_logging_credentials() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let token_path = temp.path().join("bootstrap.token");
    let binary = env!("CARGO_BIN_EXE_bullet-farmd");
    let provision = Command::new(binary)
        .arg("--provision-bootstrap-token")
        .arg(&token_path)
        .output()
        .unwrap();
    assert!(provision.status.success());
    let token = std::fs::read_to_string(&token_path).unwrap();
    assert!(token.starts_with("boot_"));
    for bytes in [&provision.stdout, &provision.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(&token));
    }
    let again = Command::new(binary)
        .arg("--provision-bootstrap-token")
        .arg(&token_path)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert_eq!(std::fs::read_to_string(&token_path).unwrap(), token);
    let combined = Command::new(binary)
        .arg("--provision-bootstrap-token")
        .arg(temp.path().join("extra.token"))
        .args(["--bind", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert!(!combined.status.success());
    assert!(!temp.path().join("extra.token").exists());
    for configured in [true, false] {
        let data = temp
            .path()
            .join(if configured { "configured" } else { "no-login" });
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        let log_path = data.join("output.log");
        let log: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log_path)
            .unwrap();
        let mut command = Command::new(binary);
        command
            .arg("--data-dir")
            .arg(&data)
            .args(["--bind", "127.0.0.1:0"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        if configured {
            command.arg("--bootstrap-token-file").arg(&token_path);
        }
        let mut process = Process(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "daemon exited before readiness"
            );
            let output = std::fs::read_to_string(&log_path).unwrap();
            assert!(output.len() < 65_536);
            assert!(!output.contains(&token));
            assert!(!output.contains("one-time bootstrap:"));
            if output.contains("bullet-farmd listening on") {
                assert!(output.contains(if configured {
                    "Bootstrap login enabled"
                } else {
                    "New bootstrap login disabled"
                }));
                break;
            }
            assert!(Instant::now() < deadline, "daemon did not become ready");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(process);
        let output = std::fs::read_to_string(log_path).unwrap();
        assert!(!output.contains(&token));
    }
}
