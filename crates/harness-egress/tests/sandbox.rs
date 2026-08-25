//! Live proofs on this machine: user+net namespace, slirp4netns uplink,
//! in-namespace nftables, host CONNECT proxy, receipt, and teardown.
//!
//! These tests need `unshare`, `nsenter`, `slirp4netns`, `nft`, `curl`,
//! `cat`, `kill`, and unprivileged user namespaces, so they are `#[ignore]`d
//! in the plain workspace run. `ops/ci/egress.sh` admits host capabilities and
//! executes their exact three-name filter with `cargo nextest run --locked
//! --workspace --run-ignored all --no-tests fail -E "$EGRESS_FILTER"`.
//! Unavailable capability is typed neutral 78; green means all three ran.
//! Only `curl`/`sh`/`sleep` run inside the namespace; no provider CLI.

use bullet_harness_egress::{
    Containment, Decision, EgressPolicy, EgressReceipt, EgressSandbox, PreparedSandbox,
    ProbeOutcome, JERYU_PORT, RECEIPT_FILE,
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const ENV: &[(&str, &str)] = &[("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), ("HOME", "/tmp")];
const IGNORE: &str =
    "needs unshare/nsenter/slirp4netns/nft/curl and user namespaces; run via ops/ci/egress.sh";

fn run(cmd: &mut Command) -> (Option<i32>, String, String) {
    let out = cmd.output().expect("spawn in-namespace command");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

fn curl(sandbox: &PreparedSandbox, args: &[&str]) -> (Option<i32>, String, String) {
    let mut argv = vec!["-q", "-s", "-o", "/dev/null"];
    argv.extend_from_slice(args);
    run(&mut sandbox.command("curl", &argv, ENV))
}

fn wait_gone(pid: u32) {
    let proc_dir = format!("/proc/{pid}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&proc_dir).exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !Path::new(&proc_dir).exists(),
        "pid {pid} still present after teardown"
    );
}

#[test]
#[ignore = "needs unshare/nsenter/slirp4netns/nft/curl and user namespaces; run via ops/ci/egress.sh"]
fn claude_strict_sandbox_proves_every_probe_and_blocks_real_commands() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = EgressSandbox::prepare(EgressPolicy::for_provider("claude").unwrap(), dir.path())
        .unwrap_or_else(|err| panic!("prepare: {err}"));
    let receipt = sandbox.receipt();
    receipt.verify().unwrap();
    assert_eq!(receipt.provider, "claude");
    assert_eq!(receipt.allowlist, vec!["api.anthropic.com".to_string()]);
    assert_eq!(receipt.proxy_port, sandbox.proxy_port());
    let names: Vec<&str> = receipt.probes.iter().map(|p| p.name.as_str()).collect();
    for required in [
        "direct-internet",
        "host-jeryu",
        "host-decoy",
        "proxy-disallowed",
        "proxy-allowed-path",
        "dns-blocked-tcp",
        "dns-blocked-udp",
        "proxy-reachable",
    ] {
        assert!(
            names.contains(&required),
            "missing probe {required}: {names:?}"
        );
    }
    assert!(receipt
        .probes
        .iter()
        .all(|p| p.outcome == ProbeOutcome::Pass));
    assert!(receipt.ruleset_listing.contains("policy drop"));
    assert_eq!(receipt.tools.len(), 7);
    let on_disk: EgressReceipt =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join(RECEIPT_FILE)).unwrap())
            .unwrap();
    assert_eq!(&on_disk, receipt);
    on_disk.verify().unwrap();
    let evidence = receipt.evidence();
    assert_eq!(evidence.receipt_digest, receipt.receipt_digest);
    assert_eq!(evidence.allowlist_digest, receipt.allowlist_digest);
    assert_eq!(evidence.ruleset_digest, receipt.ruleset_digest);
    assert_eq!(evidence.probes.len(), 5, "{:?}", evidence.probes);
    assert!(evidence
        .probes
        .iter()
        .all(|p| matches!(p.outcome, Containment::Refused | Containment::Unreachable)));

    let decisions = sandbox.decisions();
    assert!(decisions
        .iter()
        .any(|d| d.target == "example.com:443" && d.decision == Decision::Deny && d.status == 403));
    assert!(decisions.iter().any(|d| d.target == "api.anthropic.com:443"
        && d.decision == Decision::Allow
        && d.reason == "disarmed"));

    // Exactly the mission's command: with the proxy env in place curl asks the
    // proxy for 1.1.1.1:443, which the allowlist refuses (403 -> curl exit 56).
    let (code, _, _) = curl(&sandbox, &["-m", "3", "https://1.1.1.1/"]);
    assert!(
        code.is_some_and(|c| c != 0),
        "proxied 1.1.1.1 must fail: {code:?}"
    );
    // Bypassing the proxy proves the direct route itself is refused by nft.
    let (code, _, _) = curl(&sandbox, &["-m", "3", "--noproxy", "*", "https://1.1.1.1/"]);
    assert!(
        matches!(code, Some(7 | 28)),
        "direct internet reachable: {code:?}"
    );
    let jeryu = format!("http://10.0.2.2:{JERYU_PORT}/");
    let (code, _, _) = curl(&sandbox, &["-m", "3", "--noproxy", "*", &jeryu]);
    assert!(
        matches!(code, Some(7 | 28)),
        "host jeryu reachable: {code:?}"
    );
    let (_, connect, _) = curl(
        &sandbox,
        &["-m", "5", "-w", "%{http_connect}", "https://example.com/"],
    );
    assert_eq!(connect, "403", "env-driven proxy must refuse example.com");
    let (code, out, _) = run(&mut sandbox.command("env", &[], ENV));
    assert_eq!(code, Some(0));
    let expected_url = sandbox.proxy_url();
    let mut keys: Vec<&str> = out.lines().filter_map(|l| l.split('=').next()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "HOME",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "PATH",
            "http_proxy",
            "https_proxy",
            "no_proxy"
        ]
    );
    assert!(out.contains(&format!("HTTPS_PROXY={expected_url}")));
    assert!(out.lines().any(|l| l == "NO_PROXY="));
    let after = sandbox.decisions();
    assert!(
        after.len() > decisions.len(),
        "real command decisions must be logged"
    );
    assert!(after.iter().any(|d| d.target == "1.1.1.1:443"
        && d.decision == Decision::Deny
        && d.reason == "target:ipv4-literal"));
    let text = std::fs::read_to_string(sandbox.decision_log_path()).unwrap();
    assert!(text.lines().count() >= after.len());
}

#[test]
#[ignore = "needs unshare/nsenter/slirp4netns/nft/curl and user namespaces; run via ops/ci/egress.sh"]
fn custom_policy_tunnels_only_to_the_allowlisted_host_and_port() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let mut head = Vec::new();
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "client closed before request");
            head.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .unwrap();
        String::from_utf8_lossy(&head).into_owned()
    });
    let dir = tempfile::tempdir().unwrap();
    let policy = EgressPolicy::custom("tunnel-test", ["localhost"], [port]).unwrap();
    let sandbox = EgressSandbox::prepare(policy, dir.path()).unwrap_or_else(|err| panic!("{err}"));
    assert!(sandbox
        .receipt()
        .probes
        .iter()
        .all(|p| p.outcome == ProbeOutcome::Pass));
    let proxy = sandbox.proxy_url();
    let (code, body, err) = run(&mut sandbox.command(
        "curl",
        &[
            "-q",
            "-s",
            "-m",
            "5",
            "-p",
            "-x",
            &proxy,
            &format!("http://localhost:{port}/hello"),
        ],
        ENV,
    ));
    assert_eq!((code, body.as_str()), (Some(0), "hello"), "stderr: {err}");
    let request = server.join().unwrap();
    assert!(request.starts_with("GET /hello HTTP/1.1"), "{request}");
    let (_, connect, _) = curl(
        &sandbox,
        &[
            "-m",
            "5",
            "-p",
            "-x",
            &proxy,
            "-w",
            "%{http_connect}",
            &format!("http://localhost:{}/", port.wrapping_add(1).max(1)),
        ],
    );
    assert_eq!(connect, "403", "other port must be refused");
    let (_, connect, _) = curl(
        &sandbox,
        &[
            "-m",
            "5",
            "-p",
            "-x",
            &proxy,
            "-w",
            "%{http_connect}",
            &format!("http://127.0.0.1:{port}/"),
        ],
    );
    assert_eq!(
        connect, "403",
        "IP literal must be refused even for the allowed port"
    );
    let decisions = sandbox.decisions();
    assert!(decisions
        .iter()
        .any(|d| d.target == format!("localhost:{port}")
            && d.decision == Decision::Allow
            && d.reason == "tunnel"
            && d.status == 200));
    assert!(decisions
        .iter()
        .any(|d| d.decision == Decision::Deny && d.reason == "port-not-allowed"));
    assert!(decisions
        .iter()
        .any(|d| d.decision == Decision::Deny && d.reason == "target:ipv4-literal"));
    assert_eq!(sandbox.active_tunnels(), 0);
}

#[test]
#[ignore = "needs unshare/nsenter/slirp4netns/nft/curl and user namespaces; run via ops/ci/egress.sh"]
fn teardown_kills_holder_uplink_proxy_and_group_children() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = EgressSandbox::prepare(EgressPolicy::for_provider("codex").unwrap(), dir.path())
        .unwrap_or_else(|err| panic!("{err}"));
    let holder = sandbox.holder_pid();
    let slirp = sandbox.slirp_pid().expect("slirp pid");
    let port = sandbox.proxy_port();
    let mut child = sandbox.command("sleep", &["300"], ENV).spawn().unwrap();
    let child_pid = child.id();
    thread::sleep(Duration::from_millis(200));
    for pid in [holder, slirp, child_pid] {
        assert!(
            Path::new(&format!("/proc/{pid}")).exists(),
            "pid {pid} not running"
        );
    }
    let pgid = std::fs::read_to_string(format!("/proc/{child_pid}/stat")).unwrap();
    assert!(
        pgid.split_whitespace().nth(4) == Some(holder.to_string().as_str()),
        "child pgid: {pgid}"
    );
    assert!(TcpStream::connect_timeout(
        &(Ipv4Addr::LOCALHOST, port).into(),
        Duration::from_millis(500)
    )
    .is_ok());
    let receipt_path = sandbox.receipt_path().to_path_buf();
    drop(sandbox);
    wait_gone(holder);
    wait_gone(slirp);
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        child.try_wait().unwrap().is_some(),
        "group child survived teardown"
    );
    assert!(TcpStream::connect_timeout(
        &(Ipv4Addr::LOCALHOST, port).into(),
        Duration::from_millis(500)
    )
    .is_err());
    let receipt: EgressReceipt =
        serde_json::from_str(&std::fs::read_to_string(receipt_path).unwrap()).unwrap();
    receipt.verify().unwrap();
    assert_eq!(receipt.provider, "codex");
}

#[test]
fn ignore_reason_is_documented() {
    assert!(IGNORE.contains("ops/ci/egress.sh"));
}
