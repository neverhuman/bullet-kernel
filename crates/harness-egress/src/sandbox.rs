//! `EgressSandbox::prepare` builds the whole boundary (proxy, namespace,
//! uplink, ruleset, probes, receipt) and yields a [`PreparedSandbox`] whose
//! commands run inside the namespace. Dropping it tears everything down.

use crate::allowlist::EgressPolicy;
use crate::decisions::{DecisionLog, DecisionRecord};
use crate::error::{EgressCode, EgressError};
use crate::filesystem::PreparedFilesystemSandbox;
use crate::namespace::{Namespace, BACKEND, GATEWAY};
use crate::probes::{require_all_pass, run_probes, ProbeContext};
use crate::proxy::{Proxy, ProxyLimits};
use crate::receipt::{EgressReceipt, SCHEMA_VERSION};
use crate::ruleset::{ruleset_digest, ruleset_text, verify_listing};
use crate::tools::{find_tool, Tooling};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// Receipt file name inside the sandbox work directory.
pub const RECEIPT_FILE: &str = "egress-receipt.json";
/// Decision log file name inside the sandbox work directory.
pub const DECISIONS_FILE: &str = "egress-decisions.jsonl";
const NFT_TIMEOUT: Duration = Duration::from_secs(5);

/// Builder entry point.
pub struct EgressSandbox;

impl EgressSandbox {
    /// Prepare a sandbox with default proxy limits.
    ///
    /// # Errors
    ///
    /// Any `EgressError`; on error nothing is left running.
    pub fn prepare(policy: EgressPolicy, workdir: &Path) -> Result<PreparedSandbox, EgressError> {
        Self::prepare_with(policy, workdir, ProxyLimits::default())
    }

    /// Prepare a sandbox: resolve tools, start the (disarmed) proxy, create
    /// the namespace holder, attach the uplink, install and verify the
    /// ruleset, run every probe, seal and persist the receipt, then arm the
    /// proxy. `workdir` receives the receipt, decision log, and tool stderr.
    ///
    /// # Errors
    ///
    /// Any `EgressError`; `EGRESS_ISOLATION_UNPROVEN` when a probe fails.
    pub fn prepare_with(
        policy: EgressPolicy,
        workdir: &Path,
        limits: ProxyLimits,
    ) -> Result<PreparedSandbox, EgressError> {
        let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let tools = Arc::new(Tooling::discover()?);
        fs::create_dir_all(workdir).map_err(|err| EgressError::io("create workdir", &err))?;
        let log_path = workdir.join(DECISIONS_FILE);
        let log = Arc::new(DecisionLog::open(&log_path, policy.provider())?);
        let proxy = Proxy::start(policy.clone(), Arc::clone(&log), limits)?;
        let mut namespace = Namespace::create(Arc::clone(&tools), workdir)?;
        namespace.attach_uplink(workdir)?;
        let text = ruleset_text(GATEWAY, proxy.port());
        install_ruleset(&namespace, &tools, &text)?;
        let listing = list_ruleset(&namespace, &tools)?;
        verify_listing(&listing, GATEWAY, proxy.port())?;
        let decoy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|err| EgressError::io("bind decoy listener", &err))?;
        let decoy_port = decoy
            .local_addr()
            .map_err(|err| EgressError::io("decoy addr", &err))?
            .port();
        let probes = run_probes(&ProbeContext {
            namespace: &namespace,
            tools: &tools,
            policy: &policy,
            log: &log,
            proxy_port: proxy.port(),
            decoy_port,
        })?;
        drop(decoy);
        let receipt = EgressReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            provider: policy.provider().to_string(),
            allowlist_mode: policy.mode(),
            namespace_backend: BACKEND.to_string(),
            gateway: GATEWAY.to_string(),
            proxy_port: proxy.port(),
            allowlist: policy.allowlist(),
            allowed_ports: policy.ports(),
            allowlist_digest: policy.allowlist_digest(),
            ruleset_digest: ruleset_digest(&text),
            ruleset_text: text,
            ruleset_listing: listing,
            probes,
            started_at,
            tools: tools.records(),
            receipt_digest: String::new(),
        }
        .seal()?;
        require_all_pass(&receipt.probes)?;
        let receipt_path = workdir.join(RECEIPT_FILE);
        write_receipt(&receipt_path, &receipt)?;
        proxy.arm();
        let holder_pid = namespace.holder_pid();
        let slirp_pid = namespace.slirp_pid();
        Ok(PreparedSandbox {
            policy,
            receipt,
            receipt_path,
            log,
            proxy,
            namespace,
            holder_pid,
            slirp_pid,
        })
    }
}

fn install_ruleset(ns: &Namespace, tools: &Tooling, text: &str) -> Result<(), EgressError> {
    let out = ns.run_captured(
        &tools.nft.path,
        &["-f", "-"],
        Some(text.as_bytes()),
        NFT_TIMEOUT,
    )?;
    if out.code == Some(0) {
        return Ok(());
    }
    Err(EgressError::new(
        EgressCode::RulesetFailed,
        format!(
            "nft -f exit {:?}: {}",
            out.code,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    ))
}

fn list_ruleset(ns: &Namespace, tools: &Tooling) -> Result<String, EgressError> {
    let out = ns.run_captured(&tools.nft.path, &["list", "ruleset"], None, NFT_TIMEOUT)?;
    if out.code != Some(0) {
        return Err(EgressError::new(
            EgressCode::RulesetFailed,
            format!(
                "nft list ruleset exit {:?}: {}",
                out.code,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn write_receipt(path: &Path, receipt: &EgressReceipt) -> Result<(), EgressError> {
    let json = serde_json::to_string_pretty(receipt)
        .map_err(|err| EgressError::new(EgressCode::IoFailed, format!("receipt json: {err}")))?;
    let mut file = File::create(path).map_err(|err| EgressError::io("create receipt", &err))?;
    file.write_all(json.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|err| EgressError::io("write receipt", &err))
}

/// A proven, live sandbox. Commands built from it run inside the namespace
/// with only the proxy variables plus the caller's environment.
pub struct PreparedSandbox {
    policy: EgressPolicy,
    receipt: EgressReceipt,
    receipt_path: PathBuf,
    log: Arc<DecisionLog>,
    proxy: Proxy,
    namespace: Namespace,
    holder_pid: u32,
    slirp_pid: Option<u32>,
}

impl PreparedSandbox {
    /// Build an exact filesystem-contained provider command inside this
    /// already-proven network namespace. The returned command has a closed
    /// environment and does not resolve either executable through `PATH`.
    ///
    /// Keep `filesystem` alive until the returned command has spawned.
    ///
    /// # Errors
    ///
    /// `EGRESS_FILESYSTEM_CHANGED` when any admitted host subject drifted.
    pub fn filesystem_command(
        &self,
        filesystem: &PreparedFilesystemSandbox,
        provider_args: &[&str],
    ) -> Result<Command, EgressError> {
        let proxy_url = self.proxy_url();
        let plan = filesystem.command_plan_with_proxy(provider_args, Some(&proxy_url))?;
        let mut command = self.namespace.enter(plan.program().as_os_str());
        command.args(plan.arguments()).env_clear();
        start_fresh_child_process_group(&mut command);
        Ok(command)
    }

    /// Command running `program` inside the namespace and the sandbox process
    /// group. The environment is exactly `env` plus `HTTPS_PROXY`,
    /// `HTTP_PROXY`, `NO_PROXY` (and their lowercase twins) pointing at the
    /// proxy; `NO_PROXY` is empty. A bare program name is resolved against
    /// the `PATH` in `env` (or this process's `PATH`) before entering.
    pub fn command(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
        let path_hint = env
            .iter()
            .find(|(key, _)| *key == "PATH")
            .map(|(_, value)| (*value).to_string())
            .or_else(|| std::env::var("PATH").ok());
        let resolved = resolve_program(program, path_hint.as_deref());
        let mut cmd = self.namespace.enter(&resolved);
        cmd.args(args).env_clear();
        for (key, value) in env {
            cmd.env(key, value);
        }
        let url = self.proxy_url();
        for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            cmd.env(key, &url);
        }
        cmd.env("NO_PROXY", "").env("no_proxy", "");
        cmd
    }

    /// Sealed receipt.
    #[must_use]
    pub const fn receipt(&self) -> &EgressReceipt {
        &self.receipt
    }

    /// Where the receipt JSON was written.
    #[must_use]
    pub fn receipt_path(&self) -> &Path {
        &self.receipt_path
    }

    /// Where the decision JSONL is appended.
    #[must_use]
    pub fn decision_log_path(&self) -> &Path {
        self.log.path()
    }

    /// Recent proxy decisions (bounded tail).
    #[must_use]
    pub fn decisions(&self) -> Vec<DecisionRecord> {
        self.log.recent()
    }

    /// Policy in force.
    #[must_use]
    pub const fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Host proxy port.
    #[must_use]
    pub fn proxy_port(&self) -> u16 {
        self.proxy.port()
    }

    /// Proxy URL as seen from inside the namespace.
    #[must_use]
    pub fn proxy_url(&self) -> String {
        format!("http://{GATEWAY}:{}", self.proxy.port())
    }

    /// Namespace holder pid (also the sandbox process group id).
    #[must_use]
    pub const fn holder_pid(&self) -> u32 {
        self.holder_pid
    }

    /// slirp4netns pid.
    #[must_use]
    pub const fn slirp_pid(&self) -> Option<u32> {
        self.slirp_pid
    }

    /// Open tunnels right now.
    #[must_use]
    pub fn active_tunnels(&self) -> usize {
        self.proxy.active_tunnels()
    }
}

impl Drop for PreparedSandbox {
    fn drop(&mut self) {
        self.namespace.teardown();
        self.proxy.shutdown();
        let _ = self.log.sync();
        if let Ok(file) = File::open(&self.receipt_path) {
            let _ = file.sync_all();
        }
    }
}

/// Place the next spawned child in a new process group (PGID = child pid).
pub(crate) fn start_fresh_child_process_group(command: &mut Command) {
    command.process_group(0);
}

fn resolve_program(program: &str, path_hint: Option<&str>) -> std::ffi::OsString {
    if program.contains('/') {
        return OsStr::new(program).to_os_string();
    }
    let from_hint = path_hint.and_then(|paths| {
        std::env::split_paths(paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    });
    from_hint.or_else(|| find_tool(program)).map_or_else(
        || OsStr::new(program).to_os_string(),
        PathBuf::into_os_string,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_child_process_group_is_the_kill_target() {
        let marker = std::env::temp_dir().join(format!("bullet-pgid-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut command = Command::new("python3");
        command
            .arg("-c")
            .arg(format!(
                "import os, time\nchild = os.fork()\nif child == 0:\n    time.sleep(60)\n    raise SystemExit(0)\nopen(r'{marker}', 'w').write('%d %d' % (os.getpid(), child))\ntime.sleep(60)",
                marker = marker.display()
            ))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        start_fresh_child_process_group(&mut command);
        let mut child = command.spawn().expect("spawn sleeper tree");
        let pid = child.id();
        let started = std::time::Instant::now();
        let pids = loop {
            if let Ok(text) = std::fs::read_to_string(&marker) {
                let parts: Vec<&str> = text.split_whitespace().collect();
                if parts.len() >= 2 {
                    break parts
                        .into_iter()
                        .map(|part| part.parse::<u32>().expect("pid"))
                        .collect::<Vec<_>>();
                }
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "shell did not publish pids"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let shell_pid = pids[0];
        let descendant = pids[1];
        assert_eq!(shell_pid, pid);
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let pgid = proc_pgid(&stat);
        assert_eq!(pgid, pid, "filesystem child must lead its own group");
        let pgid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap())
            .expect("child pid is a valid process group");
        rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL)
            .expect("kill the fresh child process group");
        let waited = child.wait();
        let _ = std::fs::remove_file(&marker);
        assert!(waited.is_ok(), "shell should exit after group kill");
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::path::Path::new(&format!("/proc/{descendant}")).exists()
            && std::time::Instant::now() < deadline
        {
            let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !std::path::Path::new(&format!("/proc/{descendant}")).exists(),
            "timeout kill must reap the descendant {descendant}"
        );
    }

    fn proc_pgid(stat: &str) -> u32 {
        let close = stat.rfind(')').expect("comm");
        let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
        fields[2].parse().expect("pgid")
    }

    #[test]
    fn program_resolution_prefers_the_caller_path_and_keeps_absolute_paths() {
        assert_eq!(
            resolve_program("/opt/x/claude", Some("/usr/bin")),
            "/opt/x/claude"
        );
        let resolved = resolve_program("sh", Some("/nonexistent:/usr/bin:/bin"));
        assert!(Path::new(&resolved).is_absolute(), "{resolved:?}");
        assert_eq!(
            resolve_program("definitely-not-a-tool-bf-egress", Some("/usr/bin")),
            "definitely-not-a-tool-bf-egress"
        );
    }
}
