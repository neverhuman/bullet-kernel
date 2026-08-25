//! Guarded argv construction and the enclave environment contract.
//! Hard-denies worktree/tmux flags; strips SCM credentials from the child
//! environment; honors the `BULLET_PROVIDER_KILL` switch.

use crate::error::HarnessError;
use crate::EvaluatedAdmission;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Env var that, when set to `1`, refuses every provider spawn.
pub const KILL_SWITCH_VAR: &str = "BULLET_PROVIDER_KILL";

const DENIED_EXACT: [&str; 1] = ["-w"];
const DENIED_PREFIXES: [&str; 3] = ["--worktree", "--worktree-base", "--tmux"];
const INHERITED_ENV_ALLOWLIST: [&str; 7] = [
    "COLORTERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "TERM",
    "TZ",
];

/// The denial rule an argv token violates, when any.
#[must_use]
pub fn denied_token(arg: &str) -> Option<&'static str> {
    if DENIED_EXACT.contains(&arg) {
        return Some("-w");
    }
    DENIED_PREFIXES
        .iter()
        .find(|prefix| arg == **prefix || arg.starts_with(&format!("{prefix}=")))
        .copied()
}

/// Enclave inheritance contract: copy only non-authority locale/display
/// hints. Provider homes and credentials must eventually be staged by a
/// separate signed-admission boundary; they are never inherited here.
///
/// Results are key-sorted so the prepared invocation is deterministic for a
/// normal process environment (where each key is unique).
#[must_use]
pub fn filter_env<I>(vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    vars.into_iter()
        .filter(|(key, _)| INHERITED_ENV_ALLOWLIST.contains(&key.as_str()))
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .collect()
}

/// True when the kill switch value demands refusal.
#[must_use]
pub fn kill_switch_active(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Recognize every live-provider executable currently compiled into adapters.
#[must_use]
pub fn live_provider_program(program: &str) -> Option<&str> {
    let name = Path::new(program).file_name()?.to_str()?;
    match name {
        "claude" | "codex" | "cursor-agent" | "agy" => Some(name),
        _ => None,
    }
}

/// Max-invocations counter shared across one adapter's run.
#[derive(Debug)]
pub struct InvocationBudget {
    max: u32,
    used: AtomicU32,
}

impl InvocationBudget {
    /// Budget of `max` spawns.
    #[must_use]
    pub fn new(max: u32) -> Self {
        Self {
            max,
            used: AtomicU32::new(0),
        }
    }

    /// Spend one invocation.
    ///
    /// # Errors
    ///
    /// `INVOCATION_BUDGET_EXHAUSTED` once `max` spawns have been taken.
    pub fn try_acquire(&self) -> Result<u32, HarnessError> {
        let prior = self.used.fetch_add(1, Ordering::SeqCst);
        if prior >= self.max {
            self.used.fetch_sub(1, Ordering::SeqCst);
            return Err(HarnessError::InvocationBudgetExhausted { max: self.max });
        }
        Ok(prior + 1)
    }

    /// Invocations taken so far.
    #[must_use]
    pub fn used(&self) -> u32 {
        self.used.load(Ordering::SeqCst)
    }
}

/// Builder for one guarded provider invocation.
#[derive(Debug, Clone)]
pub struct ArgvBuilder {
    program: String,
    args: Vec<String>,
    cwd: PathBuf,
    timeout: Duration,
}

impl ArgvBuilder {
    /// New builder; cwd is mandatory because no provider gets a `--cwd` flag.
    #[must_use]
    pub fn new(program: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: cwd.into(),
            timeout: Duration::from_secs(180),
        }
    }

    /// Append one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Wall-clock bound for the whole invocation.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Validate and freeze the invocation.
    ///
    /// # Errors
    ///
    /// `PROVIDER_KILL_ACTIVE` when the kill switch is set;
    /// `WORKTREE_FLAG_DENIED` when any token matches the deny list; or
    /// `LIVE_ADMISSION_UNAVAILABLE` for a known live-provider executable.
    pub fn build(self) -> Result<PreparedInvocation, HarnessError> {
        self.validate_common()?;
        if let Some(provider) = live_provider_program(&self.program) {
            return Err(HarnessError::LiveAdmissionUnavailable {
                provider: provider.to_owned(),
            });
        }
        let env = filter_env(std::env::vars());
        Ok(PreparedInvocation {
            program: self.program,
            args: self.args,
            cwd: self.cwd,
            timeout: self.timeout,
            env,
        })
    }

    /// Build against a completed local admission evaluation. This method is
    /// structurally present so live adapters have one future chokepoint, but
    /// initial receipts contain signed-authority and egress blockers that
    /// verified evidence may clear before this chokepoint is reached.
    ///
    /// # Errors
    ///
    /// `PROVIDER_ADMISSION_BLOCKED` in this slice, or `ADMISSION_REFUSED`
    /// when argv attempts to substitute a different executable.
    pub fn build_with_admission(
        self,
        admission: &EvaluatedAdmission,
    ) -> Result<PreparedInvocation, HarnessError> {
        self.validate_common()?;
        if Path::new(&self.program) != admission.executable() {
            return Err(HarnessError::AdmissionRefused {
                reason: "argv executable differs from the evaluated admission".into(),
            });
        }
        admission.require_dispatch()?;
        Ok(PreparedInvocation {
            program: admission.executable().to_string_lossy().into_owned(),
            args: self.args,
            cwd: self.cwd,
            timeout: self.timeout,
            env: admission.child_env().to_vec(),
        })
    }

    fn validate_common(&self) -> Result<(), HarnessError> {
        if kill_switch_active(std::env::var(KILL_SWITCH_VAR).ok().as_deref()) {
            return Err(HarnessError::KillSwitch);
        }
        for arg in &self.args {
            if denied_token(arg).is_some() {
                return Err(HarnessError::WorktreeFlagDenied { token: arg.clone() });
            }
        }
        Ok(())
    }
}

/// A validated, ready-to-spawn invocation.
#[derive(Debug, Clone)]
pub struct PreparedInvocation {
    /// Program to run.
    pub program: String,
    /// Validated arguments.
    pub args: Vec<String>,
    /// Child working directory.
    pub cwd: PathBuf,
    /// Wall-clock bound.
    pub timeout: Duration,
    /// Filtered child environment.
    pub env: Vec<(String, String)>,
}

impl PreparedInvocation {
    /// Configure a tokio command: cleared env, filtered vars, own process
    /// group, piped stdio, kill-on-drop.
    #[must_use]
    pub fn command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worktree_and_tmux_tokens_are_denied() {
        for token in [
            "-w",
            "--worktree",
            "--worktree=side",
            "--worktree-base",
            "--worktree-base=main",
            "--tmux",
            "--tmux=classic",
        ] {
            let err = ArgvBuilder::new("claude", "/tmp")
                .arg("-p")
                .arg(token)
                .build()
                .unwrap_err();
            assert_eq!(err.reason_code(), "WORKTREE_FLAG_DENIED", "{token}");
        }
    }

    #[test]
    fn ordinary_non_provider_tokens_pass() {
        let prep = ArgvBuilder::new("printf", "/tmp")
            .args(["%s", "offline"])
            .build()
            .unwrap();
        assert_eq!(prep.program, "printf");
        assert_eq!(prep.cwd, PathBuf::from("/tmp"));
    }

    #[test]
    fn every_known_live_provider_is_quarantined() {
        for program in ["claude", "/opt/bin/codex", "cursor-agent", "/usr/bin/agy"] {
            let error = ArgvBuilder::new(program, "/tmp")
                .build()
                .expect_err("live provider must be denied before spawn");
            assert_eq!(error.reason_code(), "LIVE_ADMISSION_UNAVAILABLE");
        }
    }

    #[test]
    fn env_contract_is_a_positive_allowlist() {
        let vars = vec![
            ("HOME".to_string(), "/home/u".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
            ("TERM".to_string(), "xterm".to_string()),
            ("GH_TOKEN".to_string(), "x".to_string()),
            ("GITHUB_TOKEN".to_string(), "x".to_string()),
            ("SSH_AUTH_SOCK".to_string(), "/run/ssh".to_string()),
            ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
            ("GIT_AUTHOR_NAME".to_string(), "x".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "canary".to_string()),
            ("ANTHROPIC_API_KEY".to_string(), "canary".to_string()),
            ("OPENAI_API_KEY".to_string(), "canary".to_string()),
            ("BULLET_CANARY_SECRET".to_string(), "canary".to_string()),
        ];
        let kept = filter_env(vars);
        let keys: Vec<&str> = kept.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["LANG", "TERM"]);
        assert!(kept.iter().all(|(_, value)| value != "canary"));
    }

    #[test]
    fn env_contract_has_stable_key_order() {
        let kept = filter_env(vec![
            ("TZ".to_string(), "UTC".to_string()),
            ("LC_ALL".to_string(), "C".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
        ]);
        let keys: Vec<&str> = kept.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["LANG", "LC_ALL", "TZ"]);
    }

    #[test]
    fn kill_switch_semantics() {
        assert!(kill_switch_active(Some("1")));
        assert!(!kill_switch_active(Some("0")));
        assert!(!kill_switch_active(None));
    }

    #[test]
    fn invocation_budget_exhausts_typed() {
        let budget = InvocationBudget::new(2);
        assert_eq!(budget.try_acquire().unwrap(), 1);
        assert_eq!(budget.try_acquire().unwrap(), 2);
        let err = budget.try_acquire().unwrap_err();
        assert_eq!(err.reason_code(), "INVOCATION_BUDGET_EXHAUSTED");
        assert_eq!(budget.used(), 2);
    }
}
