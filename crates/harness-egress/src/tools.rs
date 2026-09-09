//! Host tool discovery: every binary the sandbox drives, resolved once to an
//! absolute path with its version line, so the receipt records exactly what
//! ran.

use crate::error::{EgressCode, EgressError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const FALLBACK_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// Absolute path and version line of one host tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRecord {
    /// Absolute path resolved once at prepare time.
    pub path: String,
    /// First line of `<tool> --version`, bounded.
    pub version: String,
}

/// Every host tool the sandbox drives.
#[derive(Clone, Debug)]
pub struct Tooling {
    /// `unshare` (util-linux): creates the user+net namespace holder.
    pub unshare: ToolRecord,
    /// `nsenter` (util-linux): runs commands inside the namespace.
    pub nsenter: ToolRecord,
    /// `slirp4netns`: user-mode uplink with the host at `GATEWAY`.
    pub slirp4netns: ToolRecord,
    /// `nft`: installs and lists the in-namespace ruleset.
    pub nft: ToolRecord,
    /// `curl`: in-namespace probes.
    pub curl: ToolRecord,
    /// `cat`: the holder process body.
    pub cat: ToolRecord,
    /// `kill`: process-group teardown.
    pub kill: ToolRecord,
}

impl Tooling {
    /// Resolve every tool once.
    ///
    /// # Errors
    ///
    /// `EGRESS_TOOL_MISSING` naming the first absent tool.
    pub fn discover() -> Result<Self, EgressError> {
        Ok(Self {
            unshare: tool("unshare")?,
            nsenter: tool("nsenter")?,
            slirp4netns: tool("slirp4netns")?,
            nft: tool("nft")?,
            curl: tool("curl")?,
            cat: tool("cat")?,
            kill: tool("kill")?,
        })
    }

    /// Records keyed by tool name, for the receipt.
    #[must_use]
    pub fn records(&self) -> BTreeMap<String, ToolRecord> {
        [
            ("unshare", &self.unshare),
            ("nsenter", &self.nsenter),
            ("slirp4netns", &self.slirp4netns),
            ("nft", &self.nft),
            ("curl", &self.curl),
            ("cat", &self.cat),
            ("kill", &self.kill),
        ]
        .into_iter()
        .map(|(name, record)| (name.to_string(), record.clone()))
        .collect()
    }
}

/// Locate an executable on `PATH` plus the sbin fallbacks.
#[must_use]
pub fn find_tool(name: &str) -> Option<PathBuf> {
    let from_env = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&from_env)
        .chain(FALLBACK_DIRS.iter().map(PathBuf::from))
        .map(|dir| dir.join(name))
        .find(|candidate| {
            fs::metadata(candidate)
                .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

fn tool(name: &str) -> Result<ToolRecord, EgressError> {
    let path = find_tool(name).ok_or_else(|| {
        EgressError::new(
            EgressCode::ToolMissing,
            format!("{name} not found on PATH or in {FALLBACK_DIRS:?}"),
        )
    })?;
    let version = Command::new(&path)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .ok()
        .map(|out| {
            let text = if out.stdout.is_empty() {
                out.stderr
            } else {
                out.stdout
            };
            String::from_utf8_lossy(&text)
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(120)
                .collect::<String>()
        })
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    Ok(ToolRecord {
        path: path.to_string_lossy().into_owned(),
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_tool_resolves_known_and_rejects_unknown() {
        assert!(find_tool("sh").is_some_and(|p| p.is_absolute()));
        assert!(find_tool("definitely-not-a-tool-bf-egress").is_none());
    }

    #[test]
    fn missing_tool_is_typed() {
        let err = tool("definitely-not-a-tool-bf-egress").unwrap_err();
        assert_eq!(err.code, EgressCode::ToolMissing);
        assert!(err.detail.contains("definitely-not-a-tool-bf-egress"));
    }
}
