//! Per-provider host allowlists and the [`EgressPolicy`] derived from them.
//!
//! The tables below are reviewed policy data, not discovery: every entry names
//! its purpose. `Strict` (the default) admits only the hosts a provider CLI
//! needs to make model API calls with pre-provisioned credentials. `Extended`
//! additionally admits interactive login and feature-flag hosts. Nothing is
//! ever admitted by suffix, wildcard, IP literal, or port other than the
//! policy's port set.

use crate::error::{EgressCode, EgressError};
use crate::request::{normalize_host, ConnectTarget};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Which entries of a provider table are admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowlistMode {
    /// Model API hosts only (default).
    Strict,
    /// API hosts plus login and feature-flag hosts.
    Extended,
}

/// One reviewed allowlist entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowlistEntry {
    /// Exact lowercase hostname.
    pub host: &'static str,
    /// Admitted in `Strict` mode when true; `Extended` only when false.
    pub strict: bool,
    /// Why the provider needs this host.
    pub rationale: &'static str,
}

const fn entry(host: &'static str, strict: bool, rationale: &'static str) -> AllowlistEntry {
    AllowlistEntry {
        host,
        strict,
        rationale,
    }
}

/// Claude Code (`claude`). `sentry.io` is deliberately absent: third-party
/// crash telemetry is never required to complete a task.
pub const CLAUDE: &[AllowlistEntry] = &[
    entry(
        "api.anthropic.com",
        true,
        "Anthropic Messages API; the only host needed for model calls with an API key.",
    ),
    entry(
        "claude.ai",
        false,
        "Claude.ai OAuth login and subscription-session flow; only interactive login needs it.",
    ),
    entry(
        "console.anthropic.com",
        false,
        "Console OAuth authorization/token exchange used by `claude login`.",
    ),
    entry(
        "statsig.anthropic.com",
        false,
        "Feature-flag and usage telemetry; not needed to complete a task, so strict mode blocks it.",
    ),
];

/// OpenAI Codex CLI (`codex`).
pub const CODEX: &[AllowlistEntry] = &[
    entry(
        "api.openai.com",
        true,
        "OpenAI Responses/Chat API used by the Codex CLI with an API key.",
    ),
    entry(
        "chatgpt.com",
        false,
        "ChatGPT-backed session endpoint and OAuth callback used by `codex login`.",
    ),
    entry(
        "auth.openai.com",
        false,
        "OpenAI OAuth authorization server used by `codex login`.",
    ),
];

/// Cursor agent CLI (`cursor-agent`). Hosts follow Cursor's published network
/// requirements; an operator must confirm them against the pinned CLI build.
pub const CURSOR: &[AllowlistEntry] = &[
    entry(
        "api2.cursor.sh",
        true,
        "Primary Cursor API gateway used for agent and model calls.",
    ),
    entry(
        "api3.cursor.sh",
        true,
        "Secondary Cursor API gateway (streaming/agent traffic).",
    ),
    entry(
        "repo42.cursor.sh",
        false,
        "Codebase-indexing upload endpoint; not required for a local task.",
    ),
    entry(
        "authenticator.cursor.sh",
        false,
        "Cursor login/OAuth service used by `cursor-agent login`.",
    ),
    entry(
        "cursor.com",
        false,
        "Login callback and account pages used during interactive login.",
    ),
];

/// Google Antigravity CLI (`agy`). Hosts are the Gemini API and Code Assist
/// endpoints; an operator must confirm them against the pinned CLI build.
pub const ANTIGRAVITY: &[AllowlistEntry] = &[
    entry(
        "generativelanguage.googleapis.com",
        true,
        "Gemini API used with an API key.",
    ),
    entry(
        "cloudcode-pa.googleapis.com",
        true,
        "Gemini Code Assist backend used by Google agent CLIs with OAuth credentials.",
    ),
    entry(
        "oauth2.googleapis.com",
        false,
        "Google OAuth token exchange/refresh used by interactive login.",
    ),
    entry(
        "accounts.google.com",
        false,
        "Google account sign-in used by interactive login.",
    ),
];

/// Provider wire name to table.
pub const PROVIDERS: &[(&str, &[AllowlistEntry])] = &[
    ("claude", CLAUDE),
    ("codex", CODEX),
    ("cursor", CURSOR),
    ("antigravity", ANTIGRAVITY),
];

/// Allowlist decision for one CONNECT target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Target host and port are admitted.
    Allow,
    /// Target refused; the reason is a short static token.
    Deny(&'static str),
}

/// Immutable egress policy: provider label, exact host set, and port set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressPolicy {
    provider: String,
    mode: AllowlistMode,
    hosts: BTreeSet<String>,
    ports: BTreeSet<u16>,
}

impl EgressPolicy {
    /// Strict policy for one of the four known providers.
    ///
    /// # Errors
    ///
    /// `EGRESS_ALLOWLIST_DENIED` for an unknown provider name.
    pub fn for_provider(provider: &str) -> Result<Self, EgressError> {
        Self::for_provider_with(provider, AllowlistMode::Strict)
    }

    /// Policy for a known provider in the given mode. Port 443 only.
    ///
    /// # Errors
    ///
    /// `EGRESS_ALLOWLIST_DENIED` for an unknown provider name.
    pub fn for_provider_with(provider: &str, mode: AllowlistMode) -> Result<Self, EgressError> {
        let table = PROVIDERS
            .iter()
            .find(|(name, _)| *name == provider)
            .map(|(_, table)| *table)
            .ok_or_else(|| {
                EgressError::new(
                    EgressCode::AllowlistDenied,
                    format!("unknown provider {provider:?}; no allowlist table"),
                )
            })?;
        let hosts = table
            .iter()
            .filter(|entry| entry.strict || mode == AllowlistMode::Extended)
            .map(|entry| entry.host.to_string())
            .collect();
        Ok(Self {
            provider: provider.to_string(),
            mode,
            hosts,
            ports: BTreeSet::from([443]),
        })
    }

    /// Explicit policy for tests and operator experiments. The provider label
    /// is recorded as `custom:<label>` so a receipt can never be mistaken for
    /// a provider table.
    ///
    /// # Errors
    ///
    /// `EGRESS_ALLOWLIST_DENIED` when the label, a host, or the port set is invalid.
    pub fn custom<H, P>(label: &str, hosts: H, ports: P) -> Result<Self, EgressError>
    where
        H: IntoIterator,
        H::Item: AsRef<str>,
        P: IntoIterator<Item = u16>,
    {
        let label_ok = !label.is_empty()
            && label.len() <= 64
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !label_ok {
            return Err(EgressError::new(
                EgressCode::AllowlistDenied,
                "custom policy label must be 1..=64 lowercase LDH characters",
            ));
        }
        let mut host_set = BTreeSet::new();
        for host in hosts {
            let normalized = normalize_host(host.as_ref()).map_err(|reason| {
                EgressError::new(
                    EgressCode::AllowlistDenied,
                    format!("invalid allowlist host {:?}: {reason}", host.as_ref()),
                )
            })?;
            host_set.insert(normalized);
        }
        let ports: BTreeSet<u16> = ports.into_iter().collect();
        if host_set.is_empty() || ports.is_empty() || ports.contains(&0) {
            return Err(EgressError::new(
                EgressCode::AllowlistDenied,
                "custom policy needs at least one host and one non-zero port",
            ));
        }
        Ok(Self {
            provider: format!("custom:{label}"),
            mode: AllowlistMode::Strict,
            hosts: host_set,
            ports,
        })
    }

    /// Provider label (`claude`, `codex`, `cursor`, `antigravity`, or `custom:<label>`).
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Allowlist mode.
    #[must_use]
    pub const fn mode(&self) -> AllowlistMode {
        self.mode
    }

    /// Sorted admitted hosts.
    #[must_use]
    pub fn allowlist(&self) -> Vec<String> {
        self.hosts.iter().cloned().collect()
    }

    /// Sorted admitted ports.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        self.ports.iter().copied().collect()
    }

    /// BLAKE3 hex over the canonical JSON `{"hosts":[...],"ports":[...]}`.
    #[must_use]
    pub fn allowlist_digest(&self) -> String {
        let canonical = serde_json::json!({
            "hosts": self.allowlist(),
            "ports": self.ports(),
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Decide one already-validated target. Exact host match, exact port set.
    #[must_use]
    pub fn decide(&self, target: &ConnectTarget) -> Decision {
        if !self.hosts.contains(&target.host) {
            return Decision::Deny("host-not-allowlisted");
        }
        if !self.ports.contains(&target.port) {
            return Decision::Deny("port-not-allowed");
        }
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::parse_connect_target;

    fn decide(policy: &EgressPolicy, raw: &str) -> Decision {
        policy.decide(&parse_connect_target(raw).expect("valid target"))
    }

    #[test]
    fn every_table_entry_is_a_normalized_hostname_with_rationale() {
        for (name, table) in PROVIDERS {
            assert!(!table.is_empty(), "{name}");
            assert!(table.iter().any(|e| e.strict), "{name} has no strict host");
            let mut seen = BTreeSet::new();
            for e in *table {
                assert_eq!(
                    normalize_host(e.host).as_deref(),
                    Ok(e.host),
                    "{name} {}",
                    e.host
                );
                assert!(e.rationale.len() > 20, "{name} {} rationale", e.host);
                assert!(seen.insert(e.host), "{name} duplicate {}", e.host);
            }
        }
    }

    #[test]
    fn strict_default_admits_only_api_hosts() {
        let strict = EgressPolicy::for_provider("claude").unwrap();
        assert_eq!(strict.allowlist(), vec!["api.anthropic.com".to_string()]);
        assert_eq!(strict.ports(), vec![443]);
        assert_eq!(strict.mode(), AllowlistMode::Strict);
        let extended = EgressPolicy::for_provider_with("claude", AllowlistMode::Extended).unwrap();
        assert_eq!(extended.allowlist().len(), CLAUDE.len());
        assert!(extended
            .allowlist()
            .contains(&"statsig.anthropic.com".to_string()));
        assert_ne!(strict.allowlist_digest(), extended.allowlist_digest());
        assert!(EgressPolicy::for_provider("gemini").is_err());
        assert_eq!(
            EgressPolicy::for_provider("Claude").unwrap_err().code,
            EgressCode::AllowlistDenied
        );
    }

    #[test]
    fn decisions_are_exact_on_host_and_port() {
        let policy = EgressPolicy::for_provider("claude").unwrap();
        assert_eq!(decide(&policy, "api.anthropic.com:443"), Decision::Allow);
        assert_eq!(decide(&policy, "API.ANTHROPIC.COM:443"), Decision::Allow);
        assert_eq!(
            decide(&policy, "api.anthropic.com:80"),
            Decision::Deny("port-not-allowed")
        );
        for raw in [
            "evil-api.anthropic.com:443",
            "api.anthropic.com.evil.example:443",
            "anthropic.com:443",
            "xapi.anthropic.com:443",
            "claude.ai:443",
            "example.com:443",
        ] {
            assert_eq!(
                decide(&policy, raw),
                Decision::Deny("host-not-allowlisted"),
                "{raw}"
            );
        }
    }

    #[test]
    fn custom_policy_validates_and_labels_itself() {
        let policy =
            EgressPolicy::custom("tunnel-test", ["LocalHost", "a.example"], [8443, 443]).unwrap();
        assert_eq!(policy.provider(), "custom:tunnel-test");
        assert_eq!(
            policy.allowlist(),
            vec!["a.example".to_string(), "localhost".to_string()]
        );
        assert_eq!(policy.ports(), vec![443, 8443]);
        assert_eq!(decide(&policy, "localhost:8443"), Decision::Allow);
        assert!(EgressPolicy::custom("Bad Label", ["a.example"], [443]).is_err());
        assert!(EgressPolicy::custom("x", ["1.1.1.1"], [443]).is_err());
        assert!(EgressPolicy::custom("x", ["a.example."], [443]).is_err());
        assert!(EgressPolicy::custom("x", Vec::<String>::new(), [443]).is_err());
        assert!(EgressPolicy::custom("x", ["a.example"], [0]).is_err());
        assert!(EgressPolicy::custom("x", ["a.example"], Vec::new()).is_err());
    }

    #[test]
    fn allowlist_digest_is_order_independent_and_stable() {
        let a = EgressPolicy::custom("d", ["b.example", "a.example"], [443, 80]).unwrap();
        let b = EgressPolicy::custom("d", ["a.example", "B.EXAMPLE"], [80, 443]).unwrap();
        assert_eq!(a.allowlist_digest(), b.allowlist_digest());
        let expected = blake3::hash(br#"{"hosts":["a.example","b.example"],"ports":[80,443]}"#)
            .to_hex()
            .to_string();
        assert_eq!(a.allowlist_digest(), expected);
    }
}
