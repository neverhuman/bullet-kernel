//! `JeryuForge`: the live GitHub-compatible forge at 127.0.0.1:8787 behind
//! the same port. Per ADR 0002 the stored gh token for this host is invalid
//! and every capability requires an operator re-auth
//! (`gh auth login -h 127.0.0.1:8787`) plus a probe receipt before any
//! mutating call; until both exist, every method refuses with a typed
//! error and performs no live call.

use crate::error::EffectsError;
use crate::forge::{require_candidate_ref, ForgeDescriptor, ForgeEffects, PushRequest};
use std::path::PathBuf;

/// Default Jeryu base URL from ADR 0002.
pub const JERYU_BASE_URL: &str = "http://127.0.0.1:8787";
/// Provider label for intents targeting Jeryu.
pub const JERYU_PROVIDER: &str = "jeryu";
/// Environment variable carrying an operator-supplied token.
pub const JERYU_TOKEN_ENV: &str = "BULLET_JERYU_TOKEN";

/// Where the constructor found (or did not find) a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenSource {
    /// No token anywhere.
    None,
    /// A gh hosts entry exists for the host, but ADR 0002 records that
    /// stored token as invalid; it is never used.
    GhHostsInvalid,
    /// Operator-supplied token via [`JERYU_TOKEN_ENV`].
    Environment,
}

/// Live-forge adapter. Construction never performs network calls.
pub struct JeryuForge {
    base_url: String,
    token: Option<String>,
    token_source: TokenSource,
}

fn gh_hosts_mentions_host(hosts_path: &PathBuf, host: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(hosts_path) else {
        return false;
    };
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&raw) else {
        return false;
    };
    doc.get(host).is_some()
}

impl JeryuForge {
    /// Probe for a token without any live call: the environment first, then
    /// the gh hosts file (whose stored token ADR 0002 records as invalid —
    /// it is reported but never used).
    #[must_use]
    pub fn probe(base_url: &str) -> Self {
        if let Ok(token) = std::env::var(JERYU_TOKEN_ENV) {
            if !token.trim().is_empty() {
                return Self {
                    base_url: base_url.to_string(),
                    token: Some(token),
                    token_source: TokenSource::Environment,
                };
            }
        }
        let host = base_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_string();
        let hosts_path = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(".config/gh/hosts.yml");
        let token_source = if gh_hosts_mentions_host(&hosts_path, &host) {
            TokenSource::GhHostsInvalid
        } else {
            TokenSource::None
        };
        Self {
            base_url: base_url.to_string(),
            token: None,
            token_source,
        }
    }

    /// Where the token probe landed.
    #[must_use]
    pub fn token_source(&self) -> TokenSource {
        self.token_source
    }

    /// The REST root used by the read-only liveness probe.
    #[must_use]
    pub fn api_v3_url(&self) -> String {
        format!("{}/api/v3", self.base_url)
    }

    fn refuse(&self, method: &str) -> EffectsError {
        if self.token.is_none() {
            return EffectsError::ForgeUnauthenticated(format!(
                "{method} against {} requires `gh auth login -h 127.0.0.1:8787` (ADR 0002)",
                self.base_url
            ));
        }
        EffectsError::CapabilityUnprobed(format!(
            "{method} against {} has no probe receipt; ADR 0002 requires probing before mutation",
            self.base_url
        ))
    }
}

impl ForgeEffects for JeryuForge {
    fn descriptor(&self) -> ForgeDescriptor {
        ForgeDescriptor {
            provider: JERYU_PROVIDER.into(),
            authenticated: self.token.is_some(),
            can_push_candidate_ref: false,
            notes: match self.token_source {
                TokenSource::None => "no token; blocked on operator re-auth (ADR 0002)".into(),
                TokenSource::GhHostsInvalid => {
                    "gh hosts entry present but its token is recorded invalid (ADR 0002)".into()
                }
                TokenSource::Environment => "operator token present; capabilities unprobed".into(),
            },
        }
    }

    fn push_candidate_ref(&mut self, request: &PushRequest) -> Result<(), EffectsError> {
        require_candidate_ref(&request.ref_name)?;
        Err(self.refuse("push_candidate_ref"))
    }

    fn read_ref(&self, ref_name: &str) -> Result<Option<String>, EffectsError> {
        require_candidate_ref(ref_name)?;
        Err(self.refuse("read_ref"))
    }
}
