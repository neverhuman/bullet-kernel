//! Typed egress failures with stable reason codes. Fail closed, never panic.

use std::fmt;
use thiserror::Error;

/// Stable reason code for an egress isolation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EgressCode {
    /// A required host tool (`unshare`, `nsenter`, `slirp4netns`, `nft`, `curl`, `cat`, `kill`) is missing.
    ToolMissing,
    /// The user+network namespace holder could not be created, observed, or joined.
    NamespaceFailed,
    /// The `slirp4netns` uplink did not come up.
    UplinkFailed,
    /// The nftables ruleset could not be installed or verified inside the namespace.
    RulesetFailed,
    /// The host-side CONNECT proxy could not bind or serve.
    ProxyFailed,
    /// An in-namespace probe did not match its expected outcome; no child is launched.
    IsolationUnproven,
    /// A CONNECT target or policy entry was refused by the allowlist rules.
    AllowlistDenied,
    /// A filesystem-containment profile is outside the closed admission grammar.
    FilesystemDenied,
    /// An admitted filesystem object changed after preparation.
    FilesystemChanged,
    /// Filesystem or pipe I/O failed while building or recording the sandbox.
    IoFailed,
}

impl EgressCode {
    /// Wire reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolMissing => "EGRESS_TOOL_MISSING",
            Self::NamespaceFailed => "EGRESS_NAMESPACE_FAILED",
            Self::UplinkFailed => "EGRESS_UPLINK_FAILED",
            Self::RulesetFailed => "EGRESS_RULESET_FAILED",
            Self::ProxyFailed => "EGRESS_PROXY_FAILED",
            Self::IsolationUnproven => "EGRESS_ISOLATION_UNPROVEN",
            Self::AllowlistDenied => "EGRESS_ALLOWLIST_DENIED",
            Self::FilesystemDenied => "EGRESS_FILESYSTEM_DENIED",
            Self::FilesystemChanged => "EGRESS_FILESYSTEM_CHANGED",
            Self::IoFailed => "EGRESS_IO_FAILED",
        }
    }
}

impl fmt::Display for EgressCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Egress failure: a stable code plus a non-secret human-readable detail.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {detail}")]
pub struct EgressError {
    /// Stable reason code.
    pub code: EgressCode,
    /// Non-secret detail. Never contains request bodies or credentials.
    pub detail: String,
}

impl EgressError {
    /// Build an error from a code and detail.
    pub fn new(code: EgressCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Wrap an I/O failure with the context it occurred in.
    pub fn io(context: &str, err: &std::io::Error) -> Self {
        Self::new(EgressCode::IoFailed, format!("{context}: {err}"))
    }

    /// Stable wire reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.code.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_the_documented_prefix_and_is_unique() {
        let codes = [
            EgressCode::ToolMissing,
            EgressCode::NamespaceFailed,
            EgressCode::UplinkFailed,
            EgressCode::RulesetFailed,
            EgressCode::ProxyFailed,
            EgressCode::IsolationUnproven,
            EgressCode::AllowlistDenied,
            EgressCode::FilesystemDenied,
            EgressCode::FilesystemChanged,
            EgressCode::IoFailed,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in codes {
            assert!(code.as_str().starts_with("EGRESS_"), "{code}");
            assert!(seen.insert(code.as_str()), "duplicate {code}");
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn error_display_carries_code_and_detail() {
        let err = EgressError::new(EgressCode::ProxyFailed, "bind refused");
        assert_eq!(err.to_string(), "EGRESS_PROXY_FAILED: bind refused");
        assert_eq!(err.reason_code(), "EGRESS_PROXY_FAILED");
    }
}
