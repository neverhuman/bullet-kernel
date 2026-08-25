//! CONNECT target validation and the typed request refusals.
//!
//! Nothing here resolves names or opens sockets: the parser yields a
//! normalized [`ConnectTarget`] (lowercase ASCII hostname plus port) or a typed
//! refusal, and the allowlist decision happens strictly afterwards. Bounded
//! request-head reading lives in `tunnel`.

use std::fmt;

/// Maximum bytes accepted for the request line.
pub const MAX_REQUEST_LINE: usize = 4096;
/// Maximum bytes accepted for the whole request head.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum number of header lines accepted.
pub const MAX_HEADER_LINES: usize = 64;
/// Maximum hostname length (RFC 1035 presentation limit).
pub const MAX_HOST_LEN: usize = 253;
/// Maximum DNS label length.
pub const MAX_LABEL_LEN: usize = 63;

/// A validated CONNECT target: lowercase ASCII hostname and non-zero port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectTarget {
    /// Lowercase ASCII hostname; never an IP literal.
    pub host: String,
    /// Destination port.
    pub port: u16,
}

impl fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why a request head was refused before any allowlist decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// Method other than `CONNECT`.
    MethodNotAllowed(String),
    /// The head exceeded a size bound.
    Oversized(&'static str),
    /// The head was syntactically unusable.
    Malformed(&'static str),
    /// The connection ended or failed before a complete head arrived.
    Io(String),
}

impl RequestError {
    /// HTTP status to answer with.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::MethodNotAllowed(_) => 405,
            Self::Oversized(_) => 431,
            Self::Malformed(_) | Self::Io(_) => 400,
        }
    }

    /// Short machine-readable reason for the decision log.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::MethodNotAllowed(method) => format!("method-not-allowed:{method}"),
            Self::Oversized(what) => format!("oversized:{what}"),
            Self::Malformed(what) => format!("malformed:{what}"),
            Self::Io(what) => format!("io:{what}"),
        }
    }
}

/// Validate and normalize a CONNECT authority (`host:port`).
///
/// # Errors
///
/// Returns a short static reason naming the first rule the input violates.
pub fn parse_connect_target(raw: &str) -> Result<ConnectTarget, &'static str> {
    if raw.is_empty() {
        return Err("empty");
    }
    if raw.len() > MAX_HOST_LEN + 6 {
        return Err("oversized");
    }
    if !raw.is_ascii() {
        return Err("non-ascii");
    }
    if raw.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err("whitespace-or-control");
    }
    if raw.contains('@') {
        return Err("userinfo");
    }
    if raw.contains('/') || raw.contains('?') || raw.contains('#') {
        return Err("not-authority-form");
    }
    if raw.contains('[') || raw.contains(']') {
        return Err("ipv6-literal");
    }
    if raw.contains('%') {
        return Err("percent-encoding");
    }
    let colons = raw.matches(':').count();
    let (host, port) = match colons {
        0 => return Err("port-missing"),
        1 => raw.split_once(':').unwrap_or((raw, "")),
        _ => return Err("multiple-colons"),
    };
    let port = parse_port(port)?;
    let host = normalize_host(host)?;
    Ok(ConnectTarget { host, port })
}

fn parse_port(port: &str) -> Result<u16, &'static str> {
    if port.is_empty() {
        return Err("port-empty");
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("port-charset");
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err("port-leading-zero");
    }
    let value: u32 = port.parse().map_err(|_| "port-range")?;
    match u16::try_from(value) {
        Ok(0) => Err("port-zero"),
        Ok(v) => Ok(v),
        Err(_) => Err("port-range"),
    }
}

/// Lowercase and validate one hostname. Rejects IP literals, trailing dots,
/// empty or hyphen-edged labels, and any non-ASCII or non-LDH character.
///
/// # Errors
///
/// Returns a short static reason naming the first rule the input violates.
pub fn normalize_host(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Err("host-empty");
    }
    if raw.len() > MAX_HOST_LEN {
        return Err("host-too-long");
    }
    if !raw.is_ascii() {
        return Err("non-ascii");
    }
    if raw.ends_with('.') {
        return Err("trailing-dot");
    }
    if raw.starts_with('.') {
        return Err("leading-dot");
    }
    let host = raw.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err("empty-label");
        }
        if label.len() > MAX_LABEL_LEN {
            return Err("label-too-long");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("host-charset");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("label-hyphen");
        }
    }
    if labels
        .last()
        .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("ipv4-literal");
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(raw: &str) -> Result<String, &'static str> {
        parse_connect_target(raw).map(|t| t.to_string())
    }

    #[test]
    fn accepts_exact_and_case_folded_targets() {
        assert_eq!(
            target("api.anthropic.com:443"),
            Ok("api.anthropic.com:443".into())
        );
        assert_eq!(
            target("API.Anthropic.COM:443"),
            Ok("api.anthropic.com:443".into())
        );
        assert_eq!(target("localhost:8443"), Ok("localhost:8443".into()));
        assert_eq!(
            target("xn--80ak6aa92e.com:80"),
            Ok("xn--80ak6aa92e.com:80".into())
        );
    }

    #[test]
    fn rejects_hostile_authorities() {
        let cases = [
            ("", "empty"),
            ("api.anthropic.com", "port-missing"),
            ("api.anthropic.com:", "port-empty"),
            ("api.anthropic.com.:443", "trailing-dot"),
            (".api.anthropic.com:443", "leading-dot"),
            ("api..anthropic.com:443", "empty-label"),
            ("-api.anthropic.com:443", "label-hyphen"),
            ("api.anthropic.com:443:443", "multiple-colons"),
            ("api.anthropic.com:0443", "port-leading-zero"),
            ("api.anthropic.com:65536", "port-range"),
            ("api.anthropic.com:0", "port-zero"),
            ("api.anthropic.com:44a", "port-charset"),
            ("api.anthropic.com:+443", "port-charset"),
            ("user@api.anthropic.com:443", "userinfo"),
            ("api.anthropic.com:443@evil.example:443", "userinfo"),
            ("[::1]:443", "ipv6-literal"),
            ("[2606:4700::1111]:443", "ipv6-literal"),
            ("::1:443", "multiple-colons"),
            ("1.1.1.1:443", "ipv4-literal"),
            ("10.0.2.2:8787", "ipv4-literal"),
            ("api.anthropic.com/x:443", "not-authority-form"),
            ("http://api.anthropic.com:443", "not-authority-form"),
            ("api.anthropic.com?x:443", "not-authority-form"),
            ("api.anthropic.com%2eevil.example:443", "percent-encoding"),
            ("api.anthropic.com\t:443", "whitespace-or-control"),
            ("api.anthropic.com :443", "whitespace-or-control"),
            ("api.anthr\u{f8}pic.com:443", "non-ascii"),
            ("api_anthropic.com:443", "host-charset"),
        ];
        for (raw, reason) in cases {
            assert_eq!(target(raw), Err(reason), "input {raw:?}");
        }
        let long_label = format!("{}.com:443", "a".repeat(64));
        assert_eq!(target(&long_label), Err("label-too-long"));
        let long_host = format!("{}:443", ["abcdefghij"; 26].join("."));
        assert_eq!(target(&long_host), Err("oversized"));
        let just_over: String = format!("{}.{}:443", "a".repeat(63), "b".repeat(190));
        assert_eq!(target(&just_over), Err("host-too-long"));
    }
}
