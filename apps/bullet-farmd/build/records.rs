//! Bundle path admission, MIME binding, and manifest field validators.
//!
//! Mirrors the record rules in `bullet-portal/ops/build/bundle.ts`.

use super::Refusal;
use serde_json::{Map, Value};

/// Largest admitted bundle path in bytes.
pub const MAX_PATH_BYTES: usize = 240;
/// Largest integer the JavaScript generator can express exactly.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

const MIME_BY_EXTENSION: [(&str, &str); 14] = [
    (".css", "text/css; charset=utf-8"),
    (".gif", "image/gif"),
    (".html", "text/html; charset=utf-8"),
    (".ico", "image/x-icon"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".png", "image/png"),
    (".svg", "image/svg+xml"),
    (".txt", "text/plain; charset=utf-8"),
    (".webp", "image/webp"),
    (".woff", "font/woff"),
    (".woff2", "font/woff2"),
];

/// One admitted manifest file record.
pub struct FileRecord {
    /// Bundle-relative path.
    pub path: String,
    /// MIME type bound by the manifest.
    pub mime: &'static str,
    /// Exact byte length.
    pub size: u64,
    /// Lowercase BLAKE3 hex digest without the `blake3:` tag.
    pub digest_hex: String,
}

/// Admit a bundle-relative path and return the MIME type bound to it.
///
/// Stricter than the TypeScript generator in one respect: paths must be ASCII,
/// because NFC normalization cannot be checked here without a new dependency.
///
/// # Errors
///
/// Refuses traversal, hidden, absolute, non-ASCII, unexpected-shape, and
/// unknown-extension paths.
pub fn admit_path(relative: &str) -> Result<&'static str, Refusal> {
    let forbidden = |detail: String| Refusal::new("INVALID_BUNDLE_PATH", detail);
    if relative.is_empty() || relative.len() > MAX_PATH_BYTES {
        return Err(forbidden("bundle path is empty or oversized".into()));
    }
    if !relative.is_ascii()
        || relative.starts_with('/')
        || relative.contains(['\\', ':'])
        || relative.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(forbidden(format!(
            "bundle path has forbidden syntax: {relative:?}"
        )));
    }
    let components: Vec<&str> = relative.split('/').collect();
    for component in &components {
        let admitted = !component.is_empty()
            && !component.starts_with('.')
            && !component.ends_with(['.', ' '])
            && !component.eq_ignore_ascii_case(".git");
        if !admitted {
            return Err(forbidden(format!(
                "bundle path has forbidden component: {relative:?}"
            )));
        }
    }
    if relative != "index.html" && !(components.len() == 2 && components[0] == "assets") {
        return Err(Refusal::new(
            "UNEXPECTED_BUNDLE_ENTRY",
            format!("unexpected bundle path: {relative}"),
        ));
    }
    mime_for(components[components.len() - 1]).ok_or_else(|| {
        Refusal::new(
            "UNEXPECTED_BUNDLE_ENTRY",
            format!("unsupported bundle extension: {relative}"),
        )
    })
}

fn mime_for(name: &str) -> Option<&'static str> {
    let extension = name.rfind('.').filter(|index| *index > 0)?;
    MIME_BY_EXTENSION
        .iter()
        .find(|(candidate, _)| *candidate == &name[extension..])
        .map(|(_, mime)| *mime)
}

pub fn object_with_keys<'a>(
    value: &'a Value,
    keys: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, Refusal> {
    let map = value
        .as_object()
        .ok_or_else(|| Refusal::new("MANIFEST_SCHEMA", format!("{label} must be an object")))?;
    let mut actual: Vec<&str> = map.keys().map(String::as_str).collect();
    actual.sort_unstable();
    if actual != keys {
        return Err(Refusal::new(
            "MANIFEST_SCHEMA",
            format!("{label} must have exactly the keys {keys:?}"),
        ));
    }
    Ok(map)
}

pub fn string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, Refusal> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("MANIFEST_SCHEMA", format!("{key} must be a string")))
}

pub fn unsigned(map: &Map<String, Value>, key: &str) -> Result<u64, Refusal> {
    map.get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| {
            Refusal::new(
                "MANIFEST_SCHEMA",
                format!("{key} must be an unsigned safe integer"),
            )
        })
}

fn is_lower_hex(text: &str, width: usize) -> bool {
    text.len() == width
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validate `blake3:<64 lowercase hex>` and return the hex payload.
pub fn digest<'a>(value: &'a str, field: &str) -> Result<&'a str, Refusal> {
    value
        .strip_prefix("blake3:")
        .filter(|hex| is_lower_hex(hex, 64))
        .ok_or_else(|| {
            Refusal::new(
                "INVALID_SUBJECT",
                format!("{field} must be a full lowercase BLAKE3 digest"),
            )
        })
}

/// Validate an algorithm-tagged Git OID (`sha1:`+40 hex or `sha256:`+64 hex).
pub fn oid(value: &str, field: &str) -> Result<String, Refusal> {
    let admitted = value
        .strip_prefix("sha1:")
        .is_some_and(|hex| is_lower_hex(hex, 40))
        || value
            .strip_prefix("sha256:")
            .is_some_and(|hex| is_lower_hex(hex, 64));
    if admitted {
        Ok(value.to_string())
    } else {
        Err(Refusal::new(
            "SOURCE_SUBJECT_INVALID",
            format!("source.{field} is not an exact algorithm-tagged Git OID"),
        ))
    }
}
