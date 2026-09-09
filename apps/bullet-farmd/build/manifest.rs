//! Canonical-JSON and manifest-record parsing for the Portal bundle subject.
//!
//! Mirrors `bullet-portal/ops/build/bundle.ts`: `canonicalJson` (sorted keys,
//! unsigned safe integers, no whitespace) and the framed BLAKE3 root over the
//! canonical body without `root`.

use super::records::{
    admit_path, digest, object_with_keys, oid, string, unsigned, FileRecord, MAX_SAFE_INTEGER,
};
use super::Refusal;
use serde_json::Value;
use std::collections::BTreeSet;

const SCHEMA_VERSION: &str = "bullet.portal.bundle.v1";
const ROOT_DOMAIN: &[u8] = b"bullet.portal.bundle.root.v1\0";
const MAX_FILES: usize = 2_048;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MANIFEST_KEYS: [&str; 7] = [
    "files",
    "package_lock",
    "root",
    "schema_version",
    "source",
    "tools",
    "total_size",
];
const SOURCE_KEYS: [&str; 3] = ["commit_oid", "repository", "tree_oid"];
const LOCK_KEYS: [&str; 3] = ["blake3", "path", "size"];
const FILE_KEYS: [&str; 4] = ["blake3", "mime", "path", "size"];
const TOOL_NAMES: [&str; 3] = ["git", "node", "npm"];

/// The admitted manifest subject.
pub struct Manifest {
    /// Framed BLAKE3 root, `blake3:<hex>`.
    pub root: String,
    /// Algorithm-tagged source commit OID.
    pub commit_oid: String,
    /// Algorithm-tagged source tree OID.
    pub tree_oid: String,
    /// File records in manifest (sorted) order.
    pub files: Vec<FileRecord>,
}

/// Parse the manifest bytes and prove they are the exact canonical form.
///
/// # Errors
///
/// Returns a typed refusal for non-canonical bytes, an unknown schema, a
/// malformed subject, or a root that does not bind its own body.
pub fn parse(raw: &[u8]) -> Result<Manifest, Refusal> {
    let value: Value = serde_json::from_slice(raw)
        .map_err(|error| Refusal::new("MANIFEST_INVALID_JSON", error.to_string()))?;
    let mut canonical = canonical_json(&value)?;
    canonical.push('\n');
    if canonical.as_bytes() != raw {
        return Err(Refusal::new(
            "MANIFEST_NOT_CANONICAL",
            "manifest bytes are not the canonical JSON form plus one newline",
        ));
    }
    let manifest = parse_body(&value)?;
    let root = compute_root(&value)?;
    if root != manifest.root {
        return Err(Refusal::new(
            "ROOT_MISMATCH",
            "manifest root does not bind its own body",
        ));
    }
    Ok(manifest)
}

/// Serialize `value` exactly as `ops/build/bundle.ts` `canonicalJson` does.
///
/// # Errors
///
/// Refuses non-integer, negative, or unsafe numbers and non-ASCII keys.
pub fn canonical_json(value: &Value) -> Result<String, Refusal> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), Refusal> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => {
            let unsigned = number
                .as_u64()
                .filter(|unsigned| *unsigned <= MAX_SAFE_INTEGER)
                .ok_or_else(|| {
                    Refusal::new(
                        "NON_CANONICAL_VALUE",
                        "manifest numbers must be unsigned safe integers",
                    )
                })?;
            out.push_str(&unsigned.to_string());
        }
        Value::String(text) => out.push_str(&quote(text)),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_object(map: &serde_json::Map<String, Value>, out: &mut String) -> Result<(), Refusal> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    out.push('{');
    for (index, key) in keys.iter().enumerate() {
        if !key.is_ascii() {
            return Err(Refusal::new(
                "NON_CANONICAL_VALUE",
                "manifest keys must be ASCII",
            ));
        }
        if index > 0 {
            out.push(',');
        }
        out.push_str(&quote(key));
        out.push(':');
        write_canonical(&map[*key], out)?;
    }
    out.push('}');
    Ok(())
}

/// JSON string literal with the same escapes as `JSON.stringify`.
fn quote(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| String::from("\"\""))
}

fn compute_root(value: &Value) -> Result<String, Refusal> {
    let Value::Object(map) = value else {
        return Err(Refusal::new(
            "MANIFEST_SCHEMA",
            "manifest must be an object",
        ));
    };
    let mut body = map.clone();
    body.remove("root");
    let canonical = canonical_json(&Value::Object(body))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROOT_DOMAIN);
    hasher.update(canonical.as_bytes());
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

fn parse_body(value: &Value) -> Result<Manifest, Refusal> {
    let map = object_with_keys(value, &MANIFEST_KEYS, "manifest")?;
    if string(map, "schema_version")? != SCHEMA_VERSION {
        return Err(Refusal::new(
            "MANIFEST_SCHEMA",
            "unsupported bundle schema version",
        ));
    }
    let source = object_with_keys(&map["source"], &SOURCE_KEYS, "source")?;
    if string(source, "repository")? != "bullet-portal" {
        return Err(Refusal::new(
            "SOURCE_SUBJECT_INVALID",
            "manifest source repository is not bullet-portal",
        ));
    }
    let commit_oid = oid(string(source, "commit_oid")?, "commit_oid")?;
    let tree_oid = oid(string(source, "tree_oid")?, "tree_oid")?;
    let root = digest(string(map, "root")?, "root")?.to_string();
    let lock = object_with_keys(&map["package_lock"], &LOCK_KEYS, "package_lock")?;
    if string(lock, "path")? != "package-lock.json" {
        return Err(Refusal::new(
            "MANIFEST_SCHEMA",
            "package_lock.path must be package-lock.json",
        ));
    }
    unsigned(lock, "size")?;
    digest(string(lock, "blake3")?, "package_lock.blake3")?;
    parse_tools(&map["tools"])?;
    let files = parse_files(&map["files"])?;
    let total: u64 = files.iter().map(|record| record.size).sum();
    if total > MAX_TOTAL_BYTES {
        return Err(Refusal::new(
            "BUNDLE_SIZE_EXCEEDED",
            format!("bundle exceeds {MAX_TOTAL_BYTES} bytes"),
        ));
    }
    if unsigned(map, "total_size")? != total {
        return Err(Refusal::new(
            "TOTAL_SIZE_MISMATCH",
            "total_size does not equal the sum of file sizes",
        ));
    }
    Ok(Manifest {
        root: format!("blake3:{root}"),
        commit_oid,
        tree_oid,
        files,
    })
}

fn parse_tools(value: &Value) -> Result<(), Refusal> {
    let subjects = value
        .as_array()
        .filter(|tools| tools.len() == TOOL_NAMES.len())
        .ok_or_else(|| {
            Refusal::new(
                "INVALID_SUBJECT",
                "tool subjects must contain exactly git, node, and npm",
            )
        })?;
    for (tool, expected) in subjects.iter().zip(TOOL_NAMES) {
        let tool = tool
            .as_object()
            .ok_or_else(|| Refusal::new("INVALID_SUBJECT", "tool subject must be an object"))?;
        if string(tool, "name")? != expected {
            return Err(Refusal::new(
                "INVALID_SUBJECT",
                "tool subjects must be git, node, npm in that order",
            ));
        }
        let version = string(tool, "version")?;
        let printable = (1..=160).contains(&version.len())
            && version.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
        if !printable {
            return Err(Refusal::new(
                "INVALID_SUBJECT",
                format!("{expected} version is invalid"),
            ));
        }
        if unsigned(tool, "size")? == 0 {
            return Err(Refusal::new(
                "INVALID_SUBJECT",
                format!("{expected} size is invalid"),
            ));
        }
        digest(string(tool, "blake3")?, "tool.blake3")?;
    }
    Ok(())
}

fn parse_files(value: &Value) -> Result<Vec<FileRecord>, Refusal> {
    let records = value
        .as_array()
        .filter(|records| (1..=MAX_FILES).contains(&records.len()))
        .ok_or_else(|| {
            Refusal::new(
                "BUNDLE_ENTRY_COUNT",
                format!("bundle must contain 1..{MAX_FILES} files"),
            )
        })?;
    let mut files: Vec<FileRecord> = Vec::with_capacity(records.len());
    let mut portable = BTreeSet::new();
    let mut index_count = 0_usize;
    for record in records {
        let record = object_with_keys(record, &FILE_KEYS, "file record")?;
        let path = string(record, "path")?.to_string();
        let mime = admit_path(&path)?;
        if string(record, "mime")? != mime {
            return Err(Refusal::new(
                "MIME_MISMATCH",
                format!("wrong MIME for {path}"),
            ));
        }
        let size = unsigned(record, "size")?;
        if size > MAX_FILE_BYTES {
            return Err(Refusal::new(
                "FILE_SIZE_EXCEEDED",
                format!("invalid size for {path}"),
            ));
        }
        let digest_hex = digest(string(record, "blake3")?, &format!("{path}.blake3"))?.to_string();
        if files.last().is_some_and(|previous| previous.path >= path) {
            return Err(Refusal::new(
                "BUNDLE_ORDER",
                format!("manifest files are not strictly sorted at {path}"),
            ));
        }
        if !portable.insert(path.to_ascii_lowercase()) {
            return Err(Refusal::new(
                "PORTABLE_PATH_COLLISION",
                format!("portable path collision: {path}"),
            ));
        }
        if path == "index.html" {
            index_count += 1;
        }
        files.push(FileRecord {
            path,
            mime,
            size,
            digest_hex,
        });
    }
    if index_count != 1 {
        return Err(Refusal::new(
            "MISSING_ENTRYPOINT",
            "bundle must contain exactly one index.html",
        ));
    }
    Ok(files)
}
