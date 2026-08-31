//! `bullet run`: read a durable run receipt back as prose a human can check.
//!
//! `show` **verifies rather than restates**. It recomputes the body digest over
//! the canonical body bytes and, for an effect-chain receipt, follows the chain
//! link: the receipt embeds the entire selection receipt at
//! `body.selection_receipt_hex`, and `body.selection_binding.receipt_body_digest`
//! must equal that embedded receipt's own `body_digest`. A renderer that only
//! reprinted fields would happily narrate a tampered or unrelated pair of files.
//!
//! Nothing here is authority. A receipt that renders is still `COMPONENT_PROOF`
//! with every eligibility flag false; the render says so on its own line so a
//! reader never mistakes a green render for a release.
//!
//! `print-preimages` is the author-side half of a hand-written PatchProposal:
//! preimages are BLAKE3 over the file bytes at the base commit, and an author
//! who computes one by hand gets a pre-apply refusal when they get it wrong.

use bullet_domain::{gate_definition, Digest, GateId};
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical, hash_framed_bytes};
use clap::Subcommand;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Receipts are small and bounded; refuse anything that is not.
const MAX_RECEIPT_BYTES: u64 = 1_048_576;

const SELECTION_SCHEMA: &str = "bullet.synthetic-selection-receipt.component.v1";
const SELECTION_BODY_DOMAIN: &str = "bullet.synthetic-selection-receipt.body.v1";
const EFFECT_SCHEMA: &str = "bullet.synthetic-effect-chain-receipt.component.v1";
const EFFECT_BODY_DOMAIN: &str = "bullet.synthetic-effect-chain-receipt.body.v1";

/// Every eligibility flag a component receipt carries. All nine are false on a
/// component proof; the render prints the count so `0/9` is visible, not implied.
const ELIGIBILITY_FLAGS: [&str; 9] = [
    "comparative_claim_eligible",
    "evolution_profile_eligible",
    "independent_evidence_eligible",
    "live_eligible",
    "provider_certification_eligible",
    "release_gate_eligible",
    "routing_activation_eligible",
    "team_recipe_eligible",
    "transaction_gate_eligible",
];

#[derive(Subcommand)]
pub enum RunCommands {
    /// Render one run receipt, verifying its digest and chain binding.
    Show {
        /// Path to a `.receipt.json` written by a run.
        receipt: PathBuf,
    },
    /// Emit PatchProposal preimages for paths at an exact base commit.
    PrintPreimages {
        /// Repository to read the base blobs from.
        #[arg(long)]
        repo: PathBuf,
        /// Exact base commit, as recorded in the proposal.
        #[arg(long)]
        base_sha: String,
        /// Repository-relative paths.
        #[arg(required = true)]
        paths: Vec<String>,
    },
}

pub fn run(command: RunCommands) -> Result<(), String> {
    match command {
        RunCommands::Show { receipt } => show(&receipt),
        RunCommands::PrintPreimages {
            repo,
            base_sha,
            paths,
        } => print_preimages(&repo, &base_sha, &paths),
    }
}

fn show(path: &Path) -> Result<(), String> {
    let bytes = read_bounded(path)?;
    let envelope: Value =
        decode_canonical(&bytes).map_err(|error| format!("RECEIPT_NOT_CANONICAL: {error}"))?;
    let schema = str_at(&envelope, "schema_version")?;

    // Dispatch before touching the body: an unknown schema must never have one
    // of its fields printed, because we do not know what those fields mean.
    let domain = match schema {
        SELECTION_SCHEMA => SELECTION_BODY_DOMAIN,
        EFFECT_SCHEMA => EFFECT_BODY_DOMAIN,
        other => return Err(format!("UNKNOWN_RECEIPT_SCHEMA: {other}")),
    };

    let body = envelope
        .get("body")
        .ok_or_else(|| "RECEIPT_BODY_MISSING".to_owned())?;
    let recorded = str_at(&envelope, "body_digest")?;
    let body_bytes =
        canonical_json(body).map_err(|error| format!("RECEIPT_BODY_NOT_CANONICAL: {error}"))?;
    let computed = hash_framed_bytes(domain, &body_bytes)
        .map_err(|error| format!("RECEIPT_DIGEST_UNCOMPUTABLE: {error}"))?;
    if computed != recorded {
        return Err(format!(
            "RECEIPT_BODY_DIGEST_MISMATCH: recorded {recorded}, computed {computed}"
        ));
    }

    let mut lines = vec![
        format!("receipt      {}", path.display()),
        format!("schema       {schema}"),
        format!("body_digest  OK ({})", short(recorded)),
    ];
    if schema == SELECTION_SCHEMA {
        render_selection(body, &mut lines)?;
    } else {
        render_effect_chain(body, &mut lines)?;
    }
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

fn render_selection(body: &Value, lines: &mut Vec<String>) -> Result<(), String> {
    common_header(body, lines)?;
    let shared = obj_at(body, "shared")?;
    lines.push(String::new());
    lines.push(format!("mission      {}", str_at(shared, "mission_id")?));
    lines.push(format!("base         {}", str_at(shared, "base_oid")?));
    lines.push(format!(
        "plan         {} (digest {})",
        str_at(shared, "plan_revision_id")?,
        short(str_at(shared, "plan_digest")?)
    ));
    lines.push(format!(
        "scope        {}",
        join_strings(shared, "scope_paths")?
    ));
    for gate in strings_at(shared, "gate_ids")? {
        lines.push(format!("gate         {}", describe_gate(&gate)));
    }

    let selection = obj_at(body, "selection")?;
    let views = selection
        .get("blinded_views")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let decision = selection
        .get("decision")
        .and_then(|d| d.get("rubric"))
        .and_then(Value::as_str)
        .unwrap_or("<absent>");
    lines.push(format!(
        "selection    {views} blinded views, rubric {decision}, winner {}",
        short(str_at(selection, "selected_candidate_id")?)
    ));

    let lanes = body
        .get("lanes")
        .and_then(Value::as_array)
        .ok_or_else(|| "RECEIPT_LANES_MISSING".to_owned())?;
    if lanes.is_empty() {
        return Err("RECEIPT_LANES_EMPTY".to_owned());
    }
    lines.push(String::new());
    lines.push(format!("lanes ({})", lanes.len()));
    for lane in lanes {
        lines.push(format!(
            "  {} fence {} -> {} {}",
            short(str_at(lane, "attempt_id")?),
            scalar_at(lane, "attempt_fence"),
            short(str_at(lane, "candidate_id")?),
            str_at(lane, "terminal_state").unwrap_or("?")
        ));
    }
    Ok(())
}

fn render_effect_chain(body: &Value, lines: &mut Vec<String>) -> Result<(), String> {
    common_header(body, lines)?;
    lines.push(format!(
        "authority    {}",
        str_at(body, "authority_class").unwrap_or("<absent>")
    ));

    let chain = obj_at(body, "effect_chain")?;
    lines.push(String::new());
    lines.push(format!(
        "effect       {} provider={} fence={}",
        short(str_at(chain, "effect_attempt_id").unwrap_or("<absent>")),
        str_at(chain, "provider").unwrap_or("?"),
        scalar_at(chain, "effect_fence")
    ));
    lines.push(format!(
        "state        dispatch={} settled={}",
        str_at(chain, "dispatch_state").unwrap_or("?"),
        str_at(chain, "settled_state").unwrap_or("?")
    ));
    lines.push(format!(
        "target_ref   {}",
        str_at(chain, "target_ref").unwrap_or("<absent>")
    ));

    // The chain link. The receipt carries the whole selection receipt inline;
    // verify it end to end rather than trusting two files that merely sit
    // beside each other.
    lines.push(String::new());
    lines.push(format!("chain        {}", verify_chain(body)?));
    Ok(())
}

/// Decode the embedded selection receipt, verify its own body digest, and
/// verify the binding digest recorded here equals it. Any break is an error,
/// never a rendered line that says everything is fine.
fn verify_chain(body: &Value) -> Result<String, String> {
    let hex = str_at(body, "selection_receipt_hex")?;
    let raw = hex_decode(hex)?;
    let embedded: Value = decode_canonical(&raw)
        .map_err(|error| format!("CHAIN_BROKEN: embedded receipt is not canonical: {error}"))?;
    if str_at(&embedded, "schema_version")? != SELECTION_SCHEMA {
        return Err("CHAIN_BROKEN: embedded receipt is not a selection receipt".to_owned());
    }
    let embedded_body = embedded
        .get("body")
        .ok_or_else(|| "CHAIN_BROKEN: embedded receipt has no body".to_owned())?;
    let embedded_bytes = canonical_json(embedded_body)
        .map_err(|error| format!("CHAIN_BROKEN: embedded body is not canonical: {error}"))?;
    let computed = hash_framed_bytes(SELECTION_BODY_DOMAIN, &embedded_bytes)
        .map_err(|error| format!("CHAIN_BROKEN: {error}"))?;
    let recorded = str_at(&embedded, "body_digest")?;
    if computed != recorded {
        return Err(format!(
            "CHAIN_BROKEN: embedded body digest is {computed}, receipt records {recorded}"
        ));
    }
    let binding = obj_at(body, "selection_binding")?;
    let bound = str_at(binding, "receipt_body_digest")?;
    if bound != recorded {
        return Err(format!(
            "CHAIN_BROKEN: binding names {bound}, embedded receipt is {recorded}"
        ));
    }
    Ok(format!(
        "selection receipt BOUND ({} bytes, {})",
        raw.len(),
        short(bound)
    ))
}

fn common_header(body: &Value, lines: &mut Vec<String>) -> Result<(), String> {
    let eligibility = obj_at(body, "eligibility")?;
    let mut set = 0usize;
    for flag in ELIGIBILITY_FLAGS {
        match eligibility.get(flag).and_then(Value::as_bool) {
            Some(true) => set += 1,
            Some(false) => {}
            None => return Err(format!("RECEIPT_ELIGIBILITY_INCOMPLETE: {flag}")),
        }
    }
    lines.push(format!(
        "evidence     {}",
        str_at(body, "evidence_class").unwrap_or("<absent>")
    ));
    lines.push(format!(
        "eligibility  {set}/{} — NOT a release receipt",
        ELIGIBILITY_FLAGS.len()
    ));
    lines.push(format!(
        "signing      {}",
        str_at(body, "signing_trust").unwrap_or("<absent>")
    ));
    lines.push(format!(
        "schedule     {}",
        str_at(body, "execution_schedule").unwrap_or("<absent>")
    ));
    Ok(())
}

/// Expand a sealed gate id into the exact argv it runs, so a reader sees the
/// command rather than an opaque identifier.
fn describe_gate(id: &str) -> String {
    let Ok(parsed) = GateId::parse(id) else {
        return format!("{} (unparseable id)", short(id));
    };
    match gate_definition(&parsed) {
        Some(definition) => format!(
            "{} -> {} ({}s)",
            short(id),
            definition.argv().join(" "),
            definition.timeout_secs()
        ),
        None => format!("{} (not in the sealed catalog)", short(id)),
    }
}

fn print_preimages(repo: &Path, base_sha: &str, paths: &[String]) -> Result<(), String> {
    let base = base_sha.strip_prefix("sha1:").unwrap_or(base_sha);
    for path in paths {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("show")
            .arg(format!("{base}:{path}"))
            .output()
            .map_err(|error| format!("PREIMAGE_GIT_UNAVAILABLE: {error}"))?;
        let line = if output.status.success() {
            let digest = Digest::of(&output.stdout).to_hex();
            format!(
                r#"{{"path":{},"preimage":{{"kind":"digest","digest":"{digest}"}}}}"#,
                json_string(path)
            )
        } else {
            // Absent at this commit is a first-class answer: a new file has no
            // preimage, and that is exactly what the proposal must say.
            format!(
                r#"{{"path":{},"preimage":{{"kind":"absent"}}}}"#,
                json_string(path)
            )
        };
        println!("{line}");
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|error| format!("RECEIPT_UNREADABLE: {error}"))?;
    if !meta.is_file() {
        return Err("RECEIPT_NOT_A_REGULAR_FILE".to_owned());
    }
    if meta.len() == 0 {
        return Err("RECEIPT_EMPTY".to_owned());
    }
    if meta.len() > MAX_RECEIPT_BYTES {
        return Err(format!("RECEIPT_TOO_LARGE: {} bytes", meta.len()));
    }
    std::fs::read(path).map_err(|error| format!("RECEIPT_UNREADABLE: {error}"))
}

/// Render a scalar that may be a string or a number. Receipts carry fences as
/// integers and identifiers as strings; a renderer that only understood strings
/// would silently print `?` for a fence that is present and correct.
fn scalar_at(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => "<absent>".to_owned(),
    }
}

fn str_at<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("RECEIPT_FIELD_MISSING: {key}"))
}

fn obj_at<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    let found = value
        .get(key)
        .ok_or_else(|| format!("RECEIPT_FIELD_MISSING: {key}"))?;
    if !found.is_object() {
        return Err(format!("RECEIPT_FIELD_NOT_OBJECT: {key}"));
    }
    Ok(found)
}

fn strings_at(value: &Value, key: &str) -> Result<Vec<String>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("RECEIPT_FIELD_MISSING: {key}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("RECEIPT_FIELD_NOT_STRING: {key}"))
        })
        .collect()
}

fn join_strings(value: &Value, key: &str) -> Result<String, String> {
    Ok(strings_at(value, key)?.join(", "))
}

fn short(value: &str) -> String {
    // Digests and ids are long; a reader compares prefixes. Never elide so far
    // that two distinct subjects render identically.
    match value.char_indices().nth(16) {
        Some((index, _)) => format!("{}…", &value[..index]),
        None => value.to_owned(),
    }
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("CHAIN_BROKEN: embedded receipt hex has odd length".to_owned());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("CHAIN_BROKEN: embedded receipt hex is not lowercase hex".to_owned()),
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}
