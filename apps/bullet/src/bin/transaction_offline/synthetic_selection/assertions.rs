//! Strict durable reopen checks forming the A-before-B barrier.

mod checkpoint;
mod preservation;
#[cfg(test)]
mod tests;

use super::super::support::fail;
use super::journal::LaneJournalEntry;
use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{LeaseSettlementOutcome, LeaseSettlementRequest};
use bullet_application::Ledger;
use bullet_domain::{AttemptState, Candidate, Digest, REPOSITORY_GATE_ID};
use bullet_harness_core::{PatchMutation, PatchProposal, Preimage};
use bullet_runner_core::gitd::CheckpointBinding;
use bullet_runner_core::{AcquireGrant, AttemptOutcome};
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_RAW_BYTES: u64 = 1_048_576;

pub(super) struct LaneBarrier {
    pub(super) candidate: Candidate,
    pub(super) settlement_id: String,
    pub(super) raw_artifact: PathBuf,
    pub(super) raw_digest: String,
    pub(super) repository: PathBuf,
}

pub(super) fn require_failed_abort(
    database: &Path,
    grant: &AcquireGrant,
    settlement: &LeaseSettlementRequest,
) -> Result<(), String> {
    let LeaseSettlementRequest::Release(body) = settlement else {
        return Err(fail("primed abort settlement is not release"));
    };
    if body.expected_state != AttemptState::Starting
        || body.final_state != AttemptState::Failed
        || !body.requeue
    {
        return Err(fail("primed abort is not Starting->Failed/requeue"));
    }
    let id = settlement
        .settlement_id()
        .map_err(|error| fail(format!("derive primed abort settlement: {error}")))?;
    let mut ledger = SqliteLedger::open(database)
        .map_err(|error| fail(format!("reopen primed abort ledger: {error}")))?;
    let record = ledger
        .with_lease_transport(|transaction| transaction.get_transport_settlement(&id))
        .map_err(|error| fail(format!("reopen primed abort settlement: {error}")))?
        .ok_or_else(|| fail("primed abort settlement disappeared"))?;
    let released = matches!(
        record.outcome,
        LeaseSettlementOutcome::Released(ref attempt)
            if attempt.id == grant.attempt.id && attempt.state == AttemptState::Failed
    );
    if record.request != *settlement
        || !released
        || ledger
            .get_lease(&grant.attempt.variant_id)
            .map_err(|error| fail(format!("reopen primed abort lease: {error}")))?
            .is_some()
    {
        return Err(fail("primed abort durable truth differs"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn close_lane(
    database: &Path,
    workspace_root: &Path,
    preservation_destination: &Path,
    base: &str,
    grant: &AcquireGrant,
    outcome: &AttemptOutcome,
    settlement: &LeaseSettlementRequest,
    journal: &[LaneJournalEntry],
    recovery_reopened: bool,
) -> Result<LaneBarrier, String> {
    if outcome.attempt_id != grant.attempt.id
        || outcome.fence != grant.attempt.fence
        || outcome.fence != 1
        || outcome.candidate.actual_scope != ["PONG.txt"]
        || !recovery_reopened
    {
        return Err(fail(
            "synthetic lane outcome/recovery differs from exact subject",
        ));
    }
    let repository = preservation::admit(workspace_root, preservation_destination, grant, outcome)?;
    require_journal(journal)?;
    let candidate = candidate_projection(outcome)?;
    let raw_artifact = workspace_root
        .join("artifacts")
        .join(grant.attempt.id.as_str())
        .join(format!("{}.raw.jsonl", grant.attempt.id));
    let raw =
        super::private_artifact::read(&raw_artifact, MAX_RAW_BYTES, "simulator raw artifact")?;
    let checkpoint = checkpoint::initial_checkpoint(&repository, base)?;
    require_raw_proposal(&raw, grant.attempt.id.as_str(), &checkpoint)?;
    require_git_candidate(&repository, base, outcome)?;

    let mut ledger = SqliteLedger::open(database)
        .map_err(|error| fail(format!("reopen synthetic lane ledger: {error}")))?;
    if !ledger
        .put_candidate(&candidate)
        .map_err(|error| fail(format!("persist Candidate projection: {error}")))?
    {
        return Err(fail("new synthetic Candidate unexpectedly replayed"));
    }
    drop(ledger);
    let mut reopened = SqliteLedger::open(database)
        .map_err(|error| fail(format!("reopen synthetic barrier ledger: {error}")))?;
    if reopened
        .get_candidate(&candidate.id)
        .map_err(|error| fail(format!("reopen Candidate projection: {error}")))?
        .as_ref()
        != Some(&candidate)
    {
        return Err(fail("Candidate projection changed on reopen"));
    }
    let attempt = reopened
        .get_attempt(&grant.attempt.id)
        .map_err(|error| fail(format!("reopen terminal Attempt: {error}")))?
        .ok_or_else(|| fail("terminal Attempt disappeared"))?;
    if attempt.state != AttemptState::Superseded
        || reopened
            .get_lease(&grant.attempt.variant_id)
            .map_err(|error| fail(format!("reopen terminal lease: {error}")))?
            .is_some()
    {
        return Err(fail("synthetic lane is not durably terminal"));
    }
    let settlement_id = settlement
        .settlement_id()
        .map_err(|error| fail(format!("derive settlement id: {error}")))?;
    let record = reopened
        .with_lease_transport(|transaction| transaction.get_transport_settlement(&settlement_id))
        .map_err(|error| fail(format!("reopen settlement row: {error}")))?
        .ok_or_else(|| fail("settlement row disappeared"))?;
    let released = matches!(
        &record.outcome,
        LeaseSettlementOutcome::Released(value)
            if value.id == grant.attempt.id
                && value.variant_id == grant.attempt.variant_id
                && value.fence == grant.attempt.fence
                && value.state == AttemptState::Superseded
    );
    let LeaseSettlementRequest::Release(body) = settlement else {
        return Err(fail("synthetic terminal request is not release"));
    };
    if record.request != *settlement
        || !released
        || body.expected_state != AttemptState::Preparing
        || body.final_state != AttemptState::Superseded
        || !body.requeue
    {
        return Err(fail(
            "settlement differs from Preparing->Superseded/requeue",
        ));
    }
    Ok(LaneBarrier {
        candidate,
        settlement_id,
        raw_artifact,
        raw_digest: Digest::of(&raw).to_hex(),
        repository,
    })
}

fn require_journal(entries: &[LaneJournalEntry]) -> Result<(), String> {
    let candidate = entries
        .iter()
        .any(|entry| entry.stage == "candidate_prepared");
    let released = entries
        .iter()
        .any(|entry| entry.stage == "released" && entry.detail == "superseded requeue=true");
    let ordered = entries
        .iter()
        .enumerate()
        .all(|(index, entry)| entry.sequence == (index + 1) as u64);
    if !candidate
        || !released
        || !ordered
        || entries.last().map(|entry| entry.stage.as_str()) != Some("terminated")
    {
        return Err(fail("reopened lane journal lacks exact terminal truth"));
    }
    Ok(())
}

fn candidate_projection(outcome: &AttemptOutcome) -> Result<Candidate, String> {
    Ok(Candidate {
        id: bullet_domain::CandidateId::parse(&outcome.candidate.id)
            .map_err(|error| fail(format!("parse Candidate id: {error}")))?,
        attempt_id: outcome.attempt_id.clone(),
        base_sha: outcome.candidate.base_commit.clone(),
        head_sha: outcome.candidate.head_commit.clone(),
        tree_sha: outcome.candidate.tree_hash.clone(),
        patch_digest: Digest::from_hex(&outcome.candidate.patch_hash)
            .map_err(|error| fail(format!("parse Candidate patch digest: {error}")))?,
    })
}

fn require_raw_proposal(
    raw: &[u8],
    attempt_id: &str,
    checkpoint: &CheckpointBinding,
) -> Result<(), String> {
    if raw.last() != Some(&b'\n') {
        return Err(fail("simulator raw artifact is truncated"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| fail("simulator raw artifact is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    let mut terminal = None;
    for (index, line) in lines.iter().enumerate() {
        let value = bullet_harness_core::strict_json::decode_strict_json(line)
            .map_err(|error| fail(format!("strict simulator event decode: {error}")))?;
        let object = value
            .as_object()
            .filter(|object| {
                object.len() == 2 && object.contains_key("kind") && object.contains_key("payload")
            })
            .ok_or_else(|| fail("simulator event is not recursively closed"))?;
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("turn.completed") if index + 1 == lines.len() && terminal.is_none() => {
                let payload = object
                    .get("payload")
                    .and_then(serde_json::Value::as_object)
                    .filter(|payload| {
                        payload.len() == 2
                            && payload.contains_key("proposal")
                            && payload.get("text").and_then(serde_json::Value::as_str)
                                == Some("done")
                    })
                    .ok_or_else(|| fail("simulator terminal payload is not exact"))?;
                terminal = payload.get("proposal").cloned();
            }
            Some("turn.completed" | "turn.failed") => {
                return Err(fail("simulator terminal is duplicate or not last"));
            }
            Some(_) => {}
            None => return Err(fail("simulator event kind is absent")),
        }
    }
    let proposal = PatchProposal::from_value(
        &terminal.ok_or_else(|| fail("simulator completion proposal is absent"))?,
    )
    .map_err(|error| fail(format!("strict simulator proposal: {error}")))?;
    let exact_operation = matches!(
        proposal.operations.as_slice(),
        [operation]
            if operation.path == "PONG.txt"
                && operation.preimage == Preimage::Absent
                && operation.mutation == (PatchMutation::Write { content_utf8: "PONG\n".into() })
    );
    if proposal.producing_attempt_id != attempt_id
        || proposal.base_checkpoint_id != checkpoint.id
        || proposal.base_checkpoint_digest != checkpoint.digest
        || proposal.gate_ids != [REPOSITORY_GATE_ID]
        || !exact_operation
    {
        return Err(fail("simulator proposal differs from exact lane subject"));
    }
    Ok(())
}

fn require_git_candidate(
    repository: &Path,
    base: &str,
    outcome: &AttemptOutcome,
) -> Result<(), String> {
    let head = git(repository, &["rev-parse", "HEAD"])?;
    let tree = git(repository, &["rev-parse", "HEAD^{tree}"])?;
    let base_hex = strip_oid(base);
    let expected_head = strip_oid(&outcome.candidate.head_commit);
    let expected_tree = strip_oid(&outcome.candidate.tree_hash);
    let range = format!("{base_hex}..{expected_head}");
    let diff = git_bytes(
        repository,
        &["diff", "--no-ext-diff", "--no-textconv", &range],
    )?;
    let scope = git(
        repository,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            &range,
        ],
    )?;
    if head != expected_head
        || tree != expected_tree
        || Digest::of(&diff).to_hex() != outcome.candidate.patch_hash
        || scope.lines().collect::<Vec<_>>() != ["PONG.txt"]
        || outcome.candidate.base_commit != base
    {
        return Err(fail("Candidate receipt differs from exact Git bytes"));
    }
    Ok(())
}

fn git(repository: &Path, args: &[&str]) -> Result<String, String> {
    let bytes = git_bytes(repository, args)?;
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|_| fail("Git output is not UTF-8"))
}

fn git_bytes(repository: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("/usr/bin/git")
        .arg("--no-replace-objects")
        .args(args)
        .current_dir(repository)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| fail(format!("spawn admitted Git readback: {error}")))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(fail("admitted Git readback failed or wrote stderr"));
    }
    Ok(output.stdout)
}

fn strip_oid(value: &str) -> &str {
    value.rsplit(':').next().unwrap_or(value)
}
