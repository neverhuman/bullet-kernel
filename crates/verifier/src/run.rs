//! Clean-room pipeline: fresh hostile-env clone, exact-subject checks, then
//! the bounded gate. Subject mismatches are `INVALIDATED` evidence, never
//! errors and never `PASS`.

use crate::error::{io_err, VerifierError};
use crate::evidence::{CandidateSubject, VerifierEvidence};
use crate::gate::{run_gate, GateRun};
use crate::request::VerifierRequest;
use crate::safe_git::HostileGit;
use bullet_domain::{gate_definition, EvidenceTier, GateDefinition, GateOutcome};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Reason code when the source repository could not be cloned.
pub const REASON_CLONE_FAILED: &str = "CLONE_FAILED";
/// Reason code when the head SHA is not reachable in the clone.
pub const REASON_HEAD_UNREACHABLE: &str = "HEAD_UNREACHABLE";
/// Reason code when the checked-out tree differs from the claimed tree.
pub const REASON_TREE_MISMATCH: &str = "TREE_MISMATCH";
/// Reason code when the base SHA is not an ancestor of the head.
pub const REASON_BASE_NOT_ANCESTOR: &str = "BASE_NOT_ANCESTOR";
/// Reason code when a required git read failed after the clone.
pub const REASON_GIT_READ_FAILED: &str = "GIT_READ_FAILED";

enum Reconstruction {
    Ready(PathBuf),
    Verdict {
        outcome: GateOutcome,
        reason: &'static str,
        detail: String,
    },
}

fn capture_environment(git: &HostileGit) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    if let Ok(version) = git.run(None, false, &["--version"]) {
        env.insert("git".into(), version);
    }
    if let Ok(out) = std::process::Command::new("rustc").arg("-V").output() {
        if out.status.success() {
            env.insert(
                "rustc".into(),
                String::from_utf8_lossy(&out.stdout).trim().to_string(),
            );
        }
    }
    env
}

fn reconstruct(
    git: &HostileGit,
    scratch: &Path,
    request: &VerifierRequest,
) -> Result<Reconstruction, VerifierError> {
    let clone_dir = scratch.join("clone");
    let clone_str = clone_dir.display().to_string();
    if let Err(err) = git.run(
        None,
        true,
        &[
            "clone",
            "--no-checkout",
            "--no-hardlinks",
            &request.workspace_repo_path,
            &clone_str,
        ],
    ) {
        return Ok(Reconstruction::Verdict {
            outcome: GateOutcome::InfraError,
            reason: REASON_CLONE_FAILED,
            detail: err.to_string(),
        });
    }
    if let Err(err) = git.run(
        Some(&clone_dir),
        false,
        &["checkout", "--detach", "--force", &request.head_sha],
    ) {
        return Ok(Reconstruction::Verdict {
            outcome: GateOutcome::Invalidated,
            reason: REASON_HEAD_UNREACHABLE,
            detail: err.to_string(),
        });
    }
    let observed_tree = match git.run(Some(&clone_dir), false, &["rev-parse", "HEAD^{tree}"]) {
        Ok(tree) => tree,
        Err(err) => {
            return Ok(Reconstruction::Verdict {
                outcome: GateOutcome::InfraError,
                reason: REASON_GIT_READ_FAILED,
                detail: err.to_string(),
            })
        }
    };
    if observed_tree != request.tree_sha {
        return Ok(Reconstruction::Verdict {
            outcome: GateOutcome::Invalidated,
            reason: REASON_TREE_MISMATCH,
            detail: format!("observed tree {observed_tree}"),
        });
    }
    let ancestor = git.probe(
        Some(&clone_dir),
        &[
            "merge-base",
            "--is-ancestor",
            &request.base_sha,
            &request.head_sha,
        ],
    )?;
    if !ancestor {
        return Ok(Reconstruction::Verdict {
            outcome: GateOutcome::Invalidated,
            reason: REASON_BASE_NOT_ANCESTOR,
            detail: format!(
                "{} is not an ancestor of {}",
                request.base_sha, request.head_sha
            ),
        });
    }
    Ok(Reconstruction::Ready(clone_dir))
}

fn record(
    request: &VerifierRequest,
    definition: GateDefinition,
    gate: GateRun,
    duration_ms: u64,
    environment: BTreeMap<String, String>,
) -> VerifierEvidence {
    VerifierEvidence {
        tier: EvidenceTier::E2,
        gate_id: request.gate_id.clone(),
        outcome: gate.outcome,
        reason: gate.reason,
        detail: gate.detail,
        argv: definition.argv(),
        timeout_secs: definition.timeout_secs(),
        exit_code: gate.exit_code,
        duration_ms,
        subject: CandidateSubject {
            base_sha: request.base_sha.clone(),
            head_sha: request.head_sha.clone(),
            tree_sha: request.tree_sha.clone(),
        },
        environment,
        produced_by: "bullet-verifier".into(),
        author_attempt_id: request.author_attempt_id.clone(),
    }
}

/// Execute one clean-room verification.
///
/// `author_overlap` is true when the caller runs under the writer identity
/// (the kernel passes `BULLET_VERIFIER_AUTHOR_OVERLAP=1`); the run is then
/// refused with `VERIFIER_IS_AUTHOR` before any work.
///
/// # Errors
///
/// Returns `VERIFIER_IS_AUTHOR`, `BAD_INPUT`, or an infrastructure failure
/// that prevented producing any evidence record at all.
pub async fn execute(
    request: &VerifierRequest,
    author_overlap: bool,
) -> Result<VerifierEvidence, VerifierError> {
    if author_overlap {
        return Err(VerifierError::AuthorOverlap(format!(
            "caller shares the writer identity of {}",
            request.author_attempt_id
        )));
    }
    request.validate()?;
    let definition = gate_definition(&request.gate_id).ok_or_else(|| {
        VerifierError::BadInput(format!("unknown gate_id {:?}", request.gate_id.as_str()))
    })?;
    let started = Instant::now();
    let scratch = tempfile::tempdir().map_err(|err| io_err("create scratch dir", &err))?;
    let git = HostileGit::new(&scratch.path().join("runtime"))?;
    let environment = capture_environment(&git);
    let gate = match reconstruct(&git, scratch.path(), request)? {
        Reconstruction::Ready(clone_dir) => run_gate(&clone_dir, definition).await,
        Reconstruction::Verdict {
            outcome,
            reason,
            detail,
        } => GateRun {
            outcome,
            reason: Some(reason.into()),
            detail: Some(detail),
            exit_code: None,
        },
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(record(request, definition, gate, duration_ms, environment))
}
