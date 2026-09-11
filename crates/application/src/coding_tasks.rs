//! Immutable coding intent, distinct from permission to launch an invocation.

use crate::operator_commands::OperatorCommandError;
use crate::{CodingProvider, CommandRecord, CommandRequest, RunCodingPayload};
use bullet_domain::{CommandId, Digest, DomainError};
use serde::{Deserialize, Serialize};

mod refusal;
#[cfg(test)]
mod tests;
mod validation;
pub use refusal::CodingTaskRefusal;

/// Closed public task-submission version; legacy records retain their own decoder.
pub const RUN_CODING_TASK_SCHEMA: &str = "bullet.run-coding.v2";
/// Maximum integer carried through browser JSON without precision loss.
pub const MAX_CODING_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Requested limits shared by every invocation of one immutable task revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingTaskBudget {
    /// Maximum admitted invocation requests, including queued requests.
    pub max_invocations: u32,
    /// Maximum aggregate cost in millionths of one US dollar.
    pub max_cost_microusd: u64,
}

/// Requested work. Repository and gate identities are selectors, not authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingTaskContract {
    /// Short operator-facing title.
    pub title: String,
    /// Complete requested objective.
    pub objective: String,
    /// Repository to resolve through server-owned configuration.
    pub repository_id: String,
    /// Exact Git commit, never a moving branch name.
    pub base_commit: String,
    /// Normalized repository-relative paths requiring scope admission.
    pub scope_paths: Vec<String>,
    /// Explicit conditions the independent verifier must evaluate.
    pub acceptance_criteria: Vec<String>,
    /// Immutable gate selectors requiring catalog admission.
    pub gate_ids: Vec<String>,
    /// Previously accepted task revision identities owned by this operator.
    pub dependencies: Vec<String>,
    /// Limits over this revision's invocation requests.
    pub budget: CodingTaskBudget,
    /// Absolute server-evaluated deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
}

/// Requested runtime selection. No credential or executable path is accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingRuntimeSelection {
    /// Account reference to resolve through server-owned configuration.
    pub account_id: String,
    /// Native provider protocol family.
    pub provider: CodingProvider,
    /// Exact requested model.
    pub model: String,
    /// Exact optional effort setting; omission is not a server-chosen substitute.
    #[serde(deserialize_with = "required_effort")]
    pub effort: Option<String>,
}

/// Closed task-shaped payload for the existing `run_coding` command kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCodingTaskPayload {
    /// Exact supported schema discriminator.
    pub schema_version: String,
    /// Immutable accepted task contract.
    pub task: CodingTaskContract,
    /// Requested runtime for this invocation.
    pub selection: CodingRuntimeSelection,
}

impl RunCodingTaskPayload {
    /// Decode the closed shape and enforce byte, scalar and subject limits.
    pub fn parse(payload: &str) -> Result<Self, DomainError> {
        let value: Self = serde_json::from_str(payload).map_err(encoding)?;
        value.validate()?;
        Ok(value)
    }

    /// Validate intent without granting repository, runtime or execution authority.
    pub fn validate(&self) -> Result<(), DomainError> {
        validation::payload(self)
    }
}

/// Public syntax and historical syntax stay distinguishable after decoding.
#[derive(Clone, Debug)]
pub enum CodingSubmission {
    /// Historical authority-bearing request; never a fresh public task admission.
    Legacy(Box<RunCodingPayload>),
    /// Requested task requiring durable acceptance and separate runnable admission.
    Task(Box<RunCodingTaskPayload>),
}

impl CodingSubmission {
    /// Decode original bytes; typed deserialization still refuses duplicate fields.
    pub fn parse(payload: &str) -> Result<Self, DomainError> {
        let shape: serde_json::Value = serde_json::from_str(payload).map_err(encoding)?;
        if shape.get("schema_version").is_some() {
            Ok(Self::Task(Box::new(RunCodingTaskPayload::parse(payload)?)))
        } else {
            Ok(Self::Legacy(Box::new(RunCodingPayload::parse(payload)?)))
        }
    }
}

impl CodingTaskContract {
    /// Fixed-field canonical task bytes, independent of submitted object-key order.
    pub fn canonical_json(&self) -> Result<String, DomainError> {
        validation::task(self)?;
        serde_json::to_string(self).map_err(encoding)
    }

    /// Server-derived immutable revision, isolated to the authenticated operator.
    pub fn revision_id(&self, operator: &str) -> Result<String, DomainError> {
        validate_coding_subject(operator, "opr_")?;
        let body = self.canonical_json()?;
        let seed = format!("bullet.coding-task-revision.v1\0{operator}\0{body}");
        Ok(format!("ctr_{}", Digest::of(seed.as_bytes()).to_hex()))
    }
}

/// Server-derived tracking identity; it is deliberately not a Runner identity.
#[must_use]
pub fn coding_run_id(command: &CommandId) -> String {
    let seed = format!("bullet.coding-run.v1\0{command}");
    format!("crn_{}", Digest::of(seed.as_bytes()).to_hex())
}

/// Stable lease-acquisition identity for one validated v2 coding command.
///
/// The command ID and exact request digest survive worker restart. This derives
/// an operation key only; it creates no WorkPackage, lease or Candidate authority.
///
/// # Errors
/// Invalid/non-task requests and a collision with the submission key refuse.
pub fn coding_lease_key(request: &CommandRequest) -> Result<String, DomainError> {
    request.validate()?;
    if task_payload(request)?.is_none() {
        return Err(encoding("lease identity requires a v2 coding task"));
    }
    let subject = format!(
        "bullet.coding-lease-acquire.v1\0{}\0{}",
        request.id(),
        request.digest().to_hex()
    );
    let key = format!(
        "coding-lease-v1:{}",
        Digest::of(subject.as_bytes()).to_hex()
    );
    if key == request.idempotency_key {
        return Err(DomainError::Idempotency(
            "coding lease identity collides with submission".into(),
        ));
    }
    Ok(key)
}

/// Validate a complete coding/owner identity without interpreting it as authority.
pub fn validate_coding_subject(value: &str, prefix: &str) -> Result<(), DomainError> {
    if value.strip_prefix(prefix).is_some_and(|body| {
        body.len() == 64
            && body
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        Ok(())
    } else {
        Err(DomainError::InvalidId(format!(
            "expected a complete {prefix} subject"
        )))
    }
}

/// One current reason why requested work cannot obtain runnable admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingQueueBlocker {
    /// Stable machine reason, rendered as text by clients.
    pub code: String,
    /// Exact missing or conflicting subject when one is known.
    pub subject: Option<String>,
}

/// One owner-bound observation from a single durable read transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodingRunObservation {
    /// Original command and its current validated phase.
    pub command: CommandRecord,
    /// Server-selected tracking subject, not an execution grant.
    pub run_id: String,
    /// Immutable accepted task revision.
    pub task_revision_id: String,
    /// Exact accepted task contents.
    pub task: CodingTaskContract,
    /// Exact requested selection for this invocation.
    pub selection: CodingRuntimeSelection,
    /// Original server timestamp for this invocation request.
    pub accepted_at: String,
    /// Current blockers observed in the same transaction.
    pub blockers: Vec<CodingQueueBlocker>,
    /// Latest audit sequence covered by this observation.
    pub as_of_sequence: u64,
    /// Store observation timestamp.
    pub observed_at: String,
}

/// Narrow authenticated read port; acceptance remains in the command transaction.
pub trait CodingTaskStore {
    /// Read an owned task-shaped command. Historical/noncoding/foreign rows are absent.
    fn get_operator_coding(
        &self,
        operator: &str,
        command: &CommandId,
    ) -> Result<Option<CodingRunObservation>, OperatorCommandError>;
}

/// Recognize task intent only after the request's closed decoder has validated it.
pub fn task_payload(request: &CommandRequest) -> Result<Option<RunCodingTaskPayload>, DomainError> {
    if request.kind != crate::RUN_CODING_KIND {
        return Ok(None);
    }
    match CodingSubmission::parse(&request.payload)? {
        CodingSubmission::Legacy(_) => Ok(None),
        CodingSubmission::Task(payload) => Ok(Some(*payload)),
    }
}

fn encoding(error: impl std::fmt::Display) -> DomainError {
    DomainError::Encoding(format!("CODING_TASK_INVALID: {error}"))
}

fn required_effort<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(value)
}
