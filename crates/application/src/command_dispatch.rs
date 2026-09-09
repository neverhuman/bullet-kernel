//! Durable Runner dispatch claims for public commands.
//!
//! A claim is component authority only. It can settle a supported command to
//! `UNKNOWN`; it can never manufacture applied, verified, or release truth.

use crate::{CommandRecord, CommandRequest};
use bullet_domain::{CommandId, Digest, RunnerId};
use bullet_harness_core::launch_grant::{canonical_json, MAX_SAFE_INTEGER};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact wire discriminator for a durable dispatch claim.
pub const COMMAND_DISPATCH_CLAIM_SCHEMA: &str = "bullet.command-dispatch-claim.v1";
/// Exact wire discriminator for a component completion.
pub const COMPONENT_COMMAND_COMPLETION_SCHEMA: &str = "bullet.component-command-completion.v1";
/// Evidence class retained by this bounded bridge.
pub const COMPONENT_EVIDENCE_CLASS: &str = "COMPONENT_PROOF";
/// Signing trust retained by this bounded bridge.
pub const COMPONENT_SIGNING_TRUST: &str = "UNSIGNED_FIXTURE";

const COMPLETION_DIGEST_DOMAIN: &[u8] = b"bullet-kernel.component-command-completion.v1";

/// Durable disposition selected by the Kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommandDispatchDisposition {
    /// A registered Runner incarnation owns the claim.
    Claimed,
    /// Component execution completed without transaction-grade proof.
    Unknown,
    /// The Kernel refused the command before worker execution.
    Failed,
    /// Authority moved after the claim was issued.
    Invalidated,
}

impl CommandDispatchDisposition {
    /// Stable database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "CLAIMED",
            Self::Unknown => "UNKNOWN",
            Self::Failed => "FAILED",
            Self::Invalidated => "INVALIDATED",
        }
    }

    /// Parse one exact database spelling.
    pub fn parse(value: &str) -> Result<Self, CommandDispatchError> {
        match value {
            "CLAIMED" => Ok(Self::Claimed),
            "UNKNOWN" => Ok(Self::Unknown),
            "FAILED" => Ok(Self::Failed),
            "INVALIDATED" => Ok(Self::Invalidated),
            _ => Err(CommandDispatchError::InvalidClaim(format!(
                "unknown command dispatch disposition {value}"
            ))),
        }
    }
}

/// Exact durable claim returned only to its owning Runner incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDispatchClaim {
    /// Wire discriminator.
    pub schema_version: String,
    /// Full-width `dcl_` claim identity.
    pub claim_id: String,
    /// Exact public command.
    pub command_id: CommandId,
    /// Exact correlated outbox sequence.
    pub outbox_sequence: u64,
    /// Exact admitted request.
    pub request: CommandRequest,
    /// Exact request digest.
    pub request_digest: Digest,
    /// Owning registered Runner.
    pub runner_id: RunnerId,
    /// Owning Runner incarnation.
    pub runner_epoch: u64,
    /// Kernel authority epoch at claim time.
    pub authority_epoch: u64,
    /// Kernel freeze generation at claim time.
    pub freeze_generation: u64,
    /// External restore epoch at claim time.
    pub restore_epoch: u64,
    /// Kernel-selected disposition.
    pub disposition: CommandDispatchDisposition,
    /// Component completion or Kernel-refusal digest once terminal.
    pub completion_digest: Option<Digest>,
    /// First durable claim time.
    pub claimed_at: String,
    /// Last durable transition time.
    pub updated_at: String,
}

impl CommandDispatchClaim {
    /// Validate the complete claim and all exact subject bindings.
    pub fn validate(&self) -> Result<(), CommandDispatchError> {
        if self.schema_version != COMMAND_DISPATCH_CLAIM_SCHEMA {
            return Err(CommandDispatchError::InvalidClaim(
                "claim schema is not admitted".into(),
            ));
        }
        validate_claim_id(&self.claim_id)?;
        self.request
            .validate()
            .map_err(|error| CommandDispatchError::InvalidClaim(error.to_string()))?;
        if self.request.id() != self.command_id || self.request.digest() != self.request_digest {
            return Err(CommandDispatchError::SubjectMismatch(
                "claim request does not match its command subject".into(),
            ));
        }
        for (name, value) in [
            ("outbox sequence", self.outbox_sequence),
            ("runner epoch", self.runner_epoch),
            ("authority epoch", self.authority_epoch),
        ] {
            validate_positive_safe(name, value)?;
        }
        validate_safe("freeze generation", self.freeze_generation)?;
        validate_safe("restore epoch", self.restore_epoch)?;
        validate_time("claimed_at", &self.claimed_at)?;
        validate_time("updated_at", &self.updated_at)?;
        match (self.disposition, self.completion_digest) {
            (
                CommandDispatchDisposition::Claimed | CommandDispatchDisposition::Invalidated,
                None,
            )
            | (CommandDispatchDisposition::Unknown | CommandDispatchDisposition::Failed, Some(_)) =>
                {}
            _ => {
                return Err(CommandDispatchError::InvalidClaim(
                    "claim completion digest contradicts its disposition".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Component-only completion authored from one exact claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentCommandCompletionV1 {
    /// Wire discriminator.
    pub schema_version: String,
    /// Exact command subject.
    pub command_id: CommandId,
    /// Exact admitted request digest.
    pub request_digest: Digest,
    /// Retained component receipt digest.
    pub receipt_digest: Digest,
    /// Fixed component evidence classification.
    pub evidence_class: String,
    /// Fixed fixture-only signing classification.
    pub signing_trust: String,
    /// Hard false until the complete transaction exists.
    pub transaction_gate_eligible: bool,
    /// Hard false until independent custody exists.
    pub independent_evidence_eligible: bool,
}

impl ComponentCommandCompletionV1 {
    /// Bind a retained component receipt to one currently owned claim.
    pub fn new(
        claim: &CommandDispatchClaim,
        receipt_digest: Digest,
    ) -> Result<Self, CommandDispatchError> {
        claim.validate()?;
        if claim.disposition != CommandDispatchDisposition::Claimed {
            return Err(CommandDispatchError::InvalidCompletion(
                "only a claimed dispatch accepts component completion".into(),
            ));
        }
        Ok(Self {
            schema_version: COMPONENT_COMMAND_COMPLETION_SCHEMA.into(),
            command_id: claim.command_id.clone(),
            request_digest: claim.request_digest,
            receipt_digest,
            evidence_class: COMPONENT_EVIDENCE_CLASS.into(),
            signing_trust: COMPONENT_SIGNING_TRUST.into(),
            transaction_gate_eligible: false,
            independent_evidence_eligible: false,
        })
    }

    /// Validate fixed classifications and exact claim subjects.
    pub fn validate_for(&self, claim: &CommandDispatchClaim) -> Result<(), CommandDispatchError> {
        if self.command_id != claim.command_id || self.request_digest != claim.request_digest {
            return Err(CommandDispatchError::SubjectMismatch(
                "component completion is bound to another command".into(),
            ));
        }
        if self.schema_version != COMPONENT_COMMAND_COMPLETION_SCHEMA
            || self.evidence_class != COMPONENT_EVIDENCE_CLASS
            || self.signing_trust != COMPONENT_SIGNING_TRUST
            || self.transaction_gate_eligible
            || self.independent_evidence_eligible
        {
            return Err(CommandDispatchError::InvalidCompletion(
                "component completion classification is not admitted".into(),
            ));
        }
        Ok(())
    }

    /// Domain-separated canonical completion digest.
    pub fn digest(&self) -> Result<Digest, CommandDispatchError> {
        let canonical = canonical_json(self)
            .map_err(|error| CommandDispatchError::InvalidCompletion(error.to_string()))?;
        let mut framed = Vec::with_capacity(COMPLETION_DIGEST_DOMAIN.len() + canonical.len() + 16);
        frame(&mut framed, COMPLETION_DIGEST_DOMAIN);
        frame(&mut framed, &canonical);
        Ok(Digest::of(&framed))
    }

    /// Fixed epistemically-unknown command response. It is never green.
    pub fn unknown_response(
        &self,
        claim: &CommandDispatchClaim,
    ) -> Result<String, CommandDispatchError> {
        self.validate_for(claim)?;
        serde_json::to_string(&serde_json::json!({
            "code": "COMPONENT_PROOF_NOT_TRANSACTION_ELIGIBLE",
            "command_id": claim.command_id,
            "request_digest": claim.request_digest,
            "receipt_digest": self.receipt_digest,
            "evidence_class": self.evidence_class,
            "signing_trust": self.signing_trust,
            "transaction_gate_eligible": false,
            "independent_evidence_eligible": false,
            "detail": "A retained component receipt is not complete transaction evidence.",
            "repair": "Run the signed Candidate-to-observation transaction with independent identities.",
        }))
        .map_err(|error| CommandDispatchError::InvalidCompletion(error.to_string()))
    }
}

/// Persistence port for peer-authenticated command dispatch.
pub trait CommandDispatchStore {
    /// Claim the oldest dispatch, or replay this incarnation's open claim.
    fn claim_next_command_dispatch(
        &mut self,
        runner_id: &RunnerId,
        runner_epoch: u64,
        now: &str,
    ) -> Result<Option<CommandDispatchClaim>, CommandDispatchError>;

    /// Read back this exact Runner incarnation's open claim.
    fn readback_command_dispatch(
        &self,
        runner_id: &RunnerId,
        runner_epoch: u64,
    ) -> Result<Option<CommandDispatchClaim>, CommandDispatchError>;

    /// Load durable claim truth for one public command.
    fn command_dispatch_claim_for_command(
        &self,
        command_id: &CommandId,
    ) -> Result<Option<CommandDispatchClaim>, CommandDispatchError>;

    /// Atomically settle a component completion to `UNKNOWN`.
    fn settle_component_command_dispatch(
        &mut self,
        claim_id: &str,
        runner_id: &RunnerId,
        runner_epoch: u64,
        completion: &ComponentCommandCompletionV1,
        now: &str,
    ) -> Result<CommandRecord, CommandDispatchError>;
}

/// Typed dispatch boundary failure.
#[derive(Debug, Error)]
pub enum CommandDispatchError {
    /// Durable store failure.
    #[error("command dispatch store: {0}")]
    Store(String),
    /// Corrupt or unauthored claim.
    #[error("invalid command dispatch claim: {0}")]
    InvalidClaim(String),
    /// Painted or malformed component completion.
    #[error("invalid command completion: {0}")]
    InvalidCompletion(String),
    /// Claim/completion/request subject mismatch.
    #[error("command dispatch subject mismatch: {0}")]
    SubjectMismatch(String),
    /// Authority moved after claim issue.
    #[error("command dispatch authority is stale: {0}")]
    StaleAuthority(String),
    /// Exact claim is absent.
    #[error("unknown command dispatch claim")]
    UnknownClaim,
}

impl CommandDispatchError {
    /// Stable machine-readable refusal code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Store(_) => "STORE_FAILURE",
            Self::InvalidClaim(_) => "COMMAND_DISPATCH_CLAIM_INVALID",
            Self::InvalidCompletion(_) => "COMMAND_COMPLETION_INVALID",
            Self::SubjectMismatch(_) => "COMMAND_DISPATCH_SUBJECT_MISMATCH",
            Self::StaleAuthority(_) => "COMMAND_DISPATCH_AUTHORITY_STALE",
            Self::UnknownClaim => "COMMAND_DISPATCH_CLAIM_UNKNOWN",
        }
    }
}

fn validate_claim_id(value: &str) -> Result<(), CommandDispatchError> {
    let body = value.strip_prefix("dcl_").ok_or_else(|| {
        CommandDispatchError::InvalidClaim("claim id must use the dcl_ prefix".into())
    })?;
    if body.len() != 64
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CommandDispatchError::InvalidClaim(
            "claim id must contain 64 lowercase hex characters".into(),
        ));
    }
    Ok(())
}

fn validate_positive_safe(name: &str, value: u64) -> Result<(), CommandDispatchError> {
    if value == 0 {
        return Err(CommandDispatchError::InvalidClaim(format!(
            "{name} must be positive"
        )));
    }
    validate_safe(name, value)
}

fn validate_safe(name: &str, value: u64) -> Result<(), CommandDispatchError> {
    if value > MAX_SAFE_INTEGER {
        return Err(CommandDispatchError::InvalidClaim(format!(
            "{name} exceeds MAX_SAFE_INTEGER"
        )));
    }
    Ok(())
}

fn validate_time(name: &str, value: &str) -> Result<(), CommandDispatchError> {
    let parsed = DateTime::<FixedOffset>::parse_from_rfc3339(value)
        .map_err(|error| CommandDispatchError::InvalidClaim(format!("{name}: {error}")))?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(CommandDispatchError::InvalidClaim(format!(
            "{name} must use UTC"
        )));
    }
    Ok(())
}

fn frame(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    target.extend_from_slice(bytes);
}
