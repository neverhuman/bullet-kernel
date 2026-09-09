//! Durable `run_coding` command payload and admission plan.
//!
//! `run_demo` stays a distinct kind. This kind carries the account, model,
//! revision, launch nonce, quota reservation, and allocated run that the
//! public command transaction must bind.

use crate::commands::CommandRequest;
use crate::nonce_ledger::NonceState;
use bullet_domain::{DomainError, RunnerId};
use serde::{Deserialize, Serialize};

/// Public command kind for a real-provider coding turn.
pub const RUN_CODING_KIND: &str = "run_coding";
/// Distinct demo kind that remains supported.
pub const RUN_DEMO_KIND: &str = "run_demo";
/// Upper bound on concurrent reserved coding quota units.
pub const MAX_CODING_QUOTA_UNITS: u64 = 1_000_000;

/// Provider names the production Runner may construct without spawning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodingProvider {
    /// Anthropic Claude Code.
    Claude,
    /// OpenAI Codex App Server.
    Codex,
    /// Cursor Agent.
    Cursor,
    /// Google Antigravity (`agy`).
    Antigravity,
}

impl CodingProvider {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Antigravity => "antigravity",
        }
    }
}

/// Exact JSON payload admitted for `run_coding`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCodingPayload {
    /// Caller account token.
    pub account_id: String,
    /// Constructed provider adapter.
    pub provider: CodingProvider,
    /// Provider-native model id. Never empty.
    pub model: String,
    /// Optional effort / reasoning knob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Expected `authority_epoch` at admission.
    pub expected_revision: u64,
    /// 64-hex launch nonce. First insert may issue-then-consume it in the same TX.
    pub launch_nonce: String,
    /// Caller-chosen `rsv_` reservation identity.
    pub quota_reservation: String,
    /// Positive units reserved from remaining capacity.
    pub quota_units: u64,
    /// Allocated runner subject.
    pub allocated_run: String,
}

impl RunCodingPayload {
    /// Parse and validate one compact JSON payload.
    ///
    /// # Errors
    ///
    /// `Encoding` when the payload is not the exact admitted shape.
    pub fn parse(payload: &str) -> Result<Self, DomainError> {
        let value: Self = serde_json::from_str(payload)
            .map_err(|error| DomainError::Encoding(format!("run_coding payload: {error}")))?;
        value.validate()?;
        Ok(value)
    }

    /// Validate field bounds after JSON decode.
    ///
    /// # Errors
    ///
    /// `Encoding` or `InvalidId` for malformed subjects.
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_token("account_id", &self.account_id, 64)?;
        validate_token("model", &self.model, 128)?;
        if let Some(effort) = &self.effort {
            validate_token("effort", effort, 32)?;
        }
        if self.expected_revision == 0 {
            return Err(DomainError::Encoding(
                "expected_revision must be a positive authority epoch".into(),
            ));
        }
        validate_hex_64("launch_nonce", &self.launch_nonce)?;
        validate_reservation_id(&self.quota_reservation)?;
        if self.quota_units == 0 || self.quota_units > MAX_CODING_QUOTA_UNITS {
            return Err(DomainError::Encoding(format!(
                "quota_units must be 1..={MAX_CODING_QUOTA_UNITS}"
            )));
        }
        RunnerId::parse(&self.allocated_run)?;
        Ok(())
    }
}

/// Observed durable facts used to decide first-insert vs exact replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodingAdmissionView {
    /// Current authority epoch.
    pub authority_epoch: u64,
    /// Sum of existing reservation amounts.
    pub used_quota: u64,
    /// Reservation already bound to this command, if any.
    pub existing_reservation: Option<(String, u64)>,
    /// Observed nonce digest and state, if the key exists.
    pub nonce: Option<(String, NonceState)>,
}

/// Durable rows the submit transaction must apply for a first insert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodingAdmissionPlan {
    /// Consume this nonce against the request digest.
    pub consume_nonce: String,
    /// Insert this reservation amount.
    pub reservation: (String, u64),
}

/// True when dispatch may claim the kind for a registered Runner.
#[must_use]
pub fn is_supported_dispatch_kind(kind: &str) -> bool {
    kind == RUN_DEMO_KIND || kind == RUN_CODING_KIND
}

/// Validate a `run_coding` request and plan first-insert rows.
///
/// Replay (`existed`) requires the reservation and consumed nonce to already
/// match. First insert refuses stale revision, exhausted quota, missing or
/// consumed nonce, and conflicting reservation identity.
///
/// # Errors
///
/// Domain refusal. Callers must roll back the whole command transaction.
pub fn plan_run_coding_admission(
    request: &CommandRequest,
    existed: bool,
    view: &CodingAdmissionView,
) -> Result<Option<CodingAdmissionPlan>, DomainError> {
    if request.kind != RUN_CODING_KIND {
        return Ok(None);
    }
    let payload = RunCodingPayload::parse(&request.payload)?;
    if payload.expected_revision != view.authority_epoch {
        return Err(DomainError::StaleAuthority(format!(
            "run_coding expected revision {} but authority epoch is {}",
            payload.expected_revision, view.authority_epoch
        )));
    }
    let digest = request.digest().to_hex();
    if existed {
        match &view.existing_reservation {
            Some((id, amount))
                if id == &payload.quota_reservation && *amount == payload.quota_units => {}
            _ => {
                return Err(DomainError::Encoding(
                    "run_coding replay is missing its exact quota reservation".into(),
                ));
            }
        }
        match &view.nonce {
            Some((stored, NonceState::Consumed)) if stored == &digest => {}
            _ => {
                return Err(DomainError::Encoding(
                    "run_coding replay is missing its consumed launch nonce".into(),
                ));
            }
        }
        return Ok(None);
    }
    if view.existing_reservation.is_some() {
        return Err(DomainError::Conflict(
            "quota reservation is already bound to another subject".into(),
        ));
    }
    let remaining = MAX_CODING_QUOTA_UNITS.saturating_sub(view.used_quota);
    if payload.quota_units > remaining {
        return Err(DomainError::Encoding(format!(
            "coding quota exhausted: requested {} remaining {remaining}",
            payload.quota_units
        )));
    }
    match &view.nonce {
        Some((stored, NonceState::Issued)) if stored == &digest => {}
        Some((_, NonceState::Consumed)) => {
            return Err(DomainError::Encoding(
                "run_coding launch nonce is already consumed".into(),
            ));
        }
        Some((_, _)) => {
            return Err(DomainError::Encoding(
                "run_coding launch nonce does not match this request digest".into(),
            ));
        }
        None => {
            return Err(DomainError::Encoding(
                "run_coding launch nonce has not been issued".into(),
            ));
        }
    }
    Ok(Some(CodingAdmissionPlan {
        consume_nonce: payload.launch_nonce,
        reservation: (payload.quota_reservation, payload.quota_units),
    }))
}

fn validate_token(field: &str, value: &str, maximum: usize) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(DomainError::Encoding(format!(
            "{field} must contain 1..={maximum} non-control bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-./".contains(&byte))
    {
        return Err(DomainError::Encoding(format!(
            "{field} must be a lowercase ASCII token"
        )));
    }
    Ok(())
}

fn validate_hex_64(field: &str, value: &str) -> Result<(), DomainError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(DomainError::Encoding(format!(
        "{field} must contain 64 lowercase hexadecimal characters"
    )))
}

fn validate_reservation_id(value: &str) -> Result<(), DomainError> {
    let Some(body) = value.strip_prefix("rsv_") else {
        return Err(DomainError::InvalidId(value.to_string()));
    };
    validate_hex_64("quota_reservation", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "account_id": "acct-main",
            "provider": "claude",
            "model": "claude-opus-4-6",
            "expected_revision": 1,
            "launch_nonce": "ab".repeat(32),
            "quota_reservation": format!("rsv_{}", "cd".repeat(32)),
            "quota_units": 3,
            "allocated_run": RunnerId::from_seed("coding-run").to_string(),
        })
    }

    fn request() -> CommandRequest {
        CommandRequest::new("coding-key", RUN_CODING_KIND, &payload()).expect("request")
    }

    fn issued_view() -> CodingAdmissionView {
        CodingAdmissionView {
            authority_epoch: 1,
            used_quota: 0,
            existing_reservation: None,
            nonce: Some((request().digest().to_hex(), NonceState::Issued)),
        }
    }

    #[test]
    fn first_insert_plans_nonce_and_reservation() {
        let request = request();
        let plan = plan_run_coding_admission(&request, false, &issued_view())
            .expect("admit")
            .expect("first insert");
        assert_eq!(plan.consume_nonce, "ab".repeat(32));
        assert_eq!(plan.reservation.1, 3);
    }

    #[test]
    fn stale_revision_and_exhausted_quota_leave_no_plan() {
        let request = request();
        let mut stale = issued_view();
        stale.authority_epoch = 2;
        assert!(matches!(
            plan_run_coding_admission(&request, false, &stale),
            Err(DomainError::StaleAuthority(_))
        ));
        let mut exhausted = issued_view();
        exhausted.used_quota = MAX_CODING_QUOTA_UNITS;
        assert!(plan_run_coding_admission(&request, false, &exhausted).is_err());
    }

    #[test]
    fn exact_replay_requires_consumed_nonce_and_reservation() {
        let request = request();
        let mut view = issued_view();
        view.existing_reservation = Some((format!("rsv_{}", "cd".repeat(32)), 3));
        view.nonce = Some((request.digest().to_hex(), NonceState::Consumed));
        assert_eq!(
            plan_run_coding_admission(&request, true, &view).expect("replay"),
            None
        );
    }

    #[test]
    fn demo_kind_is_not_planned() {
        let request = CommandRequest::new("demo", RUN_DEMO_KIND, &serde_json::json!({})).unwrap();
        assert_eq!(
            plan_run_coding_admission(&request, false, &issued_view()).unwrap(),
            None
        );
        assert!(is_supported_dispatch_kind(RUN_DEMO_KIND));
        assert!(is_supported_dispatch_kind(RUN_CODING_KIND));
        assert!(!is_supported_dispatch_kind("not_admitted"));
    }
}
