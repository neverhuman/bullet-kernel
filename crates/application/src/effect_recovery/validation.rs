//! Closed validation for the restart-recovery records and commands.

use super::*;
use bullet_domain::{AuthorityToken, CandidateId};
use bullet_harness_core::launch_grant::MAX_SAFE_INTEGER;
use chrono::{DateTime, FixedOffset};

impl EffectRecoveryAuthority {
    /// Project an exact current token and current database epochs.
    pub fn from_token(
        token: &AuthorityToken,
        authority_epoch: u64,
        freeze_generation: u64,
        restore_epoch: u64,
    ) -> Result<Self, EffectRecoveryError> {
        let authority = Self {
            schema_version: EFFECT_RECOVERY_AUTHORITY_SCHEMA.into(),
            successor_authority_digest: token
                .digest()
                .map_err(|error| EffectRecoveryError::Encoding(error.to_string()))?,
            runner_id: token.runner_id.clone(),
            runner_epoch: token.runner_epoch,
            attempt_id: token.attempt_id.clone(),
            attempt_fence: token.attempt_fence,
            variant_id: token.variant_id.clone(),
            workspace_id: token.workspace_id.clone(),
            workspace_nonce: token.workspace_nonce,
            authority_epoch,
            freeze_generation,
            restore_epoch,
        };
        authority.validate()?;
        Ok(authority)
    }

    /// Validate shape and bounded epoch values.
    pub fn validate(&self) -> Result<(), EffectRecoveryError> {
        if self.schema_version != EFFECT_RECOVERY_AUTHORITY_SCHEMA
            || digest_is_zero(&self.successor_authority_digest)
            || self.workspace_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(EffectRecoveryError::InvalidAuthority(
                "recovery authority subject is not admitted".into(),
            ));
        }
        positive_safe("runner epoch", self.runner_epoch)?;
        positive_safe("attempt fence", self.attempt_fence)?;
        positive_safe("authority epoch", self.authority_epoch)?;
        safe("freeze generation", self.freeze_generation)?;
        safe("restore epoch", self.restore_epoch)
    }

    /// Rebind this projection to the complete token bytes.
    pub fn validate_token(&self, token: &AuthorityToken) -> Result<(), EffectRecoveryError> {
        let digest = token
            .digest()
            .map_err(|error| EffectRecoveryError::Encoding(error.to_string()))?;
        if digest != self.successor_authority_digest
            || token.runner_id != self.runner_id
            || token.runner_epoch != self.runner_epoch
            || token.attempt_id != self.attempt_id
            || token.attempt_fence != self.attempt_fence
            || token.variant_id != self.variant_id
            || token.workspace_id != self.workspace_id
            || token.workspace_nonce != self.workspace_nonce
        {
            return Err(EffectRecoveryError::StaleAuthority(
                "successor token differs from its recovery projection".into(),
            ));
        }
        Ok(())
    }

    /// Digest of the token projection and all current database epochs.
    pub fn fingerprint(&self) -> Result<Digest, EffectRecoveryError> {
        self.validate()?;
        Digest::of_json(self).map_err(|error| EffectRecoveryError::Encoding(error.to_string()))
    }
}

impl EffectRecoveryClaim {
    /// Validate every self-contained binding and hard scope restriction.
    pub fn validate(&self) -> Result<(), EffectRecoveryError> {
        if self.schema_version != EFFECT_RECOVERY_CLAIM_SCHEMA {
            return Err(invalid_claim("recovery claim schema is not admitted"));
        }
        validate_claim_id(&self.claim_id)?;
        validate_recovery_scope(&self.intent)?;
        let stable = self
            .intent
            .stable_payload_digest()
            .map_err(|error| EffectRecoveryError::Encoding(error.to_string()))?;
        if stable != self.intent_payload_digest
            || self.intent.payload_hash != stable.to_hex()
            || self.original_attempt_id != self.intent.attempt_id
            || self.original_fence != self.intent.fence
        {
            return Err(EffectRecoveryError::SubjectMismatch(
                "claim differs from its immutable intent".into(),
            ));
        }
        let authority = self.authority_projection();
        authority.validate()?;
        if authority.fingerprint()? != self.successor_authority_fingerprint {
            return Err(EffectRecoveryError::FingerprintMismatch);
        }
        if self.recovery_attempt_id == self.original_attempt_id
            || self.recovery_attempt_fence <= self.original_fence
        {
            return Err(invalid_claim("recovery authority is not a successor"));
        }
        positive_safe("claim generation", self.claim_generation)?;
        positive_safe("outbox sequence", self.outbox_sequence)?;
        if self.disposition == EffectRecoveryDisposition::Unresolved {
            return Err(invalid_claim(
                "an unclaimed disposition cannot carry a claim identity",
            ));
        }
        if !self.disposition_state_is_valid() {
            return Err(invalid_claim(
                "recovery disposition contradicts intent state or invalidation lineage",
            ));
        }
        if utc_time("updated_at", &self.updated_at)? < utc_time("claimed_at", &self.claimed_at)? {
            return Err(invalid_claim("updated_at precedes claimed_at"));
        }
        Ok(())
    }

    /// Require an exact active-claim readback by the same successor owner.
    pub fn validate_readback(
        &self,
        intent_id: &EffectId,
        authority: &EffectRecoveryAuthority,
    ) -> Result<(), EffectRecoveryError> {
        self.validate()?;
        if self.intent.id != *intent_id {
            return Err(EffectRecoveryError::SubjectMismatch(
                "readback names another effect intent".into(),
            ));
        }
        if !self.disposition.is_active() {
            return Err(EffectRecoveryError::UnknownClaim);
        }
        self.validate_owner(authority)
    }

    /// Require a first generation or the exact successor to a terminal claim.
    pub fn validate_generation_after(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), EffectRecoveryError> {
        self.validate()?;
        if let Some(prior) = previous {
            prior.validate()?;
        }
        match previous {
            None if self.claim_generation == 1
                && matches!(
                    (self.disposition, self.intent.unknown_retries),
                    (EffectRecoveryDisposition::Claimed, 0)
                        | (EffectRecoveryDisposition::ReadbackUnknown, 1)
                ) =>
            {
                Ok(())
            }
            None => Err(invalid_claim("first claim generation must be one")),
            Some(prior)
                if prior.disposition == EffectRecoveryDisposition::Invalidated
                    && prior.invalidated_from == Some(self.disposition)
                    && prior.intent.id == self.intent.id
                    && prior.claim_id != self.claim_id
                    && prior.claim_generation.checked_add(1) == Some(self.claim_generation) =>
            {
                Ok(())
            }
            Some(_) => Err(EffectRecoveryError::ClaimConflict(
                "claim generation is not the next terminal successor".into(),
            )),
        }
    }

    fn validate_owner(
        &self,
        authority: &EffectRecoveryAuthority,
    ) -> Result<(), EffectRecoveryError> {
        authority.validate()?;
        if self.recovery_runner_id != authority.runner_id
            || self.recovery_runner_epoch != authority.runner_epoch
            || self.recovery_attempt_id != authority.attempt_id
            || self.recovery_attempt_fence != authority.attempt_fence
            || self.recovery_variant_id != authority.variant_id
            || self.recovery_workspace_id != authority.workspace_id
            || self.recovery_workspace_nonce != authority.workspace_nonce
        {
            return Err(EffectRecoveryError::ClaimConflict(
                "active recovery claim belongs to another incarnation".into(),
            ));
        }
        if self.successor_authority_digest != authority.successor_authority_digest
            || self.authority_epoch != authority.authority_epoch
            || self.freeze_generation != authority.freeze_generation
            || self.restore_epoch != authority.restore_epoch
        {
            return Err(EffectRecoveryError::StaleAuthority(
                "recovery authority or database epoch moved".into(),
            ));
        }
        if self.successor_authority_fingerprint != authority.fingerprint()? {
            return Err(EffectRecoveryError::FingerprintMismatch);
        }
        Ok(())
    }

    fn authority_projection(&self) -> EffectRecoveryAuthority {
        EffectRecoveryAuthority {
            schema_version: EFFECT_RECOVERY_AUTHORITY_SCHEMA.into(),
            successor_authority_digest: self.successor_authority_digest,
            runner_id: self.recovery_runner_id.clone(),
            runner_epoch: self.recovery_runner_epoch,
            attempt_id: self.recovery_attempt_id.clone(),
            attempt_fence: self.recovery_attempt_fence,
            variant_id: self.recovery_variant_id.clone(),
            workspace_id: self.recovery_workspace_id.clone(),
            workspace_nonce: self.recovery_workspace_nonce,
            authority_epoch: self.authority_epoch,
            freeze_generation: self.freeze_generation,
            restore_epoch: self.restore_epoch,
        }
    }
}

impl EffectRecoveryObservation {
    /// Closed verification method for `LocalBareForge::read_ref`.
    pub const METHOD: &'static str = "local-bare-read-ref-v1";

    /// Validate this observation against one exact intent.
    pub fn validate_for(&self, intent: &EffectIntentRecord) -> Result<(), EffectRecoveryError> {
        validate_recovery_scope(intent)?;
        if self.provider != LOCAL_BARE_RECOVERY_PROVIDER
            || self.remote_identity != intent.target_identity
            || self.verification_method != Self::METHOD
        {
            return Err(invalid_observation(
                "readback subject or method differs from the intent",
            ));
        }
        if let Some(oid) = &self.observed_state_hash {
            validate_oid("observed OID", oid)?;
        }
        let coherent = match self.verdict {
            ReceiptVerdict::Match => {
                self.observed_state_hash.as_deref() == Some(intent.desired_state_hash.as_str())
            }
            ReceiptVerdict::Absent => self.observed_state_hash.is_none(),
            ReceiptVerdict::Mismatch => self
                .observed_state_hash
                .as_deref()
                .is_some_and(|oid| oid != intent.desired_state_hash),
        };
        if !coherent {
            return Err(invalid_observation(
                "readback value contradicts its verdict",
            ));
        }
        Ok(())
    }

    /// Deterministic identity from immutable intent and canonical observation.
    pub fn receipt_id(
        &self,
        intent: &EffectIntentRecord,
    ) -> Result<EffectReceiptId, EffectRecoveryError> {
        self.validate_for(intent)?;
        recovery_receipt_id(
            intent,
            &self.remote_identity,
            self.observed_state_hash.as_deref(),
            &self.verification_method,
            self.verdict,
        )
        .map_err(|error| EffectRecoveryError::Encoding(error.to_string()))
    }
}

impl EffectRecoveryTransition {
    /// Construct and validate one transition without accepting caller time.
    pub fn new(
        claim: &EffectRecoveryClaim,
        authority: &EffectRecoveryAuthority,
        to: EffectRecoveryDisposition,
        observation: Option<EffectRecoveryObservation>,
        containment_reason: Option<EffectRecoveryContainmentReason>,
    ) -> Result<Self, EffectRecoveryError> {
        let receipt_id = observation
            .as_ref()
            .map(|value| value.receipt_id(&claim.intent))
            .transpose()?;
        let request = Self {
            schema_version: EFFECT_RECOVERY_TRANSITION_SCHEMA.into(),
            claim_id: claim.claim_id.clone(),
            claim_generation: claim.claim_generation,
            authority_fingerprint: authority.fingerprint()?,
            from: claim.disposition,
            to,
            observation,
            containment_reason,
            receipt_id,
        };
        request.validate_for(claim, authority)?;
        Ok(request)
    }

    /// Validate owner, edge, budget, verdict, and receipt identity.
    pub fn validate_for(
        &self,
        claim: &EffectRecoveryClaim,
        authority: &EffectRecoveryAuthority,
    ) -> Result<(), EffectRecoveryError> {
        if self.schema_version != EFFECT_RECOVERY_TRANSITION_SCHEMA
            || self.claim_id != claim.claim_id
            || self.claim_generation != claim.claim_generation
            || self.authority_fingerprint != claim.successor_authority_fingerprint
            || self.from != claim.disposition
        {
            return Err(EffectRecoveryError::SubjectMismatch(
                "transition differs from its claim".into(),
            ));
        }
        claim.validate_readback(&claim.intent.id, authority)?;
        self.from.transition(self.to)?;
        let verdict = self.observation.as_ref().map(|value| value.verdict);
        if let Some(observation) = &self.observation {
            observation.validate_for(&claim.intent)?;
        }
        match self.to {
            EffectRecoveryDisposition::RetryReserved => {
                if claim.intent.unknown_retries >= MAX_CREATE_RECOVERY_RETRIES {
                    return Err(EffectRecoveryError::RetryBudgetExhausted);
                }
                if verdict != Some(ReceiptVerdict::Absent) {
                    return Err(invalid_observation("retry requires authoritative absence"));
                }
            }
            EffectRecoveryDisposition::ReadbackUnknown | EffectRecoveryDisposition::Invalidated => {
                if self.observation.is_some() || self.containment_reason.is_some() {
                    return Err(invalid_observation(
                        "unknown or invalidated recovery cannot carry a verdict",
                    ));
                }
            }
            EffectRecoveryDisposition::Adopted if verdict != Some(ReceiptVerdict::Match) => {
                return Err(invalid_observation(
                    "adoption requires an exact desired-state match",
                ));
            }
            EffectRecoveryDisposition::Orphaned if verdict != Some(ReceiptVerdict::Mismatch) => {
                return Err(invalid_observation(
                    "orphaning requires a conflicting remote OID",
                ));
            }
            EffectRecoveryDisposition::Quarantined => {
                let spent_absence = self.from == EffectRecoveryDisposition::ReadbackUnknown
                    && claim.intent.unknown_retries == MAX_CREATE_RECOVERY_RETRIES
                    && verdict == Some(ReceiptVerdict::Absent)
                    && self.containment_reason
                        == Some(EffectRecoveryContainmentReason::RetrySpentAfterAbsence);
                let unavailable = self.observation.is_none()
                    && self.from == EffectRecoveryDisposition::ReadbackUnknown
                    && self.containment_reason
                        == Some(EffectRecoveryContainmentReason::ReadbackUnavailable);
                if !spent_absence && !unavailable {
                    return Err(invalid_observation(
                        "quarantine lacks an admitted containment predicate",
                    ));
                }
            }
            EffectRecoveryDisposition::Adopted | EffectRecoveryDisposition::Orphaned => {
                if self.containment_reason.is_some() {
                    return Err(invalid_observation(
                        "terminal verdict cannot carry a containment reason",
                    ));
                }
            }
            EffectRecoveryDisposition::Unresolved | EffectRecoveryDisposition::Claimed => {
                return Err(EffectRecoveryError::InvalidTransition {
                    from: self.from.as_str().into(),
                    to: self.to.as_str().into(),
                });
            }
        }
        let expected_receipt = self
            .observation
            .as_ref()
            .map(|value| value.receipt_id(&claim.intent))
            .transpose()?;
        if self.receipt_id != expected_receipt {
            return Err(EffectRecoveryError::SubjectMismatch(
                "transition receipt identity is not canonical".into(),
            ));
        }
        Ok(())
    }
}

fn validate_recovery_scope(intent: &EffectIntentRecord) -> Result<(), EffectRecoveryError> {
    if intent.provider != LOCAL_BARE_RECOVERY_PROVIDER
        || intent.expected_old_oid != ZERO_OID
        || intent.provider_idempotency_key.is_some()
    {
        return Err(EffectRecoveryError::UnsupportedIntent(
            "only local-bare create-only intents are recoverable".into(),
        ));
    }
    validate_candidate_ref(&intent.target_identity)?;
    validate_oid("desired OID", &intent.desired_state_hash)?;
    if intent.desired_state_hash == ZERO_OID || intent.fence == 0 {
        return Err(EffectRecoveryError::UnsupportedIntent(
            "intent desired OID and original fence must be nonzero".into(),
        ));
    }
    if intent.unknown_retries > MAX_CREATE_RECOVERY_RETRIES {
        return Err(EffectRecoveryError::RetryBudgetExhausted);
    }
    Ok(())
}

fn validate_candidate_ref(value: &str) -> Result<(), EffectRecoveryError> {
    let suffix = value.strip_prefix(CANDIDATE_REF_PREFIX).unwrap_or_default();
    if CandidateId::parse(suffix).is_err() {
        return Err(EffectRecoveryError::UnsupportedIntent(
            "target is outside the Candidate-ref namespace".into(),
        ));
    }
    Ok(())
}

fn validate_oid(name: &str, value: &str) -> Result<(), EffectRecoveryError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_observation(&format!(
            "{name} must be 40 lowercase hex characters"
        )));
    }
    Ok(())
}

fn validate_claim_id(value: &str) -> Result<(), EffectRecoveryError> {
    let body = value.strip_prefix("ecl_").unwrap_or_default();
    if body.len() != 64
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_claim(
            "claim id must be ecl_ plus 64 lowercase hex characters",
        ));
    }
    Ok(())
}

fn positive_safe(name: &str, value: u64) -> Result<(), EffectRecoveryError> {
    if value == 0 {
        return Err(invalid_claim(&format!("{name} must be positive")));
    }
    safe(name, value)
}

fn safe(name: &str, value: u64) -> Result<(), EffectRecoveryError> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid_claim(&format!("{name} exceeds MAX_SAFE_INTEGER")));
    }
    Ok(())
}

fn utc_time(name: &str, value: &str) -> Result<DateTime<FixedOffset>, EffectRecoveryError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|error| invalid_claim(&format!("{name}: {error}")))?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(invalid_claim(&format!("{name} must use UTC")));
    }
    Ok(parsed)
}

fn invalid_claim(reason: &str) -> EffectRecoveryError {
    EffectRecoveryError::InvalidClaim(reason.into())
}

fn invalid_observation(reason: &str) -> EffectRecoveryError {
    EffectRecoveryError::InvalidObservation(reason.into())
}

fn digest_is_zero(value: &Digest) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}
