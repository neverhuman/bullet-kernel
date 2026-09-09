//! Local Kernel mutation-permit mint/check/settle for production gitd.
//!
//! Accepts only a Kernel-issued one-use permit plus an online lease/fence
//! read-back. Unsigned and fixture tokens are refused here.

use bullet_application::ActiveLeaseSubject;
use bullet_domain::Digest;
use bullet_harness_core::launch_grant::random_hex_64;
use bullet_harness_core::{
    mutation_operation_audience, parse_mutation_operation, require_signed_mutation_permit,
    MutationPermitClaims, MutationPermitExpectation, MutationPermitSigningKey,
    MutationPermitVerificationKey, MAX_MUTATION_PERMIT_TTL_MS, MUTATION_PERMIT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Mutex;

mod candidate;

pub(crate) use candidate::AuthenticatedCandidatePreparation;

const FINGERPRINT_DOMAIN: &[u8] = b"bullet-gitd.pre-contract-request-fingerprint.v1";

/// In-process one-use reservation plus the operator mutation-permit key.
pub struct KernelAuthority {
    signing: MutationPermitSigningKey,
    verification: MutationPermitVerificationKey,
    candidate_verification: bullet_harness_core::CandidatePreparationVerificationKey,
    rows: Mutex<BTreeMap<String, Reserved>>,
}

#[derive(Clone)]
struct Reserved {
    claims: MutationPermitClaims,
    spent: bool,
}

#[derive(Deserialize)]
pub struct MintParams {
    pub operation: String,
    pub authority: Value,
    pub params: Value,
}

#[derive(Serialize)]
pub struct MintResult {
    pub kernel_permit: Value,
}

#[derive(Deserialize)]
pub struct CheckParams {
    pub operation: String,
    pub authority: Value,
    pub params: Value,
    pub kernel_permit: Value,
    pub transport_fingerprint: String,
}

#[derive(Serialize)]
pub struct CheckResult {
    pub subject: Value,
    pub operation: String,
    pub transport_fingerprint: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Deserialize)]
pub struct SettleParams {
    pub subject: Value,
    pub outcome: String,
    pub result_digest: String,
    pub completed_at_unix_ms: u64,
    pub settlement_fingerprint: String,
}

#[derive(Serialize)]
pub struct SettleResult {
    pub mutation_id: String,
    pub reservation_id: String,
    pub result_digest: String,
    pub settlement_fingerprint: String,
}

impl KernelAuthority {
    /// Bind one 64-byte key to mint and verify mutation permits.
    ///
    /// # Errors
    ///
    /// Malformed key bytes.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, String> {
        let signing = MutationPermitSigningKey::from_bytes("kernel-local", "mutation-1", bytes)
            .map_err(|error| error.to_string())?;
        let verification = signing
            .verification_key()
            .map_err(|error| error.to_string())?;
        let candidate_verification =
            bullet_harness_core::CandidatePreparationSigningKey::from_bytes(
                "kernel-local",
                "candidate-preparation-1",
                bytes,
            )
            .and_then(|key| key.verification_key())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            signing,
            verification,
            candidate_verification,
            rows: Mutex::new(BTreeMap::new()),
        })
    }

    /// Mint a one-use permit after an online lease/fence read-back.
    pub fn mint(
        &self,
        subject: &ActiveLeaseSubject,
        body: &MintParams,
        now_unix_ms: u64,
    ) -> Result<MintResult, (String, String)> {
        let operation = parse_op(&body.operation)?;
        let token = token_fields(&body.authority)?;
        let fingerprint = request_fingerprint(&body.operation, &body.authority, &body.params)?;
        if subject.fence != token.attempt_fence
            || to_hex(&subject.workspace_nonce) != token.workspace_nonce_hex
        {
            return Err((
                "AUTHORITY_REFUSED".into(),
                "online lease/fence/nonce read-back does not match the token".into(),
            ));
        }
        let mutation_hex = Digest::of(
            format!("{}:{}:{}", body.operation, fingerprint, subject.attempt_id).as_bytes(),
        )
        .to_hex();
        let mutation_id = format!("mut_{mutation_hex}");
        let reservation_id = format!("rsv_{}", Digest::of(mutation_id.as_bytes()).to_hex());
        let envelope_digest = Digest::of_json(&body.authority)
            .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?
            .to_hex();
        let token_nonce = Digest::of(token.attempt_id.as_bytes()).to_hex();
        let claims = MutationPermitClaims {
            schema_version: MUTATION_PERMIT_SCHEMA_VERSION.to_owned(),
            issuer: self.signing.issuer().to_owned(),
            audience: mutation_operation_audience(operation),
            operation,
            authority_envelope_digest: envelope_digest,
            authority_token_nonce: token_nonce,
            mutation_id: mutation_id.clone(),
            reservation_id: reservation_id.clone(),
            request_digest: fingerprint,
            repository_id: token.repository_id,
            workspace_id: subject.workspace_id.to_string(),
            workspace_generation: 1,
            attempt_id: subject.attempt_id.to_string(),
            attempt_fence: subject.fence,
            authority_epoch: 1,
            freeze_generation: 0,
            issued_at_unix_ms: now_unix_ms,
            not_before_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(MAX_MUTATION_PERMIT_TTL_MS),
            permit_nonce: random_hex_64()
                .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?,
        };
        let permit = self
            .signing
            .sign(&claims)
            .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?;
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| ("AUTHORITY_REFUSED".into(), "permit lock poisoned".into()))?;
        if rows.contains_key(&mutation_id) {
            return Err((
                "AUTHORITY_REFUSED".into(),
                "one-use mutation permit already issued".into(),
            ));
        }
        rows.insert(
            mutation_id,
            Reserved {
                claims,
                spent: false,
            },
        );
        let kernel_permit = serde_json::to_value(&permit)
            .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?;
        Ok(MintResult { kernel_permit })
    }

    /// Verify the permit and repeat the online lease/fence read-back.
    pub fn check(
        &self,
        subject: &ActiveLeaseSubject,
        body: &CheckParams,
        now_unix_ms: u64,
    ) -> Result<CheckResult, (String, String)> {
        let permit: bullet_harness_core::SignedMutationPermit =
            serde_json::from_value(body.kernel_permit.clone())
                .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?;
        let operation = parse_op(&body.operation)?;
        let token = token_fields(&body.authority)?;
        let fingerprint = request_fingerprint(&body.operation, &body.authority, &body.params)?;
        if fingerprint != body.transport_fingerprint {
            return Err((
                "AUTHORITY_SUBJECT_MISMATCH".into(),
                "Kernel fingerprint does not match gitd transport fingerprint".into(),
            ));
        }
        let expected = MutationPermitExpectation {
            audience: mutation_operation_audience(operation),
            operation,
            authority_envelope_digest: Digest::of_json(&body.authority)
                .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?
                .to_hex(),
            authority_token_nonce: Digest::of(token.attempt_id.as_bytes()).to_hex(),
            mutation_id: String::new(),
            reservation_id: String::new(),
            request_digest: fingerprint.clone(),
            repository_id: token.repository_id.clone(),
            workspace_id: subject.workspace_id.to_string(),
            workspace_generation: 1,
            attempt_id: subject.attempt_id.to_string(),
            attempt_fence: subject.fence,
            authority_epoch: 1,
            freeze_generation: 0,
            now_unix_ms,
        };
        // require_signed_mutation_permit binds exact IDs; look up the reserved row
        // by request digest first so the expected IDs match the minted permit.
        let reserved = {
            let rows = self
                .rows
                .lock()
                .map_err(|_| ("AUTHORITY_REFUSED".into(), "permit lock poisoned".into()))?;
            rows.values()
                .find(|row| {
                    row.claims.request_digest == fingerprint
                        && row.claims.attempt_id == subject.attempt_id.to_string()
                        && !row.spent
                })
                .cloned()
                .ok_or_else(|| {
                    (
                        "AUTHORITY_REFUSED".into(),
                        "no one-use Kernel reservation for this request".into(),
                    )
                })?
        };
        let mut expected = expected;
        expected.mutation_id = reserved.claims.mutation_id.clone();
        expected.reservation_id = reserved.claims.reservation_id.clone();
        expected.authority_envelope_digest = reserved.claims.authority_envelope_digest.clone();
        expected.authority_token_nonce = reserved.claims.authority_token_nonce.clone();
        let _claims = require_signed_mutation_permit(Some(&permit), &self.verification, &expected)
            .map_err(|error| (error.reason_code().to_string(), error.to_string()))?;
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| ("AUTHORITY_REFUSED".into(), "permit lock poisoned".into()))?;
        let row = rows
            .get_mut(&reserved.claims.mutation_id)
            .ok_or_else(|| ("AUTHORITY_REFUSED".into(), "reservation disappeared".into()))?;
        if row.spent {
            return Err((
                "AUTHORITY_REFUSED".into(),
                "Kernel one-use permit already consumed".into(),
            ));
        }
        row.spent = true;
        let permit_digest = Digest::of(reserved.claims.permit_nonce.as_bytes()).to_hex();
        Ok(CheckResult {
            subject: serde_json::json!({
                "authority_envelope_digest": reserved.claims.authority_envelope_digest,
                "authority_token_nonce": reserved.claims.authority_token_nonce,
                "mutation_id": reserved.claims.mutation_id,
                "reservation_id": reserved.claims.reservation_id,
                "operation": body.operation,
                "request_digest": fingerprint,
                "repository_id": reserved.claims.repository_id,
                "workspace_id": reserved.claims.workspace_id,
                "workspace_generation": reserved.claims.workspace_generation,
                "workspace_nonce": to_hex(&subject.workspace_nonce),
                "attempt_id": reserved.claims.attempt_id,
                "attempt_fence": reserved.claims.attempt_fence,
                "authority_epoch": reserved.claims.authority_epoch,
                "freeze_generation": reserved.claims.freeze_generation,
                "permit_nonce": reserved.claims.permit_nonce,
                "permit_digest": permit_digest,
            }),
            operation: body.operation.clone(),
            transport_fingerprint: fingerprint,
            expires_at_unix_ms: reserved.claims.expires_at_unix_ms,
        })
    }

    /// Authenticate the Candidate carrier for `prepare-candidate` only.
    pub(crate) fn authenticate_candidate_preparation(
        &self,
        body: &CheckParams,
    ) -> Result<Option<AuthenticatedCandidatePreparation>, (String, String)> {
        if body.operation == "prepare-candidate" {
            candidate::authenticate(&body.params, &body.authority, &self.candidate_verification)
                .map(Some)
        } else {
            Ok(None)
        }
    }

    /// Acknowledge settlement of a consumed permit.
    pub fn settle(&self, body: &SettleParams) -> Result<SettleResult, (String, String)> {
        let mutation_id = body
            .subject
            .get("mutation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    "MUTATION_OUTCOME_UNKNOWN".into(),
                    "subject missing mutation_id".into(),
                )
            })?
            .to_string();
        let reservation_id = body
            .subject
            .get("reservation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    "MUTATION_OUTCOME_UNKNOWN".into(),
                    "subject missing reservation_id".into(),
                )
            })?
            .to_string();
        Ok(SettleResult {
            mutation_id,
            reservation_id,
            result_digest: body.result_digest.clone(),
            settlement_fingerprint: body.settlement_fingerprint.clone(),
        })
    }
}

struct TokenFields {
    attempt_id: String,
    attempt_fence: u64,
    workspace_nonce_hex: String,
    repository_id: String,
}

fn token_fields(authority: &Value) -> Result<TokenFields, (String, String)> {
    let attempt_id = authority
        .get("attempt_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "AUTHORITY_REFUSED".into(),
                "authority token missing attempt_id".into(),
            )
        })?
        .to_string();
    let attempt_fence = authority
        .get("attempt_fence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            (
                "AUTHORITY_REFUSED".into(),
                "authority token missing attempt_fence".into(),
            )
        })?;
    let nonce = authority.get("workspace_nonce").ok_or_else(|| {
        (
            "AUTHORITY_REFUSED".into(),
            "authority token missing workspace_nonce".into(),
        )
    })?;
    let workspace_nonce_hex = if let Some(hex) = nonce.as_str() {
        hex.to_string()
    } else if let Some(bytes) = nonce.as_array() {
        let raw = bytes
            .iter()
            .map(|value| value.as_u64().unwrap_or(0) as u8)
            .collect::<Vec<_>>();
        to_hex(&raw)
    } else {
        return Err((
            "AUTHORITY_REFUSED".into(),
            "workspace_nonce is not hex or bytes".into(),
        ));
    };
    let repository_id = authority
        .get("repository_id")
        .and_then(Value::as_str)
        .unwrap_or("rep_0000000000000000000000000000000000000000000000000000000000000000")
        .to_string();
    Ok(TokenFields {
        attempt_id,
        attempt_fence,
        workspace_nonce_hex,
        repository_id,
    })
}

fn parse_op(label: &str) -> Result<bullet_harness_core::MutationOperation, (String, String)> {
    parse_mutation_operation(label).map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))
}

fn request_fingerprint(
    operation: &str,
    authority: &Value,
    params: &Value,
) -> Result<String, (String, String)> {
    let authority = serde_json::to_vec(authority)
        .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?;
    let params = serde_json::to_vec(params)
        .map_err(|error| ("AUTHORITY_REFUSED".into(), error.to_string()))?;
    let mut buf = Vec::new();
    for field in [
        FINGERPRINT_DOMAIN,
        operation.as_bytes(),
        &authority,
        &params,
    ] {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    Ok(Digest::of(&buf).to_hex())
}

pub(crate) fn token_attempt_id(authority: &Value) -> Result<String, (String, String)> {
    token_fields(authority).map(|token| token.attempt_id)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
