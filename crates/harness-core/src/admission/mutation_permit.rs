//! Short-lived PASETO mutation permits. The envelope matches
//! `SignedMutationPermitV1`; the payload, footer, and implicit assertion match
//! the hub `authority.permit` contract. Verification is not a capability until
//! `require_signed_mutation_permit` binds the exact reserved subject.

use crate::error::HarnessError;
use crate::launch_grant::{
    canonical_json, decode_canonical, is_lower_hex_64, validate_label, LaunchGrantSigningKey,
    LaunchGrantVerificationKey, SIGNING_KEY_BYTES, VERIFICATION_KEY_BYTES,
};
pub use bullet_domain::schema_bundle::{
    AuthorityAudienceV1 as AuthorityAudience, MutationOperationV1 as MutationOperation,
    MutationPermitClaimsV1 as MutationPermitClaims, SignedMutationPermitV1 as SignedMutationPermit,
};
use bullet_domain::{AttemptId, RepositoryId, WorkspaceId};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Frozen schema version of the mutation-permit contract.
pub const MUTATION_PERMIT_SCHEMA_VERSION: &str = bullet_domain::schema_bundle::SCHEMA_VERSION;
/// Footer purpose that binds the signing key to mutation permits only.
pub const MUTATION_PERMIT_KEY_PURPOSE: &str = "mutation-permit-signing";
/// PASETO implicit assertion; never transmitted, always authenticated.
pub const MUTATION_PERMIT_IMPLICIT_ASSERTION: &[u8] = b"bullet-farm.mutation-permit.v1alpha1";
/// Maximum lifetime of one permit, in milliseconds.
pub const MAX_MUTATION_PERMIT_TTL_MS: u64 = 1_000;
/// Largest integer every JSON consumer represents exactly.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TOKEN_BYTES: usize = 32_768;

/// Parse exactly one Hub-authored mutation-operation label.
///
/// # Errors
///
/// `INVALID_MUTATION_PERMIT` when the label is not in the generated closed enum.
pub fn parse_mutation_operation(label: &str) -> Result<MutationOperation, HarnessError> {
    serde_json::from_value(serde_json::Value::String(label.to_owned())).map_err(|_| {
        refused(
            "INVALID_MUTATION_PERMIT",
            "mutation operation is not a frozen contract label",
        )
    })
}

/// Audience required by a Hub-authored mutation operation.
#[must_use]
pub const fn mutation_operation_audience(operation: MutationOperation) -> AuthorityAudience {
    match operation {
        MutationOperation::DispatchEffect | MutationOperation::ReconcileEffect => {
            AuthorityAudience::EffectBroker
        }
        MutationOperation::CloneWorkspace
        | MutationOperation::ReadWorkspace
        | MutationOperation::ApplyPatch
        | MutationOperation::Checkpoint
        | MutationOperation::PrepareCandidate
        | MutationOperation::PreserveWorkspace
        | MutationOperation::CleanupWorkspace => AuthorityAudience::BulletGitd,
    }
}

fn validate_claims(claims: &MutationPermitClaims) -> Result<(), HarnessError> {
    if claims.schema_version != MUTATION_PERMIT_SCHEMA_VERSION {
        return Err(refused(
            "UNSUPPORTED_MUTATION_PERMIT_SCHEMA",
            "mutation permit claims require schema v1alpha1",
        ));
    }
    if claims.audience != mutation_operation_audience(claims.operation) {
        return Err(refused(
            "INVALID_MUTATION_PERMIT_AUDIENCE",
            "mutation permit operation is not valid for the selected gateway audience",
        ));
    }
    validate_label("issuer", &claims.issuer)
        .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?;
    for (name, value) in [
        ("mutation_id", claims.mutation_id.as_str()),
        ("reservation_id", claims.reservation_id.as_str()),
    ] {
        let prefix = if name == "mutation_id" {
            "mut_"
        } else {
            "rsv_"
        };
        if !prefixed_hex(prefix, value) {
            return Err(refused(
                "INVALID_MUTATION_PERMIT",
                format!("{name} must be a frozen typed id"),
            ));
        }
    }
    if RepositoryId::parse(&claims.repository_id).is_err()
        || WorkspaceId::parse(&claims.workspace_id).is_err()
        || AttemptId::parse(&claims.attempt_id).is_err()
    {
        return Err(refused(
            "INVALID_MUTATION_PERMIT",
            "repository, workspace, or attempt id is not a frozen typed id",
        ));
    }
    for digest in [
        claims.authority_envelope_digest.as_str(),
        claims.authority_token_nonce.as_str(),
        claims.request_digest.as_str(),
        claims.permit_nonce.as_str(),
    ] {
        if !is_lower_hex_64(digest) {
            return Err(refused(
                "INVALID_MUTATION_PERMIT",
                "permit digest fields must be 64 lowercase hex characters",
            ));
        }
    }
    for (name, value) in [
        ("workspace_generation", claims.workspace_generation),
        ("attempt_fence", claims.attempt_fence),
        ("authority_epoch", claims.authority_epoch),
    ] {
        if value == 0 || value > MAX_SAFE_INTEGER {
            return Err(refused(
                "INVALID_MUTATION_PERMIT_GENERATION",
                format!("{name} must be a positive interoperable integer"),
            ));
        }
    }
    if claims.freeze_generation > MAX_SAFE_INTEGER
        || claims.issued_at_unix_ms > MAX_SAFE_INTEGER
        || claims.not_before_unix_ms > MAX_SAFE_INTEGER
        || claims.expires_at_unix_ms > MAX_SAFE_INTEGER
    {
        return Err(refused(
            "INVALID_MUTATION_PERMIT_TIME",
            "permit time or freeze generation exceeds the interoperable integer range",
        ));
    }
    if claims.issued_at_unix_ms > claims.not_before_unix_ms
        || claims.not_before_unix_ms >= claims.expires_at_unix_ms
        || claims.expires_at_unix_ms - claims.issued_at_unix_ms > MAX_MUTATION_PERMIT_TTL_MS
    {
        return Err(refused(
            "INVALID_MUTATION_PERMIT_WINDOW",
            "permit requires issued_at <= not_before < expires_at and a TTL at most 1s",
        ));
    }
    Ok(())
}

/// Exact subject plus the verification instant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationPermitExpectation {
    /// Audience required by the reserved operation.
    pub audience: AuthorityAudience,
    /// Reserved operation.
    pub operation: MutationOperation,
    /// Digest of the durable authority envelope.
    pub authority_envelope_digest: String,
    /// Authority token nonce.
    pub authority_token_nonce: String,
    /// Reserved mutation.
    pub mutation_id: String,
    /// Reserved reservation.
    pub reservation_id: String,
    /// Request digest bound at reserve.
    pub request_digest: String,
    /// Target repository.
    pub repository_id: String,
    /// Private workspace.
    pub workspace_id: String,
    /// Workspace generation.
    pub workspace_generation: u64,
    /// Attempt incarnation.
    pub attempt_id: String,
    /// Permanent fence.
    pub attempt_fence: u64,
    /// Authority epoch.
    pub authority_epoch: u64,
    /// Freeze generation.
    pub freeze_generation: u64,
    /// Verification instant.
    pub now_unix_ms: u64,
}

/// Operator-held issuing key. The launch-grant key type is reused only as a
/// raw v4.public holder; the footer and implicit assertion stay permit-specific.
pub struct MutationPermitSigningKey {
    inner: LaunchGrantSigningKey,
}

impl MutationPermitSigningKey {
    /// Load exactly 64 raw secret-key bytes.
    ///
    /// # Errors
    ///
    /// `MUTATION_PERMIT_REFUSED` for a bad label or malformed key.
    pub fn from_bytes(issuer: &str, key_id: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        if bytes.len() != SIGNING_KEY_BYTES {
            return Err(refused(
                "INVALID_MUTATION_PERMIT",
                "PASETO v4.public secret keys are 64 bytes",
            ));
        }
        Ok(Self {
            inner: LaunchGrantSigningKey::from_bytes(issuer, key_id, bytes)
                .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?,
        })
    }

    /// Generate a fresh key pair from operating-system entropy.
    ///
    /// # Errors
    ///
    /// `MUTATION_PERMIT_REFUSED` for a bad label or an entropy failure.
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, HarnessError> {
        Ok(Self {
            inner: LaunchGrantSigningKey::generate(issuer, key_id)
                .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?,
        })
    }

    /// Issuer label.
    #[must_use]
    pub fn issuer(&self) -> &str {
        self.inner.issuer()
    }

    /// Key label.
    #[must_use]
    pub fn key_id(&self) -> &str {
        self.inner.key_id()
    }

    /// Matching verification key.
    ///
    /// # Errors
    ///
    /// Never in practice; the public half was derived from this secret.
    pub fn verification_key(&self) -> Result<MutationPermitVerificationKey, HarnessError> {
        MutationPermitVerificationKey::from_hex(
            self.inner.issuer(),
            self.inner.key_id(),
            self.inner.public_key_hex(),
        )
    }

    /// Sign validated claims whose issuer equals this key's issuer.
    ///
    /// # Errors
    ///
    /// Typed permit refusals for shape, issuer mismatch, or signing failure.
    pub fn sign(
        &self,
        claims: &MutationPermitClaims,
    ) -> Result<SignedMutationPermit, HarnessError> {
        validate_claims(claims)?;
        if claims.issuer != self.inner.issuer() {
            return Err(refused(
                "MUTATION_PERMIT_ISSUER_MISMATCH",
                "permit issuer does not match signing key issuer",
            ));
        }
        let payload = canonical_json(claims)
            .map_err(|error| refused("MUTATION_PERMIT_SIGNING_FAILED", error.to_string()))?;
        let footer = canonical_json(&permit_footer(self.inner.issuer(), self.inner.key_id()))
            .map_err(|error| refused("MUTATION_PERMIT_SIGNING_FAILED", error.to_string()))?;
        let secret = pasetors::keys::AsymmetricSecretKey::<V4>::from(self.inner.secret_bytes())
            .map_err(|_| {
                refused(
                    "MUTATION_PERMIT_SIGNING_FAILED",
                    "signing key bytes are not a v4.public secret",
                )
            })?;
        let paseto = PublicToken::sign(
            &secret,
            &payload,
            Some(&footer),
            Some(MUTATION_PERMIT_IMPLICIT_ASSERTION),
        )
        .map_err(|_| refused("MUTATION_PERMIT_SIGNING_FAILED", "PASETO signing failed"))?;
        Ok(SignedMutationPermit {
            schema_version: MUTATION_PERMIT_SCHEMA_VERSION.to_owned(),
            issuer: self.inner.issuer().to_owned(),
            key_id: self.inner.key_id().to_owned(),
            paseto,
        })
    }
}

/// Policy-published public key for one `(issuer, key_id)`.
#[derive(Clone, Debug)]
pub struct MutationPermitVerificationKey {
    inner: LaunchGrantVerificationKey,
}

impl MutationPermitVerificationKey {
    /// Parse the 64-hex raw public key form.
    ///
    /// # Errors
    ///
    /// `INVALID_MUTATION_PERMIT` for a bad label or key encoding.
    pub fn from_hex(issuer: &str, key_id: &str, public_hex: &str) -> Result<Self, HarnessError> {
        Ok(Self {
            inner: LaunchGrantVerificationKey::from_hex(issuer, key_id, public_hex)
                .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?,
        })
    }

    /// Load exactly 32 raw public-key bytes.
    ///
    /// # Errors
    ///
    /// `INVALID_MUTATION_PERMIT` for a bad label or malformed key.
    pub fn from_bytes(issuer: &str, key_id: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        if bytes.len() != VERIFICATION_KEY_BYTES {
            return Err(refused(
                "INVALID_MUTATION_PERMIT",
                "PASETO v4.public public keys are 32 bytes",
            ));
        }
        Ok(Self {
            inner: LaunchGrantVerificationKey::from_bytes(issuer, key_id, bytes)
                .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?,
        })
    }
}

/// First use site of a signed mutation permit: authenticate, bind the reserved
/// subject, and enforce the one-second window. A valid return is still not a
/// spent reservation; the caller must settle the one-use row in the same write.
///
/// # Errors
///
/// Missing envelope, bad signature, subject mismatch, or a closed time window.
pub fn require_signed_mutation_permit(
    permit: Option<&SignedMutationPermit>,
    key: &MutationPermitVerificationKey,
    expected: &MutationPermitExpectation,
) -> Result<MutationPermitClaims, HarnessError> {
    let permit = permit.ok_or_else(|| {
        refused(
            "MUTATION_PERMIT_MISSING",
            "apply requires a signed mutation permit minted from the active lease",
        )
    })?;
    let claims = authenticate(key, permit)?;
    verify_subject(&claims, expected)?;
    if expected.now_unix_ms < claims.not_before_unix_ms {
        return Err(refused(
            "MUTATION_PERMIT_NOT_YET_VALID",
            "mutation permit is not valid yet",
        ));
    }
    if expected.now_unix_ms >= claims.expires_at_unix_ms {
        return Err(refused(
            "MUTATION_PERMIT_EXPIRED",
            "mutation permit has expired",
        ));
    }
    Ok(claims)
}

fn authenticate(
    key: &MutationPermitVerificationKey,
    permit: &SignedMutationPermit,
) -> Result<MutationPermitClaims, HarnessError> {
    validate_permit_envelope(permit)?;
    if permit.issuer != key.inner.issuer() || permit.key_id != key.inner.key_id() {
        return Err(refused(
            "MUTATION_PERMIT_KEY_MISMATCH",
            "permit issuer or key does not match the selected verification key",
        ));
    }
    let footer = canonical_json(&permit_footer(key.inner.issuer(), key.inner.key_id()))
        .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?;
    let public = pasetors::keys::AsymmetricPublicKey::<V4>::from(
        &hex::decode(key.inner.public_key_hex()).map_err(|_| {
            refused(
                "INVALID_MUTATION_PERMIT",
                "verification key hex is not decodable",
            )
        })?,
    )
    .map_err(|_| {
        refused(
            "INVALID_MUTATION_PERMIT",
            "verification key bytes are not a v4.public public key",
        )
    })?;
    let untrusted = UntrustedToken::<Public, V4>::try_from(permit.paseto.as_str())
        .map_err(|_| refused("INVALID_MUTATION_PERMIT", "invalid PASETO framing"))?;
    let trusted = PublicToken::verify(
        &public,
        &untrusted,
        Some(&footer),
        Some(MUTATION_PERMIT_IMPLICIT_ASSERTION),
    )
    .map_err(|_| {
        refused(
            "INVALID_MUTATION_PERMIT_SIGNATURE",
            "permit signature, footer, or implicit assertion is invalid",
        )
    })?;
    let claims = decode_canonical::<MutationPermitClaims>(trusted.payload().as_bytes())
        .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?;
    validate_claims(&claims)?;
    if claims.issuer != key.inner.issuer() {
        return Err(refused(
            "MUTATION_PERMIT_ISSUER_MISMATCH",
            "signed permit issuer does not match the selected key",
        ));
    }
    Ok(claims)
}

fn verify_subject(
    claims: &MutationPermitClaims,
    expected: &MutationPermitExpectation,
) -> Result<(), HarnessError> {
    if claims.audience != expected.audience
        || claims.operation != expected.operation
        || claims.authority_envelope_digest != expected.authority_envelope_digest
        || claims.authority_token_nonce != expected.authority_token_nonce
        || claims.mutation_id != expected.mutation_id
        || claims.reservation_id != expected.reservation_id
        || claims.request_digest != expected.request_digest
        || claims.repository_id != expected.repository_id
        || claims.workspace_id != expected.workspace_id
        || claims.workspace_generation != expected.workspace_generation
        || claims.attempt_id != expected.attempt_id
        || claims.attempt_fence != expected.attempt_fence
        || claims.authority_epoch != expected.authority_epoch
        || claims.freeze_generation != expected.freeze_generation
    {
        return Err(refused(
            "MUTATION_PERMIT_SUBJECT_MISMATCH",
            "permit does not bind the exact reserved mutation subject",
        ));
    }
    Ok(())
}

fn validate_permit_envelope(permit: &SignedMutationPermit) -> Result<(), HarnessError> {
    if permit.schema_version != MUTATION_PERMIT_SCHEMA_VERSION {
        return Err(refused(
            "UNSUPPORTED_MUTATION_PERMIT_SCHEMA",
            "mutation permit envelope requires schema v1alpha1",
        ));
    }
    validate_label("issuer", &permit.issuer)
        .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?;
    validate_label("key_id", &permit.key_id)
        .map_err(|error| refused("INVALID_MUTATION_PERMIT", error.to_string()))?;
    if !permit.paseto.starts_with("v4.public.") || permit.paseto.len() > MAX_TOKEN_BYTES {
        return Err(refused(
            "INVALID_MUTATION_PERMIT",
            "mutation permit must be a bounded compact PASETO v4.public token",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitFooter {
    schema_version: String,
    issuer: String,
    key_id: String,
    purpose: String,
}

fn permit_footer(issuer: &str, key_id: &str) -> PermitFooter {
    PermitFooter {
        schema_version: MUTATION_PERMIT_SCHEMA_VERSION.to_owned(),
        issuer: issuer.to_owned(),
        key_id: key_id.to_owned(),
        purpose: MUTATION_PERMIT_KEY_PURPOSE.to_owned(),
    }
}

fn prefixed_hex(prefix: &str, value: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_lower_hex_64)
}

fn refused(code: &'static str, reason: impl Into<String>) -> HarnessError {
    HarnessError::MutationPermitRefused {
        code,
        reason: reason.into(),
    }
}
