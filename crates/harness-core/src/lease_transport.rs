//! Signed internal lease-transport contract.
//!
//! This is the Kernel↔Runner permit, not a public farmd route and not a
//! launch grant. Audience is `lease-runner`. Footer purpose is
//! `lease-transport-signing`. Implicit assertion is
//! `bullet-farm.lease-transport.v1alpha1`. A valid permit authorizes one
//! named operation for one request digest against one durable lease
//! subject; it does not acquire a lease by itself and it never clears
//! provider live admission. The claim set is represented by
//! [`LeaseTransportClaims`] and its re-exported subject types.

mod binding;

pub use binding::{
    nonce_binding, LeaseIncarnationClaims, LeaseSubjectClaims, LeaseTransportClaims,
    LeaseTransportError, LeaseTransportExpectation, LeaseTransportOperation,
};

use crate::launch_grant::{
    canonical_json, decode_canonical, is_lower_hex_64, random_hex_64, validate_label,
    LaunchGrantNonceLedger, NonceConsumption,
};
use binding::{invalid, map_harness, printable};
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;
use serde::{Deserialize, Serialize};

/// Frozen schema of the lease-transport permit.
pub const LEASE_TRANSPORT_SCHEMA_VERSION: &str = "v1alpha1";
/// The only audience a lease-transport permit may name.
pub const LEASE_TRANSPORT_AUDIENCE: &str = "lease-runner";
/// Footer purpose bound into the signature.
pub const LEASE_TRANSPORT_KEY_PURPOSE: &str = "lease-transport-signing";
/// PASETO implicit assertion; never transmitted.
pub const LEASE_TRANSPORT_IMPLICIT_ASSERTION: &[u8] = b"bullet-farm.lease-transport.v1alpha1";
/// Digest domain for canonical claims.
pub const LEASE_TRANSPORT_CLAIMS_DOMAIN: &str = "authority.lease-transport-claims.v1alpha1";
const MAX_TOKEN_BYTES: usize = 32_768;

/// Compact envelope carrying one PASETO v4.public token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLeasePermit {
    /// Always `v1alpha1`.
    pub schema_version: String,
    /// Issuer label repeated from the footer.
    pub issuer: String,
    /// Key label repeated from the footer.
    pub key_id: String,
    /// `v4.public.` token with canonical footer.
    pub paseto: String,
}

impl SignedLeasePermit {
    /// Validate framing without trusting the payload.
    ///
    /// # Errors
    ///
    /// `LEASE_TRANSPORT_INVALID` for unsupported schema or framing.
    pub fn validate_envelope(&self) -> Result<(), LeaseTransportError> {
        if self.schema_version != LEASE_TRANSPORT_SCHEMA_VERSION {
            return Err(invalid("envelope schema_version must be v1alpha1"));
        }
        validate_label("issuer", &self.issuer).map_err(map_harness)?;
        validate_label("key_id", &self.key_id).map_err(map_harness)?;
        if !self.paseto.starts_with("v4.public.")
            || self.paseto.len() > MAX_TOKEN_BYTES
            || !self
                .paseto
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(invalid(
                "lease permit must be a bounded compact PASETO v4.public token",
            ));
        }
        Ok(())
    }
}

/// Operator-held issuing key. Never serialized.
pub struct LeaseTransportSigningKey {
    issuer: String,
    key_id: String,
    secret: AsymmetricSecretKey<V4>,
    public_hex: String,
}

impl LeaseTransportSigningKey {
    /// Generate a fresh key pair from operating-system entropy.
    ///
    /// # Errors
    ///
    /// `LEASE_TRANSPORT_INVALID` for a bad label or entropy failure.
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, LeaseTransportError> {
        validate_label("issuer", issuer).map_err(map_harness)?;
        validate_label("key_id", key_id).map_err(map_harness)?;
        let pair = AsymmetricKeyPair::<V4>::generate().map_err(|_| {
            invalid("operating-system entropy unavailable for lease-transport key generation")
        })?;
        Self::from_bytes(issuer, key_id, pair.secret.as_bytes())
    }

    /// Load exactly 64 raw secret-key bytes.
    ///
    /// # Errors
    ///
    /// `LEASE_TRANSPORT_INVALID` for a bad label or malformed key.
    pub fn from_bytes(
        issuer: &str,
        key_id: &str,
        bytes: &[u8],
    ) -> Result<Self, LeaseTransportError> {
        validate_label("issuer", issuer).map_err(map_harness)?;
        validate_label("key_id", key_id).map_err(map_harness)?;
        if bytes.len() != 64 || bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("PASETO v4.public secret keys are 64 nonzero bytes"));
        }
        let secret = AsymmetricSecretKey::<V4>::from(bytes)
            .map_err(|_| invalid("invalid lease-transport signing key"))?;
        let public = AsymmetricPublicKey::<V4>::try_from(&secret)
            .map_err(|_| invalid("signing key has no derivable public half"))?;
        Ok(Self {
            issuer: issuer.to_string(),
            key_id: key_id.to_string(),
            secret,
            public_hex: hex::encode(public.as_bytes()),
        })
    }

    /// Issuer label.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Key label.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Raw 64 secret bytes, for the 0600 farmd key file only.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }

    /// Matching verification key.
    ///
    /// # Errors
    ///
    /// `LEASE_TRANSPORT_INVALID` if the public half cannot be parsed.
    pub fn verification_key(&self) -> Result<LeaseTransportVerificationKey, LeaseTransportError> {
        LeaseTransportVerificationKey::from_hex(&self.issuer, &self.key_id, &self.public_hex)
    }

    /// Sign validated claims whose issuer/key labels equal this key.
    ///
    /// # Errors
    ///
    /// Shape, label, or signing failure.
    pub fn sign(
        &self,
        claims: &LeaseTransportClaims,
    ) -> Result<SignedLeasePermit, LeaseTransportError> {
        claims.validate_shape()?;
        if claims.issuer != self.issuer || claims.key_id != self.key_id {
            return Err(invalid("claims issuer/key_id do not match the signing key"));
        }
        let payload = canonical_json(claims).map_err(map_harness)?;
        let footer = canonical_json(&LeaseTransportFooter::new(&self.issuer, &self.key_id))
            .map_err(map_harness)?;
        let paseto = PublicToken::sign(
            &self.secret,
            &payload,
            Some(&footer),
            Some(LEASE_TRANSPORT_IMPLICIT_ASSERTION),
        )
        .map_err(|_| invalid("PASETO signing failed"))?;
        Ok(SignedLeasePermit {
            schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            paseto,
        })
    }
}

/// Policy-published public key for one `(issuer, key_id)`.
#[derive(Clone, Debug)]
pub struct LeaseTransportVerificationKey {
    issuer: String,
    key_id: String,
    public: AsymmetricPublicKey<V4>,
}

impl LeaseTransportVerificationKey {
    /// Parse the 64-hex raw public key.
    ///
    /// # Errors
    ///
    /// `LEASE_TRANSPORT_INVALID` for a bad label or key encoding.
    pub fn from_hex(
        issuer: &str,
        key_id: &str,
        public_hex: &str,
    ) -> Result<Self, LeaseTransportError> {
        if !is_lower_hex_64(public_hex) {
            return Err(invalid(
                "verification key must be 64 lowercase hex characters",
            ));
        }
        let bytes = hex::decode(public_hex).map_err(|_| invalid("verification key hex"))?;
        validate_label("issuer", issuer).map_err(map_harness)?;
        validate_label("key_id", key_id).map_err(map_harness)?;
        if bytes.len() != 32 || bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("PASETO v4.public public keys are 32 nonzero bytes"));
        }
        let public = AsymmetricPublicKey::<V4>::from(bytes.as_slice())
            .map_err(|_| invalid("invalid verification key"))?;
        Ok(Self {
            issuer: issuer.to_string(),
            key_id: key_id.to_string(),
            public,
        })
    }

    /// Authenticate one envelope and return the claims.
    ///
    /// # Errors
    ///
    /// Envelope, footer, or signature refusal.
    pub fn authenticate(
        &self,
        permit: &SignedLeasePermit,
    ) -> Result<LeaseTransportClaims, LeaseTransportError> {
        permit.validate_envelope()?;
        if permit.issuer != self.issuer || permit.key_id != self.key_id {
            return Err(LeaseTransportError::KeyUnknown {
                issuer: printable(&permit.issuer),
                key_id: printable(&permit.key_id),
            });
        }
        let footer = canonical_json(&LeaseTransportFooter::new(&self.issuer, &self.key_id))
            .map_err(map_harness)?;
        let untrusted = UntrustedToken::<Public, V4>::try_from(permit.paseto.as_str())
            .map_err(|_| invalid("invalid PASETO framing"))?;
        let trusted = PublicToken::verify(
            &self.public,
            &untrusted,
            Some(&footer),
            Some(LEASE_TRANSPORT_IMPLICIT_ASSERTION),
        )
        .map_err(|_| invalid("PASETO signature, footer, or implicit assertion is invalid"))?;
        let claims = decode_canonical::<LeaseTransportClaims>(trusted.payload().as_bytes())
            .map_err(map_harness)?;
        claims.validate_shape()?;
        if claims.issuer != self.issuer || claims.key_id != self.key_id {
            return Err(invalid("authenticated claims do not match the key"));
        }
        Ok(claims)
    }
}

/// A permit that passed authentication, subject, time, and nonce consumption.
#[derive(Debug)]
#[must_use = "a verified lease permit must be consumed by the Kernel service or dropped"]
pub struct VerifiedLeasePermit {
    claims: LeaseTransportClaims,
}

impl VerifiedLeasePermit {
    /// Authenticated claims.
    #[must_use]
    pub fn claims(&self) -> &LeaseTransportClaims {
        &self.claims
    }
}

/// Verify one permit against the exact expectation and consume its nonce.
///
/// # Errors
///
/// Typed lease-transport refusal. Nothing is consumed unless every other
/// check passed.
pub fn verify_lease_permit(
    permit: &SignedLeasePermit,
    key: &LeaseTransportVerificationKey,
    expectation: &LeaseTransportExpectation,
    nonces: &mut dyn LaunchGrantNonceLedger,
) -> Result<VerifiedLeasePermit, LeaseTransportError> {
    let claims = key.authenticate(permit)?;
    expectation.check(&claims)?;
    let (not_before, expires_at) = claims.window();
    if expectation.now_unix_ms < not_before {
        return Err(LeaseTransportError::NotYetValid {
            not_before_unix_ms: not_before,
        });
    }
    if expectation.now_unix_ms >= expires_at {
        return Err(LeaseTransportError::Expired {
            expires_at_unix_ms: expires_at,
        });
    }
    let attempt_binding = nonce_binding(
        claims.operation,
        &claims.runner_id,
        &claims.idempotency_digest,
    );
    match nonces
        .consume_nonce(
            &claims.permit_nonce,
            &attempt_binding,
            expectation.now_unix_ms,
        )
        .map_err(map_harness)?
    {
        NonceConsumption::Consumed => Ok(VerifiedLeasePermit { claims }),
        NonceConsumption::Replayed => Err(LeaseTransportError::Replayed {
            permit_id: claims.permit_id,
        }),
        NonceConsumption::Unknown | NonceConsumption::Expired => Err(invalid(
            "permit nonce was not issued for this operation binding or has expired",
        )),
    }
}

/// Digest of one request body under the lease-transport domain.
///
/// # Errors
///
/// Encoding failure.
pub fn request_digest<T: Serialize>(body: &T) -> Result<String, LeaseTransportError> {
    crate::launch_grant::hash_canonical("authority.lease-transport-request.v1alpha1", body)
        .map_err(map_harness)
}

/// Fresh 64-hex identifier.
///
/// # Errors
///
/// Entropy failure.
pub fn new_hex_64() -> Result<String, LeaseTransportError> {
    random_hex_64().map_err(map_harness)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseTransportFooter {
    schema_version: String,
    issuer: String,
    key_id: String,
    purpose: String,
}

impl LeaseTransportFooter {
    fn new(issuer: &str, key_id: &str) -> Self {
        Self {
            schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
            issuer: issuer.to_string(),
            key_id: key_id.to_string(),
            purpose: LEASE_TRANSPORT_KEY_PURPOSE.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch_grant::MemoryNonceLedger;

    fn subject(operation: LeaseTransportOperation) -> LeaseSubjectClaims {
        LeaseSubjectClaims {
            workspace_id: "wsp_one".into(),
            workspace_generation: 1,
            workspace_nonce_digest: "e".repeat(64),
            scope_digest: "f".repeat(64),
            policy_generation: 1,
            freeze_generation: 0,
            graph_revision: 1,
            routing_generation: 1,
            authority_epoch: 1,
            incarnation: operation
                .binds_incarnation()
                .then(|| LeaseIncarnationClaims {
                    variant_id: "var_one".into(),
                    attempt_id: "atm_one".into(),
                    fence: 1,
                    scope_revision: 1,
                    context_revision: 1,
                }),
        }
    }

    fn claims(
        key: &LeaseTransportSigningKey,
        operation: LeaseTransportOperation,
    ) -> LeaseTransportClaims {
        let now = 1_700_000_000_000;
        LeaseTransportClaims {
            schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
            permit_id: "a".repeat(64),
            audience: LEASE_TRANSPORT_AUDIENCE.to_string(),
            operation,
            issuer: key.issuer().to_string(),
            key_id: key.key_id().to_string(),
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 15_000,
            permit_nonce: "b".repeat(64),
            request_digest: "c".repeat(64),
            runner_id: "run_one".into(),
            runner_epoch: 1,
            authority_epoch: 1,
            work_package_id: "wp_one".into(),
            idempotency_digest: "d".repeat(64),
            subject: subject(operation),
        }
    }

    fn expectation(claims: &LeaseTransportClaims, now: u64) -> LeaseTransportExpectation {
        LeaseTransportExpectation {
            operation: claims.operation,
            request_digest: claims.request_digest.clone(),
            runner_id: claims.runner_id.clone(),
            runner_epoch: claims.runner_epoch,
            authority_epoch: claims.authority_epoch,
            work_package_id: claims.work_package_id.clone(),
            idempotency_digest: claims.idempotency_digest.clone(),
            subject: claims.subject.clone(),
            now_unix_ms: now,
        }
    }

    #[test]
    fn acquire_permit_verifies_once_and_replays() {
        let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
        let verify = key.verification_key().unwrap();
        let claims = claims(&key, LeaseTransportOperation::Acquire);
        let permit = key.sign(&claims).unwrap();
        let mut nonces = MemoryNonceLedger::new();
        assert!(nonces.register(
            &claims.permit_nonce,
            &format!("acquire:{}:{}", claims.runner_id, claims.idempotency_digest),
            claims.expires_at_unix_ms,
        ));
        let expect = expectation(&claims, claims.not_before_unix_ms);
        drop(verify_lease_permit(&permit, &verify, &expect, &mut nonces).unwrap());
        let replayed = verify_lease_permit(&permit, &verify, &expect, &mut nonces).unwrap_err();
        assert_eq!(replayed.reason_code(), "LEASE_TRANSPORT_REPLAYED");
    }

    #[test]
    fn wrong_audience_and_subject_refuse_before_nonce() {
        let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
        let verify = key.verification_key().unwrap();
        let mut hostile = claims(&key, LeaseTransportOperation::Acquire);
        hostile.audience = "provider-runner".into();
        assert_eq!(
            hostile.validate_shape().unwrap_err().reason_code(),
            "LEASE_TRANSPORT_AUDIENCE_MISMATCH"
        );
        let claims = claims(&key, LeaseTransportOperation::Acquire);
        let permit = key.sign(&claims).unwrap();
        let mut expect = expectation(&claims, claims.not_before_unix_ms);
        expect.runner_id = "run_other".into();
        let mut nonces = MemoryNonceLedger::new();
        assert!(nonces.register(
            &claims.permit_nonce,
            &format!("acquire:{}:{}", claims.runner_id, claims.idempotency_digest),
            claims.expires_at_unix_ms,
        ));
        assert_eq!(
            verify_lease_permit(&permit, &verify, &expect, &mut nonces).unwrap_err(),
            LeaseTransportError::SubjectMismatch { field: "runner_id" }
        );
        assert!(!nonces.is_consumed(&claims.permit_nonce));
    }

    #[test]
    fn launch_grant_token_is_not_a_lease_permit() {
        let key = LeaseTransportSigningKey::generate("kernel-local", "lease-1").unwrap();
        let verify = key.verification_key().unwrap();
        let permit = SignedLeasePermit {
            schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
            issuer: "kernel-local".into(),
            key_id: "lease-1".into(),
            paseto: "v4.public.not-a-real-token".into(),
        };
        assert_eq!(
            verify.authenticate(&permit).unwrap_err().reason_code(),
            "LEASE_TRANSPORT_INVALID"
        );
    }
}
