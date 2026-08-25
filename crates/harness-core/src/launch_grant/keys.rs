//! PASETO v4.public signing and verification keys for launch grants. The
//! cryptography is delegated to `pasetors`; this module only binds the key
//! identity, footer, and implicit assertion exactly.

use super::canonical::{canonical_json, decode_canonical, is_lower_hex_64};
use super::claims::{
    validate_label, LaunchGrantClaims, LaunchGrantFooter, SignedLaunchGrant,
    LAUNCH_GRANT_IMPLICIT_ASSERTION, LAUNCH_GRANT_SCHEMA_VERSION,
};
use crate::error::HarnessError;
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;

/// Raw byte length of one v4.public secret key (seed plus public half).
pub const SIGNING_KEY_BYTES: usize = 64;
/// Raw byte length of one v4.public public key.
pub const VERIFICATION_KEY_BYTES: usize = 32;

/// Operator-held issuing key. Never serialized; only its public half leaves.
pub struct LaunchGrantSigningKey {
    issuer: String,
    key_id: String,
    secret: AsymmetricSecretKey<V4>,
    public_hex: String,
}

impl std::fmt::Debug for LaunchGrantSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchGrantSigningKey")
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .field("public_hex", &self.public_hex)
            .finish_non_exhaustive()
    }
}

impl LaunchGrantSigningKey {
    /// Generate a fresh key pair from operating-system entropy.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for a bad label or an entropy failure.
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, HarnessError> {
        validate_label("issuer", issuer)?;
        validate_label("key_id", key_id)?;
        let pair = AsymmetricKeyPair::<V4>::generate()
            .map_err(|_| invalid("operating-system entropy unavailable for key generation"))?;
        Self::from_bytes(issuer, key_id, pair.secret.as_bytes())
    }

    /// Load exactly 64 raw secret-key bytes.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for a bad label or malformed key.
    pub fn from_bytes(issuer: &str, key_id: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        validate_label("issuer", issuer)?;
        validate_label("key_id", key_id)?;
        if bytes.len() != SIGNING_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("PASETO v4.public secret keys are 64 nonzero bytes"));
        }
        let secret =
            AsymmetricSecretKey::<V4>::from(bytes).map_err(|_| invalid("invalid signing key"))?;
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

    /// Lowercase hex of the 32-byte public key (what policy publishes).
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_hex
    }

    /// Raw 64 secret bytes, for the 0600 operator key file only.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }

    /// Matching verification key.
    ///
    /// # Errors
    ///
    /// Never in practice; the public half was derived from this secret.
    pub fn verification_key(&self) -> Result<LaunchGrantVerificationKey, HarnessError> {
        LaunchGrantVerificationKey::from_hex(&self.issuer, &self.key_id, &self.public_hex)
    }

    /// Sign validated claims whose issuer/key labels equal this key's.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for an invalid shape, label mismatch, or
    /// signing failure.
    pub fn sign(&self, claims: &LaunchGrantClaims) -> Result<SignedLaunchGrant, HarnessError> {
        claims.validate_shape()?;
        if claims.issuer != self.issuer || claims.key_id != self.key_id {
            return Err(invalid("claims issuer/key_id do not match the signing key"));
        }
        let payload = canonical_json(claims)?;
        let footer = canonical_json(&LaunchGrantFooter::new(&self.issuer, &self.key_id))?;
        let paseto = PublicToken::sign(
            &self.secret,
            &payload,
            Some(&footer),
            Some(LAUNCH_GRANT_IMPLICIT_ASSERTION),
        )
        .map_err(|_| invalid("PASETO signing failed"))?;
        Ok(SignedLaunchGrant {
            schema_version: LAUNCH_GRANT_SCHEMA_VERSION.to_string(),
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            paseto,
        })
    }
}

/// Policy-published public key for one `(issuer, key_id)`.
#[derive(Clone, Debug)]
pub struct LaunchGrantVerificationKey {
    issuer: String,
    key_id: String,
    public: AsymmetricPublicKey<V4>,
    public_hex: String,
}

impl LaunchGrantVerificationKey {
    /// Parse the 64-hex raw public key form used by `IssuerKeyV1.public_key`.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for a bad label or key encoding.
    pub fn from_hex(issuer: &str, key_id: &str, public_hex: &str) -> Result<Self, HarnessError> {
        if !is_lower_hex_64(public_hex) {
            return Err(invalid(
                "verification key must be 64 lowercase hex characters",
            ));
        }
        let bytes = hex::decode(public_hex).map_err(|_| invalid("verification key hex"))?;
        Self::from_bytes(issuer, key_id, &bytes)
    }

    /// Load exactly 32 raw public-key bytes.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_INVALID` for a bad label or malformed key.
    pub fn from_bytes(issuer: &str, key_id: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        validate_label("issuer", issuer)?;
        validate_label("key_id", key_id)?;
        if bytes.len() != VERIFICATION_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("PASETO v4.public public keys are 32 nonzero bytes"));
        }
        let public = AsymmetricPublicKey::<V4>::from(bytes)
            .map_err(|_| invalid("invalid verification key"))?;
        Ok(Self {
            issuer: issuer.to_string(),
            key_id: key_id.to_string(),
            public,
            public_hex: hex::encode(bytes),
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

    /// Lowercase hex public key.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_hex
    }

    /// Authenticate the token (signature, footer, implicit assertion) and
    /// strictly decode its claims. Time, subject, policy, and nonce checks
    /// are deliberately not performed here.
    pub(crate) fn authenticate(
        &self,
        grant: &SignedLaunchGrant,
    ) -> Result<LaunchGrantClaims, HarnessError> {
        grant.validate_envelope()?;
        if grant.issuer != self.issuer || grant.key_id != self.key_id {
            return Err(HarnessError::LaunchGrantKeyUnknown {
                issuer: grant.issuer.clone(),
                key_id: grant.key_id.clone(),
                reason: "envelope names a different key than the one selected from policy"
                    .to_string(),
            });
        }
        let footer = canonical_json(&LaunchGrantFooter::new(&self.issuer, &self.key_id))?;
        let untrusted = UntrustedToken::<Public, V4>::try_from(grant.paseto.as_str())
            .map_err(|_| invalid("invalid PASETO framing"))?;
        let trusted = PublicToken::verify(
            &self.public,
            &untrusted,
            Some(&footer),
            Some(LAUNCH_GRANT_IMPLICIT_ASSERTION),
        )
        .map_err(|_| invalid("PASETO signature, footer, or implicit assertion is invalid"))?;
        let claims = decode_canonical::<LaunchGrantClaims>(trusted.payload().as_bytes())?;
        claims.validate_shape()?;
        if claims.issuer != self.issuer || claims.key_id != self.key_id {
            return Err(invalid(
                "signed claims issuer/key_id do not match the footer",
            ));
        }
        Ok(claims)
    }
}

fn invalid(reason: &str) -> HarnessError {
    HarnessError::LaunchGrantInvalid {
        reason: reason.to_string(),
    }
}
