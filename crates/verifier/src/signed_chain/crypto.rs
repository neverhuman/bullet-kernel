use super::{invalid, SignedChainError};
use crate::signed_chain::records::SignedRecordV1;
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical, validate_label};
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub(super) const INTENT_PURPOSE: &str = "verification-intent-signing";
pub(super) const EVIDENCE_PURPOSE: &str = "verification-evidence-signing";
pub(super) const PROOF_PURPOSE: &str = "verification-proof-bundle-signing";
pub(super) const INTENT_ASSERTION: &str = "bullet-farm.verification-intent.v1";
pub(super) const EVIDENCE_ASSERTION: &str = "bullet-farm.evidence.v1";
pub(super) const PROOF_ASSERTION: &str = "bullet-farm.proof-bundle.v1";

pub(super) struct RoleSigningKey {
    pub(super) issuer: String,
    pub(super) key_id: String,
    secret: AsymmetricSecretKey<V4>,
    public: AsymmetricPublicKey<V4>,
}

impl std::fmt::Debug for RoleSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleSigningKey")
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl RoleSigningKey {
    pub(super) fn generate(issuer: &str, key_id: &str) -> Result<Self, SignedChainError> {
        validate_label("issuer", issuer).map_err(|error| invalid(error.to_string()))?;
        validate_label("key_id", key_id).map_err(|error| invalid(error.to_string()))?;
        let pair = AsymmetricKeyPair::<V4>::generate()
            .map_err(|_| invalid("operating-system entropy unavailable"))?;
        let public = AsymmetricPublicKey::<V4>::try_from(&pair.secret)
            .map_err(|_| invalid("signing key has no public half"))?;
        Ok(Self {
            issuer: issuer.to_owned(),
            key_id: key_id.to_owned(),
            secret: pair.secret,
            public,
        })
    }

    pub(super) fn verification_key(&self) -> RoleVerificationKey {
        RoleVerificationKey {
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            public: self.public.clone(),
            public_hex: hex::encode(self.public.as_bytes()),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct RoleVerificationKey {
    pub(super) issuer: String,
    pub(super) key_id: String,
    public: AsymmetricPublicKey<V4>,
    pub(super) public_hex: String,
}

impl RoleVerificationKey {
    pub(super) fn from_public_hex(
        issuer: &str,
        key_id: &str,
        public_hex: &str,
    ) -> Result<Self, SignedChainError> {
        validate_label("issuer", issuer).map_err(|error| invalid(error.to_string()))?;
        validate_label("key_id", key_id).map_err(|error| invalid(error.to_string()))?;
        if public_hex.len() != 64
            || !public_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("verification public key must be 64 lowercase hex"));
        }
        let bytes = hex::decode(public_hex).map_err(|_| invalid("invalid public-key hex"))?;
        let public = AsymmetricPublicKey::<V4>::from(&bytes)
            .map_err(|_| invalid("invalid PASETO v4.public verification key"))?;
        Ok(Self {
            issuer: issuer.to_owned(),
            key_id: key_id.to_owned(),
            public,
            public_hex: public_hex.to_owned(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Footer<'a> {
    schema_version: &'a str,
    purpose: &'a str,
    issuer: &'a str,
    key_id: &'a str,
}

pub(super) fn sign_record<T>(
    key: &RoleSigningKey,
    record: T,
    envelope_schema: &str,
    purpose: &str,
    assertion: &str,
) -> Result<SignedRecordV1<T>, SignedChainError>
where
    T: Serialize,
{
    let payload = canonical_json(&record).map_err(|error| invalid(error.to_string()))?;
    let footer = canonical_json(&Footer {
        schema_version: envelope_schema,
        purpose,
        issuer: &key.issuer,
        key_id: &key.key_id,
    })
    .map_err(|error| invalid(error.to_string()))?;
    let paseto = PublicToken::sign(
        &key.secret,
        &payload,
        Some(&footer),
        Some(assertion.as_bytes()),
    )
    .map_err(|_| invalid("PASETO v4.public signing failed"))?;
    Ok(SignedRecordV1 {
        schema_version: envelope_schema.to_owned(),
        issuer: key.issuer.clone(),
        key_id: key.key_id.clone(),
        paseto,
        record,
    })
}

pub(super) fn verify_record<T>(
    signed: &SignedRecordV1<T>,
    key: &RoleVerificationKey,
    envelope_schema: &str,
    purpose: &str,
    assertion: &str,
) -> Result<T, SignedChainError>
where
    T: Clone + DeserializeOwned + Eq + Serialize,
{
    if signed.schema_version != envelope_schema
        || signed.issuer != key.issuer
        || signed.key_id != key.key_id
    {
        return Err(SignedChainError::SigningKeyMismatch);
    }
    let footer = canonical_json(&Footer {
        schema_version: envelope_schema,
        purpose,
        issuer: &key.issuer,
        key_id: &key.key_id,
    })
    .map_err(|error| invalid(error.to_string()))?;
    let token = UntrustedToken::<Public, V4>::try_from(signed.paseto.as_str())
        .map_err(|_| SignedChainError::SignatureInvalid)?;
    let trusted = PublicToken::verify(
        &key.public,
        &token,
        Some(&footer),
        Some(assertion.as_bytes()),
    )
    .map_err(|_| SignedChainError::SignatureInvalid)?;
    let record = decode_canonical::<T>(trusted.payload().as_bytes())
        .map_err(|_| SignedChainError::SignatureInvalid)?;
    if record != signed.record {
        return Err(SignedChainError::SignatureInvalid);
    }
    Ok(record)
}
