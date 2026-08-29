use super::canonical::{canonical_json, decode_canonical, invalid};
use super::claims::{
    validate_candidate_preparation_grant, validate_signed, CandidatePreparationFooter,
    CANDIDATE_PREPARATION_IMPLICIT_ASSERTION,
};
use super::{CandidatePreparationGrantV1, SignedCandidatePreparationGrantV1};
use crate::error::HarnessError;
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;

const SIGNING_KEY_BYTES: usize = 64;
const VERIFICATION_KEY_BYTES: usize = 32;

pub struct CandidatePreparationSigningKey {
    issuer: String,
    key_id: String,
    secret: AsymmetricSecretKey<V4>,
    public_hex: String,
}

impl std::fmt::Debug for CandidatePreparationSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CandidatePreparationSigningKey")
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .field("public_hex", &self.public_hex)
            .finish_non_exhaustive()
    }
}

impl CandidatePreparationSigningKey {
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, HarnessError> {
        let pair = AsymmetricKeyPair::<V4>::generate()
            .map_err(|_| invalid("operating-system entropy unavailable"))?;
        Self::from_bytes(issuer, key_id, pair.secret.as_bytes())
    }

    pub fn from_bytes(issuer: &str, key_id: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        require_key_labels(issuer, key_id)?;
        if bytes.len() != SIGNING_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("signing key must be 64 nonzero bytes"));
        }
        let secret = AsymmetricSecretKey::<V4>::from(bytes)
            .map_err(|_| invalid("invalid Candidate-preparation signing key"))?;
        let public = AsymmetricPublicKey::<V4>::try_from(&secret)
            .map_err(|_| invalid("signing key has no public half"))?;
        Ok(Self {
            issuer: issuer.to_owned(),
            key_id: key_id.to_owned(),
            secret,
            public_hex: hex::encode(public.as_bytes()),
        })
    }

    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_hex
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verification_key(&self) -> Result<CandidatePreparationVerificationKey, HarnessError> {
        CandidatePreparationVerificationKey::from_hex(&self.issuer, &self.key_id, &self.public_hex)
    }

    pub fn sign(
        &self,
        claims: &CandidatePreparationGrantV1,
    ) -> Result<SignedCandidatePreparationGrantV1, HarnessError> {
        validate_candidate_preparation_grant(claims)?;
        if claims.issuer != self.issuer || claims.key_id != self.key_id {
            return Err(invalid("claims issuer/key do not match signing key"));
        }
        let payload = canonical_json(claims)?;
        let footer = canonical_json(&CandidatePreparationFooter::new(&self.issuer, &self.key_id))?;
        let paseto = PublicToken::sign(
            &self.secret,
            &payload,
            Some(&footer),
            Some(CANDIDATE_PREPARATION_IMPLICIT_ASSERTION),
        )
        .map_err(|_| invalid("PASETO signing failed"))?;
        Ok(SignedCandidatePreparationGrantV1 {
            schema_version: "v1alpha1".to_owned(),
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            paseto,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CandidatePreparationVerificationKey {
    issuer: String,
    key_id: String,
    public: AsymmetricPublicKey<V4>,
    public_hex: String,
}

impl CandidatePreparationVerificationKey {
    pub fn from_hex(issuer: &str, key_id: &str, value: &str) -> Result<Self, HarnessError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("verification key must be 64 lowercase hex"));
        }
        let bytes = hex::decode(value).map_err(|_| invalid("verification key hex"))?;
        Self::from_bytes(issuer, key_id, &bytes)
    }

    pub fn from_bytes(issuer: &str, key_id: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        require_key_labels(issuer, key_id)?;
        if bytes.len() != VERIFICATION_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("verification key must be 32 nonzero bytes"));
        }
        let public = AsymmetricPublicKey::<V4>::from(bytes)
            .map_err(|_| invalid("invalid Candidate-preparation verification key"))?;
        Ok(Self {
            issuer: issuer.to_owned(),
            key_id: key_id.to_owned(),
            public,
            public_hex: hex::encode(bytes),
        })
    }

    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_hex
    }

    pub(super) fn authenticate(
        &self,
        signed: &SignedCandidatePreparationGrantV1,
    ) -> Result<CandidatePreparationGrantV1, HarnessError> {
        validate_signed(signed)?;
        if signed.issuer != self.issuer || signed.key_id != self.key_id {
            return Err(HarnessError::CandidatePreparationKeyUnknown {
                issuer: signed.issuer.clone(),
                key_id: signed.key_id.clone(),
            });
        }
        let footer = canonical_json(&CandidatePreparationFooter::new(&self.issuer, &self.key_id))?;
        let untrusted = UntrustedToken::<Public, V4>::try_from(signed.paseto.as_str())
            .map_err(|_| invalid("invalid PASETO framing"))?;
        let trusted = PublicToken::verify(
            &self.public,
            &untrusted,
            Some(&footer),
            Some(CANDIDATE_PREPARATION_IMPLICIT_ASSERTION),
        )
        .map_err(|_| invalid("PASETO signature, footer, or implicit assertion is invalid"))?;
        let claims: CandidatePreparationGrantV1 = decode_canonical(trusted.payload().as_bytes())?;
        validate_candidate_preparation_grant(&claims)?;
        if claims.issuer != self.issuer || claims.key_id != self.key_id {
            return Err(invalid(
                "claims key identity differs from authenticated footer",
            ));
        }
        Ok(claims)
    }
}

/// Authenticate one exact Candidate-preparation carrier with an independently pinned key.
///
/// The returned claims have passed PASETO v4.public signature verification,
/// purpose-separated footer and implicit-assertion checks, recursive canonical
/// decoding, frozen claim validation, and issuer/key binding. Callers must
/// still compare the claims to their own durable subject and consume the nonce.
pub fn authenticate_candidate_preparation_grant(
    signed: &SignedCandidatePreparationGrantV1,
    key: &CandidatePreparationVerificationKey,
) -> Result<CandidatePreparationGrantV1, HarnessError> {
    key.authenticate(signed)
}

fn require_key_labels(issuer: &str, key_id: &str) -> Result<(), HarnessError> {
    for (name, value) in [("issuer", issuer), ("key_id", key_id)] {
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
            })
        {
            return Err(invalid(format!("{name} is outside the frozen label set")));
        }
    }
    Ok(())
}
