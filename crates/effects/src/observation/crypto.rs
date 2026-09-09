use super::validation::{
    derive_readback, observation_id, validate_identity, validate_record, validate_subject,
    validate_window,
};
use super::{
    invalid, ObservationError, ObservationInputV1, ObservationSubjectV1, ObservationV1,
    SignedObservationV1, COMPONENT_CLASS, ENVELOPE_SCHEMA, FIXTURE_TRUST, IMPLICIT_ASSERTION,
    OBSERVATION_SCHEMA, SIGNING_PURPOSE,
};
use crate::ForgeIntegration;
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical, is_lower_hex_64};
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;
use serde::{Deserialize, Serialize};

/// Ephemeral component observer signing key.
pub struct FixtureObserverSigningKey {
    issuer: String,
    key_id: String,
    secret: AsymmetricSecretKey<V4>,
    public: AsymmetricPublicKey<V4>,
}

impl std::fmt::Debug for FixtureObserverSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixtureObserverSigningKey")
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Expected observer public key reconstructed outside the signed envelope.
#[derive(Clone, Debug)]
pub struct FixtureObserverVerificationKey {
    issuer: String,
    key_id: String,
    public: AsymmetricPublicKey<V4>,
    public_hex: String,
}

impl FixtureObserverSigningKey {
    /// Generate one fixture-only purpose key.
    pub fn generate(issuer: &str, key_id: &str) -> Result<Self, ObservationError> {
        validate_identity(issuer, key_id)?;
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

    /// Matching expected public key.
    #[must_use]
    pub fn verification_key(&self) -> FixtureObserverVerificationKey {
        FixtureObserverVerificationKey {
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            public: self.public.clone(),
            public_hex: hex::encode(self.public.as_bytes()),
        }
    }

    /// Read the exact target and sign the derived four-valued result.
    pub fn observe<F: ForgeIntegration>(
        &self,
        forge: &F,
        input: ObservationInputV1,
        observed_at_unix_ms: u64,
    ) -> Result<SignedObservationV1, ObservationError> {
        validate_subject(&input.subject)?;
        let fresh_until_unix_ms = validate_window(observed_at_unix_ms, input.freshness_window_ms)?;
        let (outcome, observed_oid, reason) = derive_readback(
            forge.read_target(&input.subject.target),
            &input.subject.integrated_oid,
        );
        let integration_survived = outcome == super::ObservationOutcomeV1::Matched;
        let mut record = ObservationV1 {
            schema_version: OBSERVATION_SCHEMA.into(),
            evidence_class: COMPONENT_CLASS.into(),
            signing_trust: FIXTURE_TRUST.into(),
            independent_evidence_eligible: false,
            transaction_gate_eligible: false,
            release_gate_eligible: false,
            observation_id: String::new(),
            subject: input.subject,
            outcome,
            observed_oid,
            readback_reason_code: reason,
            integration_survived,
            observed_at_unix_ms,
            fresh_until_unix_ms,
            observer_service_id: self.issuer.clone(),
            observer_key_id: self.key_id.clone(),
        };
        record.observation_id = observation_id(&record)?;
        validate_record(&record, &self.issuer, &self.key_id, None)?;
        sign(&self.secret, &self.issuer, &self.key_id, record)
    }
}

impl FixtureObserverVerificationKey {
    /// Reconstruct one externally expected public key from canonical bytes.
    pub fn from_public_hex(
        issuer: &str,
        key_id: &str,
        public_hex: &str,
    ) -> Result<Self, ObservationError> {
        validate_identity(issuer, key_id)?;
        if !is_lower_hex_64(public_hex) {
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

    /// Canonical public half as 64 lowercase hex.
    #[must_use]
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// Authenticate one exact subject within its current freshness window.
    pub fn verify(
        &self,
        signed: &SignedObservationV1,
        expected: &ObservationSubjectV1,
        now_unix_ms: u64,
    ) -> Result<ObservationV1, ObservationError> {
        if signed.schema_version != ENVELOPE_SCHEMA
            || signed.issuer != self.issuer
            || signed.key_id != self.key_id
        {
            return Err(ObservationError::SigningKeyMismatch);
        }
        let footer = footer(&self.issuer, &self.key_id)?;
        let token = UntrustedToken::<Public, V4>::try_from(signed.paseto.as_str())
            .map_err(|_| ObservationError::SignatureInvalid)?;
        let trusted = PublicToken::verify(
            &self.public,
            &token,
            Some(&footer),
            Some(IMPLICIT_ASSERTION.as_bytes()),
        )
        .map_err(|_| ObservationError::SignatureInvalid)?;
        let record = decode_canonical::<ObservationV1>(trusted.payload().as_bytes())
            .map_err(|_| ObservationError::SignatureInvalid)?;
        if record != signed.record {
            return Err(ObservationError::SignatureInvalid);
        }
        validate_record(
            &record,
            &self.issuer,
            &self.key_id,
            Some((expected, now_unix_ms)),
        )?;
        Ok(record)
    }
}

/// Canonical bytes for retained component evidence.
pub fn canonical_observation_bytes(
    signed: &SignedObservationV1,
) -> Result<Vec<u8>, ObservationError> {
    canonical_json(signed).map_err(|error| invalid(error.to_string()))
}

/// Canonically decode, authenticate, and exact-subject-check one observation.
pub fn decode_and_verify_fixture_observation(
    bytes: &[u8],
    key: &FixtureObserverVerificationKey,
    expected: &ObservationSubjectV1,
    now_unix_ms: u64,
) -> Result<SignedObservationV1, ObservationError> {
    let signed = decode_canonical::<SignedObservationV1>(bytes)
        .map_err(|error| invalid(error.to_string()))?;
    key.verify(&signed, expected, now_unix_ms)?;
    Ok(signed)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Footer<'a> {
    schema_version: &'a str,
    purpose: &'a str,
    issuer: &'a str,
    key_id: &'a str,
}

fn sign(
    secret: &AsymmetricSecretKey<V4>,
    issuer: &str,
    key_id: &str,
    record: ObservationV1,
) -> Result<SignedObservationV1, ObservationError> {
    let payload = canonical_json(&record).map_err(|error| invalid(error.to_string()))?;
    let footer = footer(issuer, key_id)?;
    let paseto = PublicToken::sign(
        secret,
        &payload,
        Some(&footer),
        Some(IMPLICIT_ASSERTION.as_bytes()),
    )
    .map_err(|_| invalid("PASETO v4.public signing failed"))?;
    Ok(SignedObservationV1 {
        schema_version: ENVELOPE_SCHEMA.into(),
        issuer: issuer.into(),
        key_id: key_id.into(),
        paseto,
        record,
    })
}

fn footer(issuer: &str, key_id: &str) -> Result<Vec<u8>, ObservationError> {
    canonical_json(&Footer {
        schema_version: ENVELOPE_SCHEMA,
        purpose: SIGNING_PURPOSE,
        issuer,
        key_id,
    })
    .map_err(|error| invalid(error.to_string()))
}
