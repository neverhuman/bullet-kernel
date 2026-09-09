use super::CandidatePreparationError;
use bullet_domain::AttemptId;
use bullet_harness_core::candidate_preparation::{
    candidate_preparation_envelope_digest, canonical_candidate_preparation_json,
    decode_signed_candidate_preparation_grant, validate_candidate_preparation_binding,
    validate_execution_envelope, CandidatePreparationGrantV1, ExecutionEnvelopeV1,
    SignedCandidatePreparationGrantV1,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const SOURCE_SCHEMA: &str = "v1alpha1";
const SOURCE_DIGEST_DOMAIN: &str = "candidate-preparation.request.v1alpha1";
const FRAMED_DOMAIN_PREFIX: &[u8] = b"bullet-wire.v1\0";
const MAX_TTL_MS: u64 = 15_000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePreparationSource {
    pub schema_version: String,
    pub attempt_id: AttemptId,
    pub root_change: bool,
    pub change_id: String,
    pub parent_candidate_ids: Vec<String>,
    pub execution_envelope: ExecutionEnvelopeV1,
    pub ttl_ms: u64,
}

impl CandidatePreparationSource {
    pub fn validate(&self) -> Result<(), CandidatePreparationError> {
        if self.schema_version != SOURCE_SCHEMA {
            return Err(refused("source schema is not v1alpha1"));
        }
        require_id("change_id", &self.change_id, "chg")?;
        if self.root_change != self.parent_candidate_ids.is_empty() {
            return Err(refused(
                "root_change must be explicit exactly when the parent list is empty",
            ));
        }
        if self.parent_candidate_ids.len() > 128 {
            return Err(refused("parent Candidate list exceeds 128"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for parent in &self.parent_candidate_ids {
            require_id("parent_candidate_id", parent, "can")?;
            if !seen.insert(parent) {
                return Err(refused("parent Candidate list contains a duplicate"));
            }
        }
        if !(1..=MAX_TTL_MS).contains(&self.ttl_ms) {
            return Err(refused("ttl_ms must be within 1..=15000"));
        }
        validate_execution_envelope(&self.execution_envelope)?;
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, CandidatePreparationError> {
        self.validate()?;
        hash_canonical(SOURCE_DIGEST_DOMAIN, self)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CandidatePreparationError> {
        self.validate()?;
        canonical(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CandidatePreparationError> {
        let value: Self = decode_canonical(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredCandidatePreparationSource {
    pub request_digest: String,
    pub source: CandidatePreparationSource,
    pub registered_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidatePreparationAuthoritySnapshot {
    pub repository_id: String,
    pub mission_id: String,
    pub plan_revision_id: String,
    pub work_package_id: String,
    pub variant_id: String,
    pub attempt_id: String,
    pub attempt_fence: u64,
    pub runner_id: String,
    pub runner_epoch: u64,
    pub workspace_id: String,
    pub scope_grant_digest: String,
    pub scope_revision: u64,
    pub context_revision: u64,
    pub graph_revision_id: String,
    pub context_capsule_id: String,
    pub authority_token_digest: String,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredCandidatePreparationGrant {
    pub grant: CandidatePreparationGrantV1,
    pub signed: SignedCandidatePreparationGrantV1,
    pub claims_bytes: Vec<u8>,
    pub signed_bytes: Vec<u8>,
    pub envelope_digest: String,
}

pub struct PreparedCandidatePreparationGrant {
    record: StoredCandidatePreparationGrant,
}

impl PreparedCandidatePreparationGrant {
    pub(crate) fn new(record: StoredCandidatePreparationGrant) -> Self {
        Self { record }
    }

    #[must_use]
    pub fn record(&self) -> &StoredCandidatePreparationGrant {
        &self.record
    }

    pub(crate) fn into_record(self) -> StoredCandidatePreparationGrant {
        self.record
    }
}

impl StoredCandidatePreparationGrant {
    pub fn from_records(
        grant: CandidatePreparationGrantV1,
        signed: SignedCandidatePreparationGrantV1,
        envelope: &ExecutionEnvelopeV1,
    ) -> Result<Self, CandidatePreparationError> {
        validate_candidate_preparation_binding(&grant, envelope)?;
        let claims_bytes = canonical(&grant)?;
        let signed_bytes = canonical(&signed)?;
        let envelope_digest = candidate_preparation_envelope_digest(&signed)?;
        Ok(Self {
            grant,
            signed,
            claims_bytes,
            signed_bytes,
            envelope_digest,
        })
    }

    pub fn validate(
        &self,
        envelope: &ExecutionEnvelopeV1,
    ) -> Result<(), CandidatePreparationError> {
        validate_candidate_preparation_binding(&self.grant, envelope)?;
        if canonical(&self.grant)? != self.claims_bytes
            || canonical(&self.signed)? != self.signed_bytes
            || decode_canonical::<CandidatePreparationGrantV1>(&self.claims_bytes)? != self.grant
            || decode_signed_candidate_preparation_grant(&self.signed_bytes)? != self.signed
            || candidate_preparation_envelope_digest(&self.signed)? != self.envelope_digest
            || self.signed.issuer != self.grant.issuer
            || self.signed.key_id != self.grant.key_id
        {
            return Err(refused("stored grant canonical binding is corrupt"));
        }
        Ok(())
    }
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, CandidatePreparationError> {
    canonical_candidate_preparation_json(value).map_err(Into::into)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CandidatePreparationError> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(refused("canonical document is empty or exceeds 64 KiB"));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| refused(format!("strict record decode: {error}")))?;
    if canonical(&value)? != bytes {
        return Err(refused("record is not RFC 8785 canonical JSON"));
    }
    Ok(value)
}

fn hash_canonical<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, CandidatePreparationError> {
    let bytes = canonical(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(FRAMED_DOMAIN_PREFIX);
    for subject in [domain.as_bytes(), bytes.as_slice()] {
        hasher.update(
            &u64::try_from(subject.len())
                .map_err(|_| refused("canonical subject length overflow"))?
                .to_le_bytes(),
        );
        hasher.update(subject);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn require_id(name: &str, value: &str, prefix: &str) -> Result<(), CandidatePreparationError> {
    let valid = value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(|body| {
            body.len() == 64
                && body
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if valid {
        Ok(())
    } else {
        Err(refused(format!("{name} is not a full-width {prefix} id")))
    }
}

fn refused(reason: impl Into<String>) -> CandidatePreparationError {
    CandidatePreparationError::Refused(reason.into())
}
