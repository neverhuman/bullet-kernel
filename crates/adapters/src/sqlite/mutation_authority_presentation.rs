//! Immutable signed-permit presentation schema and exact read-back. The
//! structural first-use writer is test-only until a trusted verification and
//! durable repository/envelope/nonce binding predecessor exists.

use super::mutation_authority::MutationAuthorityError;
#[cfg(test)]
use super::mutation_authority::{
    exact_permit, load_required, transition, MutationAuthorityRecord, MutationDisposition, Row,
};
use super::{authority, store};
#[cfg(test)]
use super::{lease_time, leases, SqliteLedger};
use bullet_application::NormalizedAuthority;
#[cfg(test)]
use bullet_application::{ActiveLeaseSubject, OneUsePermit};
use bullet_domain::schema_bundle::{
    AuthorityAudienceV1, MutationOperationV1, MutationPermitClaimsV1, SignedMutationPermitV1,
    SCHEMA_VERSION,
};
#[cfg(test)]
use bullet_domain::{AttemptId, RepositoryId, WorkspaceId};
use bullet_domain::{Digest, DomainError};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::OptionalExtension;
#[cfg(test)]
use rusqlite::{params, TransactionBehavior};

#[cfg(test)]
const MAX_SIGNED_ENVELOPE_BYTES: usize = 33_792;
#[cfg(test)]
const MAX_CLAIMS_BYTES: usize = 32_768;
const MAX_PERMIT_TTL_MS: u64 = 1_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(super) fn fingerprint(
    conn: &rusqlite::Connection,
) -> Result<(NormalizedAuthority, u64), bullet_application::LedgerError> {
    let current = authority::current(conn)?;
    let restore_epoch: i64 = conn
        .query_row(
            "SELECT restore_epoch FROM restore_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(mutation_write)?;
    Ok((current, u64::try_from(restore_epoch).map_err(store)?))
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MutationPermitPresentation {
    pub signed_permit_bytes: Vec<u8>,
    pub verified_claims: MutationPermitClaimsV1,
}

/// Immutable exact read-back of the permit presented before repository I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationPermitPresentationRecord {
    pub signed_permit_bytes: Vec<u8>,
    pub permit_digest: String,
    pub claims_bytes: Vec<u8>,
    pub claims_digest: String,
    pub schema_version: String,
    pub issuer: String,
    pub key_id: String,
    pub audience: String,
    pub operation: String,
    pub authority_envelope_digest: String,
    pub authority_token_nonce: String,
    pub permit_nonce: String,
    pub mutation_id: String,
    pub reservation_id: String,
    pub request_digest: String,
    pub repository_id: String,
    pub workspace_id: String,
    pub workspace_generation: u64,
    pub attempt_id: String,
    pub attempt_fence: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
    pub issued_at_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub presented_at: String,
}

#[cfg(test)]
impl SqliteLedger {
    pub(crate) fn present_mutation(
        &mut self,
        subject: &ActiveLeaseSubject,
        permit: &OneUsePermit,
        presentation: &MutationPermitPresentation,
    ) -> Result<MutationAuthorityRecord, MutationAuthorityError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store)?;
        let row = exact_permit(load_required(&tx, &permit.mutation_id)?, subject, permit)?;
        if row.record.disposition == MutationDisposition::Invalidated {
            return Err(MutationAuthorityError::Invalidated(
                permit.reservation_id.clone(),
            ));
        }
        let requires_live_window = row.record.disposition == MutationDisposition::Reserved;
        let prepared = prepare(&tx, &row, presentation, requires_live_window)?;
        if !requires_live_window {
            if row
                .record
                .presentation
                .as_ref()
                .is_some_and(|stored| stored.same_payload(&prepared))
            {
                tx.commit().map_err(store)?;
                return Ok(row.record);
            }
            return Err(MutationAuthorityError::Conflict(permit.mutation_id.clone()));
        }
        leases::check_active_lease_in(&tx, subject)?;
        insert(&tx, &prepared)?;
        transition(&tx, permit, MutationDisposition::Consumed, None)?;
        let record = load_required(&tx, &permit.mutation_id)?.record;
        tx.commit().map_err(store)?;
        Ok(record)
    }
}

#[cfg(test)]
impl MutationPermitPresentationRecord {
    fn same_payload(&self, other: &Self) -> bool {
        let mut normalized = other.clone();
        normalized.presented_at.clone_from(&self.presented_at);
        self == &normalized
    }
}

#[cfg(test)]
fn prepare(
    conn: &rusqlite::Connection,
    row: &Row,
    input: &MutationPermitPresentation,
    require_live_window: bool,
) -> Result<MutationPermitPresentationRecord, MutationAuthorityError> {
    if input.signed_permit_bytes.is_empty()
        || input.signed_permit_bytes.len() > MAX_SIGNED_ENVELOPE_BYTES
    {
        return Err(invalid("signed permit envelope is empty or oversized"));
    }
    let signed: SignedMutationPermitV1 = serde_json::from_slice(&input.signed_permit_bytes)
        .map_err(|_| invalid("signed permit envelope is not the frozen JSON shape"))?;
    let claims = &input.verified_claims;
    let claims_bytes = serde_json::to_vec(claims)
        .map_err(|error| invalid(format!("permit claims cannot be encoded: {error}")))?;
    if claims_bytes.is_empty() || claims_bytes.len() > MAX_CLAIMS_BYTES {
        return Err(invalid("verified permit claims are empty or oversized"));
    }
    validate_envelope(&signed, claims)?;
    validate_claims(row, claims)?;
    let presented_at = lease_time::database_time(conn)?;
    validate_window(claims, &presented_at, require_live_window)?;
    Ok(MutationPermitPresentationRecord {
        signed_permit_bytes: input.signed_permit_bytes.clone(),
        permit_digest: Digest::of(&input.signed_permit_bytes).to_hex(),
        claims_digest: Digest::of(&claims_bytes).to_hex(),
        claims_bytes,
        schema_version: signed.schema_version,
        issuer: signed.issuer,
        key_id: signed.key_id,
        audience: audience_label(claims.audience).into(),
        operation: operation_label(claims.operation).into(),
        authority_envelope_digest: claims.authority_envelope_digest.clone(),
        authority_token_nonce: claims.authority_token_nonce.clone(),
        permit_nonce: claims.permit_nonce.clone(),
        mutation_id: claims.mutation_id.clone(),
        reservation_id: claims.reservation_id.clone(),
        request_digest: claims.request_digest.clone(),
        repository_id: claims.repository_id.clone(),
        workspace_id: claims.workspace_id.clone(),
        workspace_generation: claims.workspace_generation,
        attempt_id: claims.attempt_id.clone(),
        attempt_fence: claims.attempt_fence,
        authority_epoch: claims.authority_epoch,
        freeze_generation: claims.freeze_generation,
        issued_at_unix_ms: claims.issued_at_unix_ms,
        not_before_unix_ms: claims.not_before_unix_ms,
        expires_at_unix_ms: claims.expires_at_unix_ms,
        presented_at,
    })
}

fn validate_envelope(
    signed: &SignedMutationPermitV1,
    claims: &MutationPermitClaimsV1,
) -> Result<(), MutationAuthorityError> {
    if signed.schema_version != SCHEMA_VERSION
        || signed.issuer != claims.issuer
        || !valid_label(&signed.issuer)
        || !valid_label(&signed.key_id)
        || !signed.paseto.starts_with("v4.public.")
        || signed.paseto.len() > 32_768
    {
        return Err(invalid(
            "signed permit envelope does not match verified claims",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_claims(
    row: &Row,
    claims: &MutationPermitClaimsV1,
) -> Result<(), MutationAuthorityError> {
    let permit = &row.record.permit;
    if claims.schema_version != SCHEMA_VERSION
        || !valid_label(&claims.issuer)
        || claims.audience != expected_audience(claims.operation)
        || operation_label(claims.operation) != permit.operation
        || claims.mutation_id != permit.mutation_id
        || claims.reservation_id != permit.reservation_id
        || claims.request_digest != permit.request_digest
        || claims.workspace_id != row.subject.workspace_id
        || claims.attempt_id != row.subject.attempt_id
        || claims.attempt_fence != row.subject.fence
        || claims.workspace_generation != row.record.workspace_generation
        || claims.authority_epoch != row.record.authority_epoch
        || claims.freeze_generation != row.record.freeze_generation
        || RepositoryId::parse(&claims.repository_id).is_err()
        || WorkspaceId::parse(&claims.workspace_id).is_err()
        || AttemptId::parse(&claims.attempt_id).is_err()
    {
        return Err(MutationAuthorityError::Conflict(permit.mutation_id.clone()));
    }
    for digest in [
        &claims.authority_envelope_digest,
        &claims.authority_token_nonce,
        &claims.request_digest,
        &claims.permit_nonce,
    ] {
        if !super::migrations::valid_digest(digest) {
            return Err(invalid("permit digest fields are not canonical"));
        }
    }
    Ok(())
}

fn validate_window(
    claims: &MutationPermitClaimsV1,
    database_now: &str,
    require_live: bool,
) -> Result<(), MutationAuthorityError> {
    let values = [
        claims.workspace_generation,
        claims.attempt_fence,
        claims.authority_epoch,
        claims.freeze_generation,
        claims.issued_at_unix_ms,
        claims.not_before_unix_ms,
        claims.expires_at_unix_ms,
    ];
    if claims.workspace_generation == 0
        || claims.attempt_fence == 0
        || claims.authority_epoch == 0
        || values.into_iter().any(|value| value > MAX_SAFE_INTEGER)
        || claims.issued_at_unix_ms > claims.not_before_unix_ms
        || claims.not_before_unix_ms >= claims.expires_at_unix_ms
        || claims.expires_at_unix_ms - claims.issued_at_unix_ms > MAX_PERMIT_TTL_MS
    {
        return Err(invalid("mutation permit time window is not canonical"));
    }
    let now = DateTime::parse_from_rfc3339(database_now)
        .map_err(|_| invalid("database time is not RFC 3339"))?
        .timestamp_millis();
    let now = u64::try_from(now).map_err(|_| invalid("database time precedes the Unix epoch"))?;
    if require_live && (now < claims.not_before_unix_ms || now >= claims.expires_at_unix_ms) {
        return Err(invalid("mutation permit is not live at database time"));
    }
    Ok(())
}

#[cfg(test)]
fn insert(
    tx: &rusqlite::Transaction<'_>,
    value: &MutationPermitPresentationRecord,
) -> Result<(), MutationAuthorityError> {
    tx.execute(
        "INSERT INTO mutation_permit_presentations (
           mutation_id, reservation_id, operation, request_digest, signed_permit_bytes,
           permit_digest, claims_bytes, claims_digest, schema_version, issuer, key_id,
           audience, authority_envelope_digest, authority_token_nonce, permit_nonce,
           repository_id, workspace_id, workspace_generation, attempt_id, attempt_fence,
           authority_epoch, freeze_generation, issued_at_unix_ms, not_before_unix_ms,
           expires_at_unix_ms, presented_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
           ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26
         )",
        params![
            value.mutation_id,
            value.reservation_id,
            value.operation,
            value.request_digest,
            value.signed_permit_bytes,
            value.permit_digest,
            value.claims_bytes,
            value.claims_digest,
            value.schema_version,
            value.issuer,
            value.key_id,
            value.audience,
            value.authority_envelope_digest,
            value.authority_token_nonce,
            value.permit_nonce,
            value.repository_id,
            value.workspace_id,
            to_i64(value.workspace_generation)?,
            value.attempt_id,
            to_i64(value.attempt_fence)?,
            to_i64(value.authority_epoch)?,
            to_i64(value.freeze_generation)?,
            to_i64(value.issued_at_unix_ms)?,
            to_i64(value.not_before_unix_ms)?,
            to_i64(value.expires_at_unix_ms)?,
            value.presented_at,
        ],
    )
    .map_err(mutation_write)?;
    Ok(())
}

pub(super) fn load(
    conn: &rusqlite::Connection,
    mutation_id: &str,
) -> Result<Option<MutationPermitPresentationRecord>, MutationAuthorityError> {
    let raw = conn
        .query_row(
            "SELECT signed_permit_bytes, permit_digest, claims_bytes, claims_digest,
                    schema_version, issuer, key_id, audience, operation,
                    authority_envelope_digest, authority_token_nonce, permit_nonce,
                    mutation_id, reservation_id, request_digest, repository_id, workspace_id,
                    workspace_generation, attempt_id, attempt_fence, authority_epoch,
                    freeze_generation, issued_at_unix_ms, not_before_unix_ms,
                    expires_at_unix_ms, presented_at
             FROM mutation_permit_presentations WHERE mutation_id = ?1",
            [mutation_id],
            |row| {
                Ok(MutationPermitPresentationRecord {
                    signed_permit_bytes: row.get(0)?,
                    permit_digest: row.get(1)?,
                    claims_bytes: row.get(2)?,
                    claims_digest: row.get(3)?,
                    schema_version: row.get(4)?,
                    issuer: row.get(5)?,
                    key_id: row.get(6)?,
                    audience: row.get(7)?,
                    operation: row.get(8)?,
                    authority_envelope_digest: row.get(9)?,
                    authority_token_nonce: row.get(10)?,
                    permit_nonce: row.get(11)?,
                    mutation_id: row.get(12)?,
                    reservation_id: row.get(13)?,
                    request_digest: row.get(14)?,
                    repository_id: row.get(15)?,
                    workspace_id: row.get(16)?,
                    workspace_generation: read_u64(row, 17)?,
                    attempt_id: row.get(18)?,
                    attempt_fence: read_u64(row, 19)?,
                    authority_epoch: read_u64(row, 20)?,
                    freeze_generation: read_u64(row, 21)?,
                    issued_at_unix_ms: read_u64(row, 22)?,
                    not_before_unix_ms: read_u64(row, 23)?,
                    expires_at_unix_ms: read_u64(row, 24)?,
                    presented_at: row.get(25)?,
                })
            },
        )
        .optional()
        .map_err(store)?;
    if let Some(value) = &raw {
        validate_stored(value)?;
    }
    Ok(raw)
}

fn validate_stored(value: &MutationPermitPresentationRecord) -> Result<(), MutationAuthorityError> {
    let signed: SignedMutationPermitV1 = serde_json::from_slice(&value.signed_permit_bytes)
        .map_err(|_| store("corrupt persisted signed mutation permit"))?;
    let claims: MutationPermitClaimsV1 = serde_json::from_slice(&value.claims_bytes)
        .map_err(|_| store("corrupt persisted mutation permit claims"))?;
    let canonical_time = DateTime::parse_from_rfc3339(&value.presented_at)
        .map(|time| {
            time.with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Millis, true)
        })
        .map_err(|_| store("corrupt mutation permit presentation time"))?;
    if Digest::of(&value.signed_permit_bytes).to_hex() != value.permit_digest
        || Digest::of(&value.claims_bytes).to_hex() != value.claims_digest
        || signed.schema_version != value.schema_version
        || signed.issuer != value.issuer
        || signed.key_id != value.key_id
        || audience_label(claims.audience) != value.audience
        || operation_label(claims.operation) != value.operation
        || claims.authority_envelope_digest != value.authority_envelope_digest
        || claims.authority_token_nonce != value.authority_token_nonce
        || claims.permit_nonce != value.permit_nonce
        || claims.mutation_id != value.mutation_id
        || claims.reservation_id != value.reservation_id
        || claims.request_digest != value.request_digest
        || claims.repository_id != value.repository_id
        || claims.workspace_id != value.workspace_id
        || claims.workspace_generation != value.workspace_generation
        || claims.attempt_id != value.attempt_id
        || claims.attempt_fence != value.attempt_fence
        || claims.authority_epoch != value.authority_epoch
        || claims.freeze_generation != value.freeze_generation
        || claims.issued_at_unix_ms != value.issued_at_unix_ms
        || claims.not_before_unix_ms != value.not_before_unix_ms
        || claims.expires_at_unix_ms != value.expires_at_unix_ms
        || canonical_time != value.presented_at
    {
        return Err(store("corrupt mutation permit presentation").into());
    }
    validate_envelope(&signed, &claims)?;
    validate_window(&claims, &value.presented_at, false)?;
    Ok(())
}

#[cfg(test)]
const fn expected_audience(operation: MutationOperationV1) -> AuthorityAudienceV1 {
    match operation {
        MutationOperationV1::DispatchEffect | MutationOperationV1::ReconcileEffect => {
            AuthorityAudienceV1::EffectBroker
        }
        _ => AuthorityAudienceV1::BulletGitd,
    }
}

const fn audience_label(audience: AuthorityAudienceV1) -> &'static str {
    match audience {
        AuthorityAudienceV1::BulletGitd => "bullet-gitd",
        AuthorityAudienceV1::EffectBroker => "effect-broker",
        AuthorityAudienceV1::ProviderRunner => "provider-runner",
    }
}

const fn operation_label(operation: MutationOperationV1) -> &'static str {
    match operation {
        MutationOperationV1::CloneWorkspace => "clone-workspace",
        MutationOperationV1::ReadWorkspace => "read-workspace",
        MutationOperationV1::ApplyPatch => "apply-patch",
        MutationOperationV1::Checkpoint => "checkpoint",
        MutationOperationV1::PrepareCandidate => "prepare-candidate",
        MutationOperationV1::PreserveWorkspace => "preserve-workspace",
        MutationOperationV1::CleanupWorkspace => "cleanup-workspace",
        MutationOperationV1::DispatchEffect => "dispatch-effect",
        MutationOperationV1::ReconcileEffect => "reconcile-effect",
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn read_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn invalid(detail: impl Into<String>) -> MutationAuthorityError {
    MutationAuthorityError::InvalidRequest(detail.into())
}

pub(super) fn mutation_write(error: rusqlite::Error) -> bullet_application::LedgerError {
    let message = error.to_string();
    if message.contains("stale mutation authority") {
        DomainError::StaleAuthority(message).into()
    } else {
        store(error)
    }
}

pub(super) fn to_i64(value: u64) -> Result<i64, MutationAuthorityError> {
    i64::try_from(value).map_err(|error| MutationAuthorityError::Ledger(store(error)))
}

#[cfg(test)]
#[path = "../../tests/lease_command_atomicity/permit_presentation.rs"]
mod tests;
