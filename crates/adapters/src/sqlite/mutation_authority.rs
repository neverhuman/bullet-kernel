//! Durable one-use repository mutation authority.

use super::{lease_time, leases, migrations, mutation_authority_presentation, store, SqliteLedger};
use bullet_application::{ActiveLeaseSubject, LedgerError, MutationReserveRequest, OneUsePermit};
use bullet_domain::Digest;
use mutation_authority_presentation::{mutation_write, to_i64};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use thiserror::Error;

pub use mutation_authority_presentation::MutationPermitPresentationRecord;

/// Durable state of one exact mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationDisposition {
    /// Admitted but not yet presented at the mutation boundary.
    Reserved,
    /// Presented exactly once; repository I/O may be in flight.
    Consumed,
    /// Authoritative read-back proved the requested mutation result.
    Settled,
    /// I/O may have happened, but authoritative read-back is unresolved.
    Unknown,
    /// Authority changed before first use, so no I/O was authorized.
    Invalidated,
}

impl MutationDisposition {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "RESERVED",
            Self::Consumed => "CONSUMED",
            Self::Settled => "SETTLED",
            Self::Unknown => "UNKNOWN",
            Self::Invalidated => "INVALIDATED",
        }
    }

    fn parse(value: &str) -> Result<Self, LedgerError> {
        match value {
            "RESERVED" => Ok(Self::Reserved),
            "CONSUMED" => Ok(Self::Consumed),
            "SETTLED" => Ok(Self::Settled),
            "UNKNOWN" => Ok(Self::Unknown),
            "INVALIDATED" => Ok(Self::Invalidated),
            _ => Err(store("corrupt mutation authority disposition")),
        }
    }
}

/// A terminal result recorded only after the repository mutation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationCompletion {
    /// Exact authoritative read-back matched the requested mutation.
    Settled { result_digest: String },
    /// Authoritative read-back could not determine whether mutation occurred.
    Unknown { observation_digest: String },
    /// The wire has an aborted outcome, but durable rollback semantics are not
    /// yet agreed. It is always refused without changing durable state.
    Aborted { observation_digest: String },
}

impl MutationCompletion {
    fn parts(&self) -> Result<(MutationDisposition, &str), MutationAuthorityError> {
        match self {
            Self::Settled { result_digest } => Ok((MutationDisposition::Settled, result_digest)),
            Self::Unknown { observation_digest } => {
                Ok((MutationDisposition::Unknown, observation_digest))
            }
            Self::Aborted { .. } => Err(MutationAuthorityError::UnsupportedOutcome(
                "aborted mutation settlement has no admitted durable semantics".into(),
            )),
        }
    }
}

/// Exact durable read-back for one mutation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationAuthorityRecord {
    /// Stable one-use permit fields shared with the application layer.
    pub permit: OneUsePermit,
    /// Current durable disposition.
    pub disposition: MutationDisposition,
    /// Result or ambiguity observation digest for a terminal I/O state.
    pub completion_digest: Option<String>,
    /// Graph revision bound when reserved.
    pub graph_revision: u64,
    /// Workspace generation bound when reserved.
    pub workspace_generation: u64,
    /// Exact scope digest bound when reserved.
    pub scope_digest: String,
    /// Policy generation bound when reserved.
    pub policy_generation: u64,
    /// Routing generation bound when reserved.
    pub routing_generation: u64,
    /// Authority epoch bound when reserved.
    pub authority_epoch: u64,
    /// Freeze generation bound when reserved.
    pub freeze_generation: u64,
    /// Restore epoch bound when reserved.
    pub restore_epoch: u64,
    /// Exact immutable presentation, once the permit crossed the boundary.
    pub presentation: Option<MutationPermitPresentationRecord>,
}

/// Fail-closed durable mutation authority error.
#[derive(Debug, Error)]
pub enum MutationAuthorityError {
    /// Durable store or active-lease failure.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Mutation identity was replayed with different exact inputs.
    #[error("mutation authority replay conflict: {0}")]
    Conflict(String),
    /// Mutation identity has no durable reservation.
    #[error("mutation authority not found: {0}")]
    NotFound(String),
    /// The requested transition is not legal from the durable disposition.
    #[error("mutation authority state {state} refuses {operation}")]
    IllegalState { state: String, operation: String },
    /// Authority changed before first use.
    #[error("mutation authority invalidated: {0}")]
    Invalidated(String),
    /// Request fields are empty, oversized, or not canonical digests.
    #[error("invalid mutation authority request: {0}")]
    InvalidRequest(String),
    /// A generated wire outcome has no admitted durable mapping yet.
    #[error("unsupported mutation outcome: {0}")]
    UnsupportedOutcome(String),
}

impl MutationAuthorityError {
    /// Stable machine reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Ledger(error) => error.reason_code(),
            Self::Conflict(_) => "MUTATION_AUTHORITY_CONFLICT",
            Self::NotFound(_) => "MUTATION_AUTHORITY_NOT_FOUND",
            Self::IllegalState { .. } => "MUTATION_AUTHORITY_STATE_ILLEGAL",
            Self::Invalidated(_) => "MUTATION_AUTHORITY_INVALIDATED",
            Self::InvalidRequest(_) => "MUTATION_AUTHORITY_INVALID_REQUEST",
            Self::UnsupportedOutcome(_) => "MUTATION_ABORTED_UNSUPPORTED",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Row {
    pub(super) record: MutationAuthorityRecord,
    pub(super) subject: Subject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Subject {
    variant_id: String,
    pub(super) attempt_id: String,
    work_package_id: String,
    pub(super) fence: u64,
    runner_id: String,
    runner_epoch: u64,
    pub(super) workspace_id: String,
    workspace_nonce: Vec<u8>,
    scope_revision: u64,
    context_revision: u64,
}

impl Subject {
    pub(super) fn from_active(value: &ActiveLeaseSubject) -> Self {
        Self {
            variant_id: value.variant_id.to_string(),
            attempt_id: value.attempt_id.to_string(),
            work_package_id: value.work_package_id.to_string(),
            fence: value.fence,
            runner_id: value.runner_id.to_string(),
            runner_epoch: value.runner_epoch,
            workspace_id: value.workspace_id.to_string(),
            workspace_nonce: value.workspace_nonce.to_vec(),
            scope_revision: value.scope_revision,
            context_revision: value.context_revision,
        }
    }
}

impl SqliteLedger {
    /// Reserve one exact mutation after rechecking the active lease inside the
    /// same immediate transaction. Exact replay returns durable disposition.
    pub fn reserve_mutation(
        &mut self,
        subject: &ActiveLeaseSubject,
        request: &MutationReserveRequest,
    ) -> Result<MutationAuthorityRecord, MutationAuthorityError> {
        if !migrations::valid_mutation_contract(
            &request.mutation_id,
            &request.operation,
            &request.request_digest,
        ) {
            return Err(MutationAuthorityError::InvalidRequest(
                "mutation id, operation, or request digest is not canonical".into(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store)?;
        if let Some(row) = load(&tx, &request.mutation_id)? {
            exact_request(&row, subject, request)?;
            if row.record.disposition == MutationDisposition::Reserved {
                leases::check_active_lease_in(&tx, subject)?;
            }
            tx.commit().map_err(store)?;
            return Ok(row.record);
        }
        leases::check_active_lease_in(&tx, subject)?;
        let (authority, restore_epoch) = mutation_authority_presentation::fingerprint(&tx)?;
        let permit = OneUsePermit {
            reservation_id: format!(
                "rsv_{}",
                Digest::of(request.mutation_id.as_bytes()).to_hex()
            ),
            mutation_id: request.mutation_id.clone(),
            operation: request.operation.clone(),
            request_digest: request.request_digest.clone(),
        };
        let now = lease_time::database_time(&tx)?;
        let bound = Subject::from_active(subject);
        tx.execute(
            "INSERT INTO mutation_authority (
               reservation_id, mutation_id, operation, request_digest,
               variant_id, attempt_id, work_package_id, fence, runner_id, runner_epoch,
               workspace_id, workspace_nonce, scope_revision, context_revision,
               authority_epoch, freeze_generation, restore_epoch, disposition,
               completion_digest, created_at, updated_at, graph_revision,
               workspace_generation, scope_digest, policy_generation, routing_generation
             ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
               ?15, ?16, ?17, 'RESERVED', NULL, ?18, ?18, ?19, ?20, ?21, ?22, ?23
             )",
            params![
                permit.reservation_id,
                permit.mutation_id,
                permit.operation,
                permit.request_digest,
                bound.variant_id,
                bound.attempt_id,
                bound.work_package_id,
                to_i64(bound.fence)?,
                bound.runner_id,
                to_i64(bound.runner_epoch)?,
                bound.workspace_id,
                bound.workspace_nonce,
                to_i64(bound.scope_revision)?,
                to_i64(bound.context_revision)?,
                to_i64(authority.authority_epoch())?,
                to_i64(authority.freeze_generation())?,
                to_i64(restore_epoch)?,
                now,
                to_i64(authority.graph_revision())?,
                to_i64(authority.workspace_generation())?,
                authority.scope_digest(),
                to_i64(authority.policy_generation())?,
                to_i64(authority.routing_generation())?,
            ],
        )
        .map_err(mutation_write)?;
        let record = load(&tx, &request.mutation_id)?
            .ok_or_else(|| store("inserted mutation authority row is absent"))?
            .record;
        tx.commit().map_err(store)?;
        Ok(record)
    }

    /// Record authoritative post-I/O read-back. Exact terminal replay is
    /// idempotent; a conflicting result or transition refuses.
    pub fn complete_mutation(
        &mut self,
        subject: &ActiveLeaseSubject,
        permit: &OneUsePermit,
        completion: &MutationCompletion,
    ) -> Result<MutationAuthorityRecord, MutationAuthorityError> {
        let (next, digest) = completion.parts()?;
        if !migrations::valid_digest(digest) {
            return Err(MutationAuthorityError::InvalidRequest(
                "completion digest is not canonical".into(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store)?;
        let row = exact_permit(load_required(&tx, &permit.mutation_id)?, subject, permit)?;
        if row.record.disposition == next && row.record.completion_digest.as_deref() == Some(digest)
        {
            tx.commit().map_err(store)?;
            return Ok(row.record);
        }
        if row.record.disposition != MutationDisposition::Consumed {
            return Err(illegal(row.record.disposition, "complete"));
        }
        transition(&tx, permit, next, Some(digest))?;
        let record = load_required(&tx, &permit.mutation_id)?.record;
        tx.commit().map_err(store)?;
        Ok(record)
    }

    /// Read the exact durable disposition without granting mutation authority.
    pub fn mutation_disposition(
        &self,
        mutation_id: &str,
    ) -> Result<Option<MutationAuthorityRecord>, MutationAuthorityError> {
        Ok(load(&self.conn, mutation_id)?.map(|row| row.record))
    }
}

struct RawRow {
    reservation_id: String,
    mutation_id: String,
    operation: String,
    request_digest: String,
    disposition: String,
    completion_digest: Option<String>,
    graph_revision: i64,
    workspace_generation: i64,
    scope_digest: String,
    policy_generation: i64,
    routing_generation: i64,
    authority_epoch: i64,
    freeze_generation: i64,
    restore_epoch: i64,
    variant_id: String,
    attempt_id: String,
    work_package_id: String,
    fence: i64,
    runner_id: String,
    runner_epoch: i64,
    workspace_id: String,
    workspace_nonce: Vec<u8>,
    scope_revision: i64,
    context_revision: i64,
}

pub(super) fn load(
    conn: &rusqlite::Connection,
    mutation_id: &str,
) -> Result<Option<Row>, MutationAuthorityError> {
    let raw = conn
        .query_row(
            "SELECT reservation_id, mutation_id, operation, request_digest, disposition,
                    completion_digest, graph_revision, workspace_generation, scope_digest,
                    policy_generation, routing_generation, authority_epoch, freeze_generation,
                    restore_epoch, variant_id, attempt_id, work_package_id, fence, runner_id,
                    runner_epoch, workspace_id, workspace_nonce, scope_revision, context_revision
             FROM mutation_authority WHERE mutation_id = ?1",
            [mutation_id],
            |row| {
                Ok(RawRow {
                    reservation_id: row.get(0)?,
                    mutation_id: row.get(1)?,
                    operation: row.get(2)?,
                    request_digest: row.get(3)?,
                    disposition: row.get(4)?,
                    completion_digest: row.get(5)?,
                    graph_revision: row.get(6)?,
                    workspace_generation: row.get(7)?,
                    scope_digest: row.get(8)?,
                    policy_generation: row.get(9)?,
                    routing_generation: row.get(10)?,
                    authority_epoch: row.get(11)?,
                    freeze_generation: row.get(12)?,
                    restore_epoch: row.get(13)?,
                    variant_id: row.get(14)?,
                    attempt_id: row.get(15)?,
                    work_package_id: row.get(16)?,
                    fence: row.get(17)?,
                    runner_id: row.get(18)?,
                    runner_epoch: row.get(19)?,
                    workspace_id: row.get(20)?,
                    workspace_nonce: row.get(21)?,
                    scope_revision: row.get(22)?,
                    context_revision: row.get(23)?,
                })
            },
        )
        .optional()
        .map_err(store)?;
    let Some(raw) = raw else { return Ok(None) };
    let parsed = Row {
        record: MutationAuthorityRecord {
            permit: OneUsePermit {
                reservation_id: raw.reservation_id,
                mutation_id: raw.mutation_id,
                operation: raw.operation,
                request_digest: raw.request_digest,
            },
            disposition: MutationDisposition::parse(&raw.disposition)?,
            completion_digest: raw.completion_digest,
            graph_revision: u64::try_from(raw.graph_revision).map_err(store)?,
            workspace_generation: u64::try_from(raw.workspace_generation).map_err(store)?,
            scope_digest: raw.scope_digest,
            policy_generation: u64::try_from(raw.policy_generation).map_err(store)?,
            routing_generation: u64::try_from(raw.routing_generation).map_err(store)?,
            authority_epoch: u64::try_from(raw.authority_epoch).map_err(store)?,
            freeze_generation: u64::try_from(raw.freeze_generation).map_err(store)?,
            restore_epoch: u64::try_from(raw.restore_epoch).map_err(store)?,
            presentation: mutation_authority_presentation::load(conn, mutation_id)?,
        },
        subject: Subject {
            variant_id: raw.variant_id,
            attempt_id: raw.attempt_id,
            work_package_id: raw.work_package_id,
            fence: u64::try_from(raw.fence).map_err(store)?,
            runner_id: raw.runner_id,
            runner_epoch: u64::try_from(raw.runner_epoch).map_err(store)?,
            workspace_id: raw.workspace_id,
            workspace_nonce: raw.workspace_nonce,
            scope_revision: u64::try_from(raw.scope_revision).map_err(store)?,
            context_revision: u64::try_from(raw.context_revision).map_err(store)?,
        },
    };
    migrations::validate_mutation_row(conn, mutation_id)?;
    Ok(Some(parsed))
}

pub(super) fn load_required(
    conn: &rusqlite::Connection,
    mutation_id: &str,
) -> Result<Row, MutationAuthorityError> {
    load(conn, mutation_id)?.ok_or_else(|| MutationAuthorityError::NotFound(mutation_id.into()))
}

fn exact_request(
    row: &Row,
    subject: &ActiveLeaseSubject,
    request: &MutationReserveRequest,
) -> Result<(), MutationAuthorityError> {
    if row.record.permit.mutation_id != request.mutation_id
        || row.record.permit.operation != request.operation
        || row.record.permit.request_digest != request.request_digest
        || row.subject != Subject::from_active(subject)
    {
        return Err(MutationAuthorityError::Conflict(
            request.mutation_id.clone(),
        ));
    }
    Ok(())
}

pub(super) fn exact_permit(
    row: Row,
    subject: &ActiveLeaseSubject,
    permit: &OneUsePermit,
) -> Result<Row, MutationAuthorityError> {
    if row.record.permit != *permit || row.subject != Subject::from_active(subject) {
        return Err(MutationAuthorityError::Conflict(permit.mutation_id.clone()));
    }
    Ok(row)
}

pub(super) fn transition(
    tx: &Transaction<'_>,
    permit: &OneUsePermit,
    next: MutationDisposition,
    digest: Option<&str>,
) -> Result<(), MutationAuthorityError> {
    let now = lease_time::database_time(tx)?;
    let changed = tx
        .execute(
            "UPDATE mutation_authority
             SET disposition = ?1, completion_digest = ?2, updated_at = ?3
             WHERE mutation_id = ?4 AND reservation_id = ?5",
            params![
                next.as_str(),
                digest,
                now,
                permit.mutation_id,
                permit.reservation_id
            ],
        )
        .map_err(mutation_write)?;
    if changed != 1 {
        return Err(MutationAuthorityError::NotFound(permit.mutation_id.clone()));
    }
    Ok(())
}

pub(super) fn illegal(state: MutationDisposition, operation: &str) -> MutationAuthorityError {
    MutationAuthorityError::IllegalState {
        state: state.as_str().into(),
        operation: operation.into(),
    }
}
