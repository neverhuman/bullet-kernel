//! Transaction-local lease-transport port.
//!
//! Every method here reads or writes the ONE store transaction opened by
//! [`crate::store::Ledger::with_lease_transport`]: no second connection, no
//! pre-transaction snapshot, and lease time is the store's own clock. A
//! caller that resolves graph, authority, Attempt, and lease truth through
//! this port and only then mutates never carries a stale observation into
//! its write.

use crate::authority::ActiveLeaseSubject;
use crate::authority_revision::NormalizedAuthority;
use crate::lease_transport::{LeaseGrantRecord, LeaseSettlementRecord};
use crate::records::{
    ActiveLease, HeartbeatRequest, LeaseGrant, LeaseRequest, ReleaseRequest, StoredGraph,
};
use crate::store::{LedgerError, NonceConsumption};
use bullet_domain::{
    Attempt, AttemptId, DomainError, Mission, PlanRevision, Variant, VariantId, WorkPackage,
    WorkPackageId,
};

/// One work package resolved against the store's current graph inside the
/// open transaction: the Mission that owns it, the plan that materialized
/// it, the package row as currently stored, and its single Variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentPackage {
    /// Owning Mission as currently stored.
    pub mission: Mission,
    /// Plan revision that materialized the package.
    pub plan: PlanRevision,
    /// Package row as currently stored (state included).
    pub package: WorkPackage,
    /// The package's single Variant, carrying the current fence counter.
    pub variant: Variant,
}

impl CurrentPackage {
    /// Locate `package` inside one stored graph. `Ok(None)` when the graph
    /// does not own the package; a store failure when the graph owns the
    /// package but not exactly one Variant for it.
    ///
    /// # Errors
    /// Store failure for a graph whose package has zero or several Variants.
    pub fn from_graph(
        graph: &StoredGraph,
        package: &WorkPackageId,
    ) -> Result<Option<Self>, LedgerError> {
        let Some(found) = graph.packages.iter().find(|row| row.id == *package) else {
            return Ok(None);
        };
        let mut variants = graph
            .variants
            .iter()
            .filter(|variant| variant.work_package_id == *package);
        let (Some(variant), None) = (variants.next(), variants.next()) else {
            return Err(LedgerError::Store(format!(
                "package {package} does not have exactly one variant in graph {}",
                graph.mission.id
            )));
        };
        Ok(Some(Self {
            mission: graph.mission.clone(),
            plan: graph.plan.clone(),
            package: found.clone(),
            variant: variant.clone(),
        }))
    }

    /// Locate one exact selected Variant for `package`. Other Variants for
    /// the same package are allowed; absence is stale authority and duplicate
    /// identity is corrupt graph truth.
    ///
    /// # Errors
    /// Stale authority for a non-member; store failure for duplicate identity.
    pub fn from_graph_variant(
        graph: &StoredGraph,
        package: &WorkPackageId,
        selected: &VariantId,
    ) -> Result<Option<Self>, LedgerError> {
        let mut matches = graph
            .variants
            .iter()
            .filter(|variant| variant.id == *selected);
        let variant = matches.next();
        if matches.next().is_some() {
            return Err(LedgerError::Store(format!(
                "variant {selected} is duplicated in graph {}",
                graph.mission.id
            )));
        }
        let Some(found) = graph.packages.iter().find(|row| row.id == *package) else {
            return Ok(None);
        };
        let variant = variant.ok_or_else(|| {
            DomainError::StaleAuthority(format!(
                "variant {selected} is not a member of work package {package}"
            ))
        })?;
        if variant.work_package_id != *package {
            return Err(DomainError::StaleAuthority(format!(
                "variant {selected} is not a member of work package {package}"
            ))
            .into());
        }
        Ok(Some(Self {
            mission: graph.mission.clone(),
            plan: graph.plan.clone(),
            package: found.clone(),
            variant: variant.clone(),
        }))
    }

    /// Typed refusal for a package that no current graph owns.
    #[must_use]
    pub fn unknown(package: &WorkPackageId) -> LedgerError {
        DomainError::StaleAuthority(format!(
            "work package {package} is not in any current graph"
        ))
        .into()
    }
}

/// Exact incarnation subject for `attempt` at `fence`, derived from the
/// Attempt row loaded inside the open transaction. Refuses a missing Attempt
/// or a fence that differs from the durable one, so the subsequent
/// authoritative-clock check runs against the durable incarnation only.
///
/// # Errors
/// `STALE_AUTHORITY` when the Attempt is unknown or its durable fence is not
/// `fence`.
pub fn incarnation_subject(
    stored: Option<Attempt>,
    attempt: &AttemptId,
    fence: u64,
) -> Result<ActiveLeaseSubject, LedgerError> {
    let stored = stored
        .ok_or_else(|| DomainError::StaleAuthority(format!("no Attempt {attempt} in the store")))?;
    if stored.id != *attempt || stored.fence != fence {
        return Err(DomainError::StaleAuthority(format!(
            "Attempt {attempt} fence {fence} does not match durable fence {}",
            stored.fence
        ))
        .into());
    }
    Ok(ActiveLeaseSubject::from_attempt(&stored))
}

/// Mutations and reads that belong in the signed lease-transport transaction.
pub trait LeaseTransportTxn {
    /// Persist one unused permit nonce bound to its operation subject.
    ///
    /// # Errors
    /// Store failure or a duplicate nonce.
    fn reserve_transport_nonce(
        &mut self,
        nonce: &str,
        binding: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), LedgerError>;

    /// Consume one reserved nonce exactly once.
    ///
    /// # Errors
    /// Store failure.
    fn consume_transport_nonce(
        &mut self,
        nonce: &str,
        binding: &str,
        now_unix_ms: u64,
    ) -> Result<NonceConsumption, LedgerError>;

    /// Acquire or replay one writer lease.
    ///
    /// # Errors
    /// Typed fence/idempotency errors or store failure.
    fn acquire_lease(&mut self, request: &LeaseRequest) -> Result<LeaseGrant, LedgerError>;

    /// Renew one live lease.
    ///
    /// # Errors
    /// `StaleAuthority` or store failure.
    fn heartbeat(&mut self, request: &HeartbeatRequest) -> Result<(), LedgerError>;

    /// Close one lease.
    ///
    /// # Errors
    /// `StaleAuthority` or store failure.
    fn release_lease(&mut self, request: &ReleaseRequest) -> Result<(), LedgerError>;

    /// Apply one legal attempt transition.
    ///
    /// # Errors
    /// Typed transition errors or store failure.
    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError>;

    /// Load one attempt.
    ///
    /// # Errors
    /// Store failure.
    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError>;

    /// Resolve one work package against the store's current graph as this
    /// transaction sees it.
    ///
    /// # Errors
    /// `STALE_AUTHORITY` when no current graph owns the package; store
    /// failure for corrupt graph truth.
    fn resolve_package(&self, package: &WorkPackageId) -> Result<CurrentPackage, LedgerError>;

    /// Resolve one exact Variant member for a package while allowing sibling
    /// Variants in the same SelectionGroup.
    ///
    /// # Errors
    /// Stale authority for an unknown package/non-member; store failure for
    /// corrupt graph truth.
    fn resolve_variant(
        &self,
        package: &WorkPackageId,
        variant: &VariantId,
    ) -> Result<CurrentPackage, LedgerError>;

    /// The singleton normalized authority row as this transaction sees it.
    ///
    /// # Errors
    /// Store failure or a missing/invalid durable row.
    fn current_authority(&self) -> Result<NormalizedAuthority, LedgerError>;

    /// The active lease held by exactly this Attempt incarnation. `None`
    /// before acquisition, after release or expiry reclaim, and when another
    /// Attempt now holds the Variant's lease.
    ///
    /// # Errors
    /// Store failure.
    fn get_lease(&self, attempt: &AttemptId) -> Result<Option<ActiveLease>, LedgerError>;

    /// Prove that `attempt` at `fence` still holds a live lease at the
    /// store's own clock: load the durable Attempt, require the exact fence,
    /// then run the authoritative-clock active check against the stored
    /// lease/Attempt pair. Success is an observation inside this
    /// transaction, never a capability that outlives it.
    ///
    /// # Errors
    /// `STALE_AUTHORITY` for an unknown Attempt, a fence mismatch, a released
    /// or reclaimed lease, an expired lease, or an Attempt state that no
    /// longer permits the check; store failure for corrupt persisted state.
    fn check_active_lease(&self, attempt: &AttemptId, fence: u64) -> Result<(), LedgerError>;

    /// Persist the strict versioned grant record for an acquire idempotency
    /// digest as its canonical [`LeaseGrantRecord::encode`] bytes, inside the
    /// acquire transaction. Writing the identical record again is a no-op.
    ///
    /// # Errors
    /// Store failure, a different record already under the digest, or a row
    /// under the digest that does not decode as exactly one current record
    /// ([`LeaseGrantRecord::refused`]).
    fn put_transport_grant(
        &mut self,
        idempotency_digest: &str,
        record: &LeaseGrantRecord,
    ) -> Result<(), LedgerError>;

    /// Load the grant record for an acquire idempotency digest through the
    /// strict [`LeaseGrantRecord::decode`]: exact version, no unknown field,
    /// canonical bytes, agreeing rows. There is no fallback parser: a legacy
    /// bare grant or any other deviation is [`LeaseGrantRecord::refused`].
    ///
    /// # Errors
    /// Store failure; the fixed refusal for a row that is not one current
    /// record.
    fn get_transport_grant(
        &self,
        idempotency_digest: &str,
    ) -> Result<Option<LeaseGrantRecord>, LedgerError>;

    /// Append one strict immutable settlement plus its correlated audit event.
    ///
    /// Identical replay is a no-op. A different or malformed row under the
    /// same typed identity is refused. The row and event belong to this exact
    /// transaction.
    ///
    /// # Errors
    /// Store failure or immutable-record conflict.
    fn put_transport_settlement(
        &mut self,
        record: &LeaseSettlementRecord,
    ) -> Result<(), LedgerError>;

    /// Strictly decode one immutable settlement row.
    ///
    /// # Errors
    /// Fixed store refusal for a malformed or internally inconsistent row.
    fn get_transport_settlement(
        &self,
        settlement_id: &str,
    ) -> Result<Option<LeaseSettlementRecord>, LedgerError>;
}

impl LeaseGrantRecord {
    /// The port's one refusal for a `grant_json` row that is not exactly one
    /// current record: `STORE_FAILURE` with a fixed text. Nothing about the
    /// row — its shape, version, or content — is disclosed.
    #[must_use]
    pub fn refused() -> LedgerError {
        LedgerError::Store("lease-transport grant record refused".into())
    }
}
