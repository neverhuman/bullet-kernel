use super::{
    CandidatePreparationError, CandidatePreparationSource, CandidatePreparationStore,
    PreparedCandidatePreparationGrant, StoredCandidatePreparationGrant,
};
use bullet_domain::{AttemptId, RunnerId};
use bullet_harness_core::candidate_preparation::{
    validate_candidate_preparation_binding, CandidatePreparationGrantV1,
    CandidatePreparationSigningKey, CANDIDATE_PREPARATION_CLAIMS_DOMAIN,
    CANDIDATE_PREPARATION_ENVELOPE_DOMAIN, CANDIDATE_PREPARATION_SIGNING_PURPOSE,
};
use bullet_harness_core::launch_grant::random_hex_64;

pub trait CandidatePreparationIssuer {
    fn mint(
        &mut self,
        request_digest: &str,
    ) -> Result<StoredCandidatePreparationGrant, CandidatePreparationError>;
}

pub struct LedgerCandidatePreparationIssuer<'a, S> {
    store: &'a mut S,
    key: &'a CandidatePreparationSigningKey,
}

impl<'a, S: CandidatePreparationStore> LedgerCandidatePreparationIssuer<'a, S> {
    #[must_use]
    pub fn new(store: &'a mut S, key: &'a CandidatePreparationSigningKey) -> Self {
        Self { store, key }
    }

    /// Mint or replay only for the authenticated workload incarnation.
    ///
    /// The Attempt and Runner checks execute inside the store transaction and
    /// precede every grant, event, or outbox insertion.
    pub fn mint_for_workload(
        &mut self,
        request_digest: &str,
        attempt_id: &AttemptId,
        runner_id: &RunnerId,
        runner_epoch: u64,
    ) -> Result<StoredCandidatePreparationGrant, CandidatePreparationError> {
        self.mint_bound(
            request_digest,
            Some(WorkloadSubject {
                attempt_id,
                runner_id,
                runner_epoch,
            }),
        )
    }

    fn mint_bound(
        &mut self,
        request_digest: &str,
        workload: Option<WorkloadSubject<'_>>,
    ) -> Result<StoredCandidatePreparationGrant, CandidatePreparationError> {
        let key = self.key;
        self.store.with_candidate_preparation(|txn| {
            if let Some(existing) = txn.get_issued(request_digest)? {
                require_workload_record(&existing, workload)?;
                if workload.is_some() {
                    let registered = require_registered(txn, request_digest, workload)?;
                    txn.require_parent_candidates(&registered.source)?;
                    let authority = txn.authority_snapshot(&registered.source.attempt_id)?;
                    require_workload_authority(&authority, workload)?;
                    require_current_source(&registered.source, &authority)?;
                }
                return Ok(existing);
            }
            let registered = require_registered(txn, request_digest, workload)?;
            txn.require_parent_candidates(&registered.source)?;
            let authority = txn.authority_snapshot(&registered.source.attempt_id)?;
            require_workload_authority(&authority, workload)?;
            let record = build_record(&registered.source, request_digest, &authority, key)?;
            let prepared = PreparedCandidatePreparationGrant::new(record);
            txn.put_issued(&prepared)?;
            Ok(prepared.into_record())
        })
    }
}

impl<S: CandidatePreparationStore> CandidatePreparationIssuer
    for LedgerCandidatePreparationIssuer<'_, S>
{
    fn mint(
        &mut self,
        request_digest: &str,
    ) -> Result<StoredCandidatePreparationGrant, CandidatePreparationError> {
        self.mint_bound(request_digest, None)
    }
}

#[derive(Clone, Copy)]
struct WorkloadSubject<'a> {
    attempt_id: &'a AttemptId,
    runner_id: &'a RunnerId,
    runner_epoch: u64,
}

fn require_registered(
    txn: &mut dyn super::CandidatePreparationTransaction,
    request_digest: &str,
    workload: Option<WorkloadSubject<'_>>,
) -> Result<super::RegisteredCandidatePreparationSource, CandidatePreparationError> {
    let registered = txn
        .get_source(request_digest)?
        .ok_or(CandidatePreparationError::SourceMissing)?;
    if registered.request_digest != registered.source.request_digest()?
        || registered.request_digest != request_digest
    {
        return Err(CandidatePreparationError::Refused(
            "registered request digest is corrupt".to_owned(),
        ));
    }
    if workload.is_some_and(|subject| registered.source.attempt_id != *subject.attempt_id) {
        return Err(workload_refused());
    }
    Ok(registered)
}

fn require_workload_record(
    record: &StoredCandidatePreparationGrant,
    workload: Option<WorkloadSubject<'_>>,
) -> Result<(), CandidatePreparationError> {
    if workload.is_some_and(|subject| {
        record.grant.attempt_id != subject.attempt_id.as_str()
            || record.grant.runner_id != subject.runner_id.as_str()
            || record.grant.runner_epoch != subject.runner_epoch
    }) {
        return Err(workload_refused());
    }
    Ok(())
}

fn require_workload_authority(
    authority: &super::CandidatePreparationAuthoritySnapshot,
    workload: Option<WorkloadSubject<'_>>,
) -> Result<(), CandidatePreparationError> {
    if workload.is_some_and(|subject| {
        authority.attempt_id != subject.attempt_id.as_str()
            || authority.runner_id != subject.runner_id.as_str()
            || authority.runner_epoch != subject.runner_epoch
    }) {
        return Err(workload_refused());
    }
    Ok(())
}

fn workload_refused() -> CandidatePreparationError {
    CandidatePreparationError::Refused(
        "authenticated workload differs from the durable Attempt incarnation".to_owned(),
    )
}

fn build_record(
    source: &CandidatePreparationSource,
    request_digest: &str,
    authority: &super::CandidatePreparationAuthoritySnapshot,
    key: &CandidatePreparationSigningKey,
) -> Result<StoredCandidatePreparationGrant, CandidatePreparationError> {
    require_current_source(source, authority)?;
    let envelope = &source.execution_envelope;
    let requested_expiry = authority
        .now_unix_ms
        .checked_add(source.ttl_ms)
        .ok_or_else(|| CandidatePreparationError::Refused("grant expiry overflows".to_owned()))?;
    let expires_at_unix_ms = requested_expiry
        .min(authority.lease_expires_at_unix_ms)
        .min(envelope.expires_at_unix_ms);
    if expires_at_unix_ms <= authority.now_unix_ms {
        return Err(CandidatePreparationError::Refused(
            "durable authority expires before the grant opens".to_owned(),
        ));
    }
    let grant = CandidatePreparationGrantV1 {
        schema_version: "v1alpha1".to_owned(),
        candidate_preparation_grant_id: format!("cpg_{}", random_hex_64()?),
        issuer: key.issuer().to_owned(),
        key_id: key.key_id().to_owned(),
        signing_purpose: CANDIDATE_PREPARATION_SIGNING_PURPOSE.to_owned(),
        claims_domain: CANDIDATE_PREPARATION_CLAIMS_DOMAIN.to_owned(),
        envelope_domain: CANDIDATE_PREPARATION_ENVELOPE_DOMAIN.to_owned(),
        request_digest: request_digest.to_owned(),
        authority_token_digest: authority.authority_token_digest.clone(),
        grant_nonce: random_hex_64()?,
        repository_id: authority.repository_id.clone(),
        mission_id: authority.mission_id.clone(),
        plan_revision_id: authority.plan_revision_id.clone(),
        work_package_id: authority.work_package_id.clone(),
        variant_id: authority.variant_id.clone(),
        attempt_id: authority.attempt_id.clone(),
        attempt_fence: authority.attempt_fence,
        runner_id: authority.runner_id.clone(),
        runner_epoch: authority.runner_epoch,
        workspace_id: authority.workspace_id.clone(),
        scope_grant_digest: authority.scope_grant_digest.clone(),
        scope_revision: authority.scope_revision,
        context_revision: authority.context_revision,
        change_id: source.change_id.clone(),
        graph_revision_id: authority.graph_revision_id.clone(),
        parent_candidate_ids: source.parent_candidate_ids.clone(),
        context_capsule_id: authority.context_capsule_id.clone(),
        execution_envelope_id: envelope.execution_envelope_id.clone(),
        environment_digest: envelope.environment_digest.clone(),
        toolchain_digest: envelope.toolchain_digest.clone(),
        authority_epoch: authority.authority_epoch,
        freeze_generation: authority.freeze_generation,
        issued_at_unix_ms: authority.now_unix_ms,
        not_before_unix_ms: authority.now_unix_ms,
        expires_at_unix_ms,
    };
    validate_candidate_preparation_binding(&grant, envelope)?;
    let signed = key.sign(&grant)?;
    StoredCandidatePreparationGrant::from_records(grant, signed, envelope)
}

fn require_current_source(
    source: &CandidatePreparationSource,
    authority: &super::CandidatePreparationAuthoritySnapshot,
) -> Result<(), CandidatePreparationError> {
    source.validate()?;
    let envelope = &source.execution_envelope;
    if source.attempt_id.as_str() != authority.attempt_id
        || envelope.runner_id != authority.runner_id
        || envelope.runner_epoch != authority.runner_epoch
        || envelope.authority_epoch != authority.authority_epoch
        || envelope.freeze_generation != authority.freeze_generation
        || authority.now_unix_ms < envelope.issued_at_unix_ms
        || authority.now_unix_ms >= envelope.expires_at_unix_ms
    {
        return Err(CandidatePreparationError::Refused(
            "execution envelope differs from current durable authority".to_owned(),
        ));
    }
    Ok(())
}
