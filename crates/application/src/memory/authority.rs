//! Lease acquisition, heartbeat, expiry, and release for the memory ledger.
//! Semantics mirror the SQLite adapter's transactions: every path validates
//! and serializes first, then commits all map mutations together.

use super::{json, MemoryLedger};
use crate::records::{
    ActiveLease, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerEvent, OutboxItem,
    ReleaseRequest, StoredGraph,
};
use crate::store::LedgerError;
use bullet_domain::{
    Attempt, AttemptId, AttemptState, CommandId, CommandPhase, Digest, DomainError, WorkPackageId,
    WorkPackageState,
};

impl MemoryLedger {
    pub(super) fn push_event(
        &mut self,
        kind: &str,
        body: &str,
        stream_id: Option<String>,
        correlation_id: Option<String>,
        authority_token_hash: Option<String>,
    ) {
        let seq = self.events.len() as u64 + 1;
        let event_id = Digest::of(format!("evt:{seq}:{kind}:{body}").as_bytes()).to_hex();
        self.events.push(LedgerEvent {
            seq,
            kind: kind.to_string(),
            body: body.to_string(),
            event_id: Some(event_id),
            stream_id,
            sequence: Some(seq),
            causation_id: None,
            correlation_id,
            authority_token_hash,
        });
    }

    pub(super) fn materialize_graph_impl(
        &mut self,
        graph: &StoredGraph,
        now: &str,
    ) -> Result<(), LedgerError> {
        self.tick()?;
        let key = graph.mission.id.to_string();
        if self.graphs.contains_key(&key) {
            return Err(DomainError::Conflict(format!("graph {key} already materialized")).into());
        }
        self.graphs.insert(key, graph.clone());
        for variant in &graph.variants {
            self.fences.entry(variant.id.to_string()).or_insert(0);
        }
        for package in &graph.packages {
            if package.state == WorkPackageState::Ready {
                self.ready
                    .entry(package.id.to_string())
                    .or_insert_with(|| now.to_string());
            }
        }
        self.push_event(
            "graph_materialized",
            graph.mission.id.as_str(),
            Some(graph.mission.id.to_string()),
            None,
            None,
        );
        Ok(())
    }

    pub(super) fn acquire_lease_impl(
        &mut self,
        req: &LeaseRequest,
    ) -> Result<LeaseGrant, LedgerError> {
        self.tick()?;
        let stable = req.stable_payload()?;
        if let Some(existing) = self.commands.get(&req.idempotency_key) {
            if existing.payload != stable {
                return Err(DomainError::Idempotency(req.idempotency_key.clone()).into());
            }
            let response = existing
                .response
                .as_deref()
                .ok_or_else(|| LedgerError::Store("lease command has no stored result".into()))?;
            return serde_json::from_str(response)
                .map_err(|err| LedgerError::Store(err.to_string()));
        }
        let graph = self
            .graphs
            .get(&req.mission_id.to_string())
            .ok_or_else(|| LedgerError::Store("graph missing".into()))?
            .clone();
        let vidx = graph
            .variants
            .iter()
            .position(|variant| variant.id == req.variant_id)
            .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
        let pidx = graph
            .packages
            .iter()
            .position(|package| package.id == graph.variants[vidx].work_package_id)
            .ok_or_else(|| LedgerError::Store("package missing".into()))?;
        let package = &graph.packages[pidx];
        if package.state != WorkPackageState::Ready {
            return Err(DomainError::Conflict(format!(
                "package {} is {:?}, not ready",
                package.id, package.state
            ))
            .into());
        }
        if !self.ready.contains_key(&package.id.to_string()) {
            return Err(
                DomainError::Conflict(format!("package {} has no ready row", package.id)).into(),
            );
        }
        if let Some(holder) = self.leases.get(&req.variant_id.to_string()) {
            return Err(DomainError::Fence(format!(
                "variant {} already leased to {}",
                req.variant_id, holder.attempt_id
            ))
            .into());
        }
        let fence = self
            .fences
            .get(&req.variant_id.to_string())
            .copied()
            .unwrap_or(0)
            + 1;
        let attempt = Attempt {
            id: AttemptId::from_seed(&req.attempt_seed),
            variant_id: req.variant_id.clone(),
            work_package_id: package.id.clone(),
            fence,
            runner_id: req.runner_id.clone(),
            runner_epoch: req.runner_epoch,
            workspace_id: req.workspace_id.clone(),
            workspace_nonce: req.workspace_nonce,
            scope_revision: req.scope_revision,
            context_revision: req.context_revision,
            state: AttemptState::Starting,
        };
        if self.attempts.contains_key(&attempt.id.to_string()) {
            return Err(
                DomainError::Conflict(format!("attempt {} already exists", attempt.id)).into(),
            );
        }
        let lease = ActiveLease {
            variant_id: req.variant_id.clone(),
            attempt_id: attempt.id.clone(),
            fence,
            runner_id: req.runner_id.clone(),
            runner_epoch: req.runner_epoch,
            workspace_nonce: req.workspace_nonce,
            heartbeat_at: req.now.clone(),
            expires_at: req.expires_at.clone(),
        };
        let mut next_graph = graph;
        next_graph.packages[pidx].state = next_graph.packages[pidx]
            .state
            .transition(WorkPackageState::Leased)?;
        next_graph.variants[vidx].fence_counter = fence;
        let grant = LeaseGrant {
            attempt: attempt.clone(),
            lease: lease.clone(),
        };
        let grant_json = json(&grant)?;
        let token_hash = Digest::of(grant_json.as_bytes()).to_hex();
        // Commit.
        self.fences.insert(req.variant_id.to_string(), fence);
        self.attempts.insert(attempt.id.to_string(), attempt);
        self.leases.insert(req.variant_id.to_string(), lease);
        self.ready.remove(&next_graph.packages[pidx].id.to_string());
        self.graphs
            .insert(next_graph.mission.id.to_string(), next_graph);
        self.push_event(
            "attempt_leased",
            &grant_json,
            Some(req.variant_id.to_string()),
            Some(req.idempotency_key.clone()),
            Some(token_hash),
        );
        let seq = self.outbox.len() as u64 + 1;
        self.outbox.push(OutboxItem {
            seq,
            kind: "dispatch_attempt".into(),
            payload: grant_json.clone(),
            phase: CommandPhase::Pending,
            delivered_at: None,
            acked_at: None,
        });
        self.commands.insert(
            req.idempotency_key.clone(),
            crate::commands::CommandRecord {
                id: CommandId::from_seed(&req.idempotency_key),
                idempotency_key: req.idempotency_key.clone(),
                kind: "acquire_lease".into(),
                payload: stable.clone(),
                payload_digest: Digest::of(stable.as_bytes()),
                phase: CommandPhase::Applied,
                response: Some(grant_json),
            },
        );
        Ok(grant)
    }

    pub(super) fn heartbeat_impl(&mut self, req: &HeartbeatRequest) -> Result<(), LedgerError> {
        self.tick()?;
        if let Some(lease) = self.leases.get_mut(&req.variant_id.to_string()) {
            if lease.attempt_id == req.attempt_id
                && lease.fence == req.fence
                && lease.runner_id == req.runner_id
                && lease.runner_epoch == req.runner_epoch
                && lease.workspace_nonce == req.workspace_nonce
            {
                lease.heartbeat_at = req.now.clone();
                lease.expires_at = req.expires_at.clone();
                return Ok(());
            }
        }
        Err(DomainError::StaleAuthority(format!(
            "heartbeat matched zero lease rows for {}",
            req.attempt_id
        ))
        .into())
    }

    pub(super) fn expire_leases_impl(
        &mut self,
        now: &str,
    ) -> Result<Vec<ExpiredLease>, LedgerError> {
        self.tick()?;
        let expired: Vec<ActiveLease> = self
            .leases
            .values()
            .filter(|lease| lease.expires_at.as_str() < now)
            .cloned()
            .collect();
        let mut out = Vec::new();
        for lease in expired {
            let attempt_key = lease.attempt_id.to_string();
            let attempt = self
                .attempts
                .get(&attempt_key)
                .cloned()
                .ok_or_else(|| LedgerError::Store("lease without attempt".into()))?;
            let next_state = if attempt.state.may_mutate() {
                attempt.state.transition(AttemptState::Crashed)?
            } else {
                attempt.state
            };
            if let Some(stored) = self.attempts.get_mut(&attempt_key) {
                stored.state = next_state;
            }
            self.leases.remove(&lease.variant_id.to_string());
            self.requeue_package(&attempt.work_package_id, now)?;
            self.push_event(
                "lease_expired",
                lease.attempt_id.as_str(),
                Some(lease.variant_id.to_string()),
                None,
                None,
            );
            out.push(ExpiredLease {
                variant_id: lease.variant_id.clone(),
                attempt_id: lease.attempt_id.clone(),
                work_package_id: attempt.work_package_id.clone(),
                fence: lease.fence,
            });
        }
        Ok(out)
    }

    pub(super) fn release_lease_impl(&mut self, req: &ReleaseRequest) -> Result<(), LedgerError> {
        self.tick()?;
        if req.final_state.may_mutate() {
            return Err(DomainError::InvalidTransition {
                from: "release".into(),
                to: format!("{:?}", req.final_state),
            }
            .into());
        }
        let vkey = req.variant_id.to_string();
        match self.leases.get(&vkey).cloned() {
            Some(lease) if lease.attempt_id == req.attempt_id => {
                let attempt = self
                    .attempts
                    .get(&req.attempt_id.to_string())
                    .cloned()
                    .ok_or_else(|| LedgerError::Store("lease without attempt".into()))?;
                let next_state = attempt.state.transition(req.final_state)?;
                if let Some(stored) = self.attempts.get_mut(&req.attempt_id.to_string()) {
                    stored.state = next_state;
                }
                self.leases.remove(&vkey);
                if req.requeue {
                    self.requeue_package(&attempt.work_package_id, &req.now)?;
                }
                self.push_event(
                    "lease_released",
                    req.attempt_id.as_str(),
                    Some(vkey),
                    None,
                    None,
                );
                Ok(())
            }
            Some(lease) => Err(DomainError::StaleAuthority(format!(
                "lease held by {}, not {}",
                lease.attempt_id, req.attempt_id
            ))
            .into()),
            None => match self.attempts.get(&req.attempt_id.to_string()) {
                Some(attempt) if attempt.state == req.final_state => Ok(()),
                _ => Err(DomainError::StaleAuthority(format!(
                    "no active lease for {}",
                    req.attempt_id
                ))
                .into()),
            },
        }
    }

    pub(super) fn put_attempt_impl(&mut self, attempt: &Attempt) -> Result<(), LedgerError> {
        self.tick()?;
        let key = attempt.id.to_string();
        let existing = self.attempts.get(&key).cloned().ok_or_else(|| {
            LedgerError::Domain(DomainError::Conflict(format!(
                "attempt {} does not exist; attempts are created by acquire_lease",
                attempt.id
            )))
        })?;
        if existing.variant_id != attempt.variant_id
            || existing.work_package_id != attempt.work_package_id
            || existing.fence != attempt.fence
            || existing.runner_id != attempt.runner_id
            || existing.runner_epoch != attempt.runner_epoch
            || existing.workspace_id != attempt.workspace_id
            || existing.workspace_nonce != attempt.workspace_nonce
        {
            return Err(DomainError::Conflict(format!(
                "attempt {} identity columns are immutable",
                attempt.id
            ))
            .into());
        }
        if existing.state != attempt.state {
            existing.state.transition(attempt.state)?;
        }
        self.attempts.insert(key, attempt.clone());
        Ok(())
    }

    fn requeue_package(&mut self, package: &WorkPackageId, now: &str) -> Result<(), LedgerError> {
        for graph in self.graphs.values_mut() {
            if let Some(idx) = graph.packages.iter().position(|p| p.id == *package) {
                let current = graph.packages[idx].state;
                if let Ok(next) = current.transition(WorkPackageState::Ready) {
                    graph.packages[idx].state = next;
                    self.ready
                        .entry(package.to_string())
                        .or_insert_with(|| now.to_string());
                }
                return Ok(());
            }
        }
        Err(LedgerError::Store(format!(
            "package {package} not in any graph"
        )))
    }
}
