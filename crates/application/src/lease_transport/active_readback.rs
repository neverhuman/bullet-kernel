//! Transaction-local readback that returns only a currently active grant.

use super::mint::{grant_truth, idempotency_digest};
use super::{not_active, KernelLeaseTransport, SignedAcquireBody, SignedLeaseError};
use crate::records::LeaseGrant;
use crate::store::{LeaseTransportTxn, Ledger};
use bullet_harness_core::lease_transport::LeaseTransportOperation;

impl KernelLeaseTransport {
    /// Return the strict recorded grant only while its exact Attempt/fence is active.
    ///
    /// Archival [`Self::readback`] deliberately remains available after expiry or
    /// supersession. Recovery callers must use this method before treating the
    /// returned grant as execution authority.
    ///
    /// # Errors
    /// Typed transport refusal, `LEASE_TRANSPORT_GRANT_ABSENT` when no record exists,
    /// or `LEASE_NOT_ACTIVE` when the recorded incarnation is no longer active.
    pub fn readback_active<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        let digest = idempotency_digest(&body.idempotency_key)?;
        let prepare = |txn: &dyn LeaseTransportTxn| {
            let row = txn
                .get_transport_grant(&digest)?
                .ok_or(SignedLeaseError::GrantAbsent)?;
            let (expected, truth) =
                grant_truth(txn, LeaseTransportOperation::Readback, body, now_unix_ms).map_err(
                    |error| match error {
                        SignedLeaseError::Unknown => SignedLeaseError::NotActive {
                            reason: "recorded grant package no longer resolves".into(),
                        },
                        other => other,
                    },
                )?;
            Ok((expected, (truth, row)))
        };
        self.admit(ledger, prepare, |txn, _expected, (truth, row)| {
            let grant = truth.bind_row(row)?.grant;
            txn.check_active_lease(&grant.attempt.id, grant.attempt.fence)
                .map_err(not_active)?;
            Ok(grant)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{materialize_plan, Ledger, MemoryLedger, PlanInput, ReleaseRequest};
    use bullet_domain::{AttemptState, RunnerId, TaskClass};

    const NOW: u64 = 1_700_000_000_000;

    fn fixture() -> (MemoryLedger, KernelLeaseTransport, SignedAcquireBody) {
        let mut ledger = MemoryLedger::new();
        let now = ledger.simulation_time();
        let plan = PlanInput {
            title: "active readback".into(),
            objective: "reconcile exact active authority".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        };
        let graph = materialize_plan(&mut ledger, "active-readback", &plan, &now).unwrap();
        let body = SignedAcquireBody {
            work_package_id: graph.packages[0].id.clone(),
            runner_id: RunnerId::from_seed("active-readback-runner"),
            runner_epoch: 7,
            idempotency_key: "active-readback-key".into(),
            ttl_seconds: 15,
        };
        (ledger, KernelLeaseTransport::generate().unwrap(), body)
    }

    #[test]
    fn active_readback_returns_only_the_exact_live_grant() {
        let (mut ledger, kernel, body) = fixture();
        let acquired = kernel.acquire(&mut ledger, &body, NOW).unwrap();
        let recovered = kernel.readback_active(&mut ledger, &body, NOW).unwrap();
        assert_eq!(recovered.attempt.id, acquired.attempt.id);
        assert_eq!(recovered.lease.fence, acquired.lease.fence);
    }

    #[test]
    fn exact_missing_grant_row_has_a_distinct_absence_code() {
        let (mut ledger, kernel, body) = fixture();
        let error = kernel.readback_active(&mut ledger, &body, NOW).unwrap_err();
        assert_eq!(error.reason_code(), "LEASE_TRANSPORT_GRANT_ABSENT");
    }

    #[test]
    fn recorded_grant_with_unresolvable_current_package_is_not_absence() {
        let (mut ledger, kernel, body) = fixture();
        let acquired = kernel.acquire(&mut ledger, &body, NOW).unwrap();
        let mission = ledger.list_missions().unwrap().remove(0).id;
        let mut graph = ledger.get_graph(&mission).unwrap().unwrap();
        graph.packages.clear();
        graph.variants.clear();
        ledger.put_graph(&graph).unwrap();

        let error = kernel.readback_active(&mut ledger, &body, NOW).unwrap_err();
        assert_eq!(error.reason_code(), "LEASE_NOT_ACTIVE");
        assert!(Ledger::get_lease(&ledger, &acquired.lease.variant_id)
            .unwrap()
            .is_some());
    }

    #[test]
    fn expired_grant_remains_archival_but_is_not_active_authority() {
        let (mut ledger, kernel, body) = fixture();
        let acquired = kernel.acquire(&mut ledger, &body, NOW).unwrap();
        ledger.advance_simulation_time(16).unwrap();
        assert_eq!(
            kernel.readback(&mut ledger, &body, NOW).unwrap().attempt.id,
            acquired.attempt.id
        );
        let error = kernel.readback_active(&mut ledger, &body, NOW).unwrap_err();
        assert_eq!(error.reason_code(), "LEASE_NOT_ACTIVE");
    }

    #[test]
    fn released_or_superseded_grants_never_recover_as_active() {
        for successor in [false, true] {
            let (mut ledger, kernel, body) = fixture();
            let acquired = kernel.acquire(&mut ledger, &body, NOW).unwrap();
            Ledger::release_lease(
                &mut ledger,
                &ReleaseRequest {
                    variant_id: acquired.lease.variant_id.clone(),
                    attempt_id: acquired.attempt.id.clone(),
                    final_state: AttemptState::Failed,
                    requeue: successor,
                },
            )
            .unwrap();
            if successor {
                let mut next = body.clone();
                next.idempotency_key = "active-readback-successor".into();
                let next_grant = kernel.acquire(&mut ledger, &next, NOW).unwrap();
                assert!(next_grant.lease.fence > acquired.lease.fence);
            }
            assert_eq!(
                kernel.readback(&mut ledger, &body, NOW).unwrap().attempt.id,
                acquired.attempt.id
            );
            let error = kernel.readback_active(&mut ledger, &body, NOW).unwrap_err();
            assert_eq!(error.reason_code(), "LEASE_NOT_ACTIVE");
        }
    }
}
