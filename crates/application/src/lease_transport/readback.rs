//! Strict read-back binding of one recorded grant.
//!
//! [`LeaseGrantRecord`] is the strict, versioned grant record. Acquire binds
//! it inside the transaction from `mint::grant_truth`; readback reconstructs
//! the request, the canonical body digest, and the authority subject inside
//! the same kind of transaction and requires exact agreement before any grant
//! is returned. Nothing observed before the transaction reaches either.

use super::mint::{transport, workspace_for_key, SignedLeaseError};
use super::SignedAcquireBody;
use crate::records::{LeaseGrant, LeaseRequest};
use bullet_domain::{AttemptId, DomainError};
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical, workspace_nonce_digest};
use bullet_harness_core::lease_transport::{
    request_digest, LeaseSubjectClaims, LeaseTransportOperation,
};
use serde::{Deserialize, Serialize};

/// Exact version label of the strict grant record.
pub const LEASE_GRANT_RECORD_VERSION: &str = "lease-transport-grant.v1alpha1";

/// Strict, deny-unknown, versioned record of one acquire: the resolved request,
/// the canonical digest of the body, the grant-class subject in force, and the
/// grant. A changed package, runner, runner epoch, or TTL under the same key is
/// `IDEMPOTENCY_CONFLICT`; rows that disagree with each other or with the key
/// are a store failure that discloses nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseGrantRecord {
    /// Always [`LEASE_GRANT_RECORD_VERSION`].
    pub version: String,
    /// Request resolved inside the acquire transaction.
    pub request: LeaseRequest,
    /// Canonical digest of the acquire body.
    pub request_digest: String,
    /// Grant-class subject minted for the acquire.
    pub subject: LeaseSubjectClaims,
    /// Grant the ledger returned in the same transaction.
    pub grant: LeaseGrant,
}

impl LeaseGrantRecord {
    /// Canonical encoding for the opaque `grant_json` value.
    ///
    /// # Errors
    /// Encoding refusal.
    pub fn encode(&self) -> Result<String, SignedLeaseError> {
        let bytes = canonical_json(self).map_err(transport)?;
        String::from_utf8(bytes).map_err(|_| store_refusal())
    }

    /// Strict decode of exactly one canonical document of this version whose
    /// rows agree. Corrupt bytes, an unknown version or field, or a legacy bare
    /// grant are a store failure disclosing nothing; there is no fallback parser.
    ///
    /// # Errors
    /// `STORE_FAILURE` for any deviation.
    pub fn decode(text: &str) -> Result<Self, SignedLeaseError> {
        let record: Self = decode_canonical(text.as_bytes()).map_err(|_| store_refusal())?;
        record.check().map_err(|_| store_refusal()).map(|()| record)
    }

    /// Rows must agree with each other, the key, the subject shape, and the recomputed digest.
    fn check(&self) -> Result<(), SignedLeaseError> {
        let (a, l) = (&self.grant.attempt, &self.grant.lease);
        let (r, s) = (&self.request, &self.subject);
        let (workspace_id, workspace_nonce) = workspace_for_key(&r.idempotency_key);
        let agrees = l.variant_id == a.variant_id
            && l.attempt_id == a.id
            && a.id == AttemptId::from_seed(&r.attempt_seed)
            && l.fence == a.fence
            && l.runner_id == a.runner_id
            && l.runner_epoch == a.runner_epoch
            && l.workspace_nonce == a.workspace_nonce
            && r.workspace_id == workspace_id
            && r.workspace_nonce == workspace_nonce
            && r.attempt_seed == r.idempotency_key
            && a.workspace_id == r.workspace_id
            && a.workspace_nonce == r.workspace_nonce
            && a.scope_revision == r.scope_revision
            && a.context_revision == r.context_revision
            && s.validate_shape(LeaseTransportOperation::Acquire).is_ok()
            && s.workspace_id == r.workspace_id.as_str()
            && s.workspace_nonce_digest
                == workspace_nonce_digest(&r.workspace_nonce).map_err(transport)?;
        if self.version != LEASE_GRANT_RECORD_VERSION || !agrees {
            return Err(store_refusal());
        }
        let changed = [
            (a.variant_id != r.variant_id, "work_package_id"),
            (a.runner_id != r.runner_id, "runner_id"),
            (a.runner_epoch != r.runner_epoch, "runner_epoch"),
            (l.ttl_seconds != r.ttl_seconds, "ttl_seconds"),
        ];
        if let Some((_, field)) = changed.into_iter().find(|(deviates, _)| *deviates) {
            return Err(conflict(field));
        }
        let body = SignedAcquireBody {
            work_package_id: a.work_package_id.clone(),
            runner_id: r.runner_id.clone(),
            runner_epoch: r.runner_epoch,
            idempotency_key: r.idempotency_key.clone(),
            ttl_seconds: r.ttl_seconds,
        };
        let digest = request_digest(&body).map_err(SignedLeaseError::Transport)?;
        (digest == self.request_digest)
            .then_some(())
            .ok_or_else(store_refusal)
    }
}

/// Grant-class truth resolved inside the open transaction.
pub(super) struct ExpectedGrant {
    pub(super) request: LeaseRequest,
    pub(super) subject: LeaseSubjectClaims,
    pub(super) request_digest: String,
}
type Bound = Result<LeaseGrantRecord, SignedLeaseError>;

impl ExpectedGrant {
    /// Bind `grant` to this expectation: `STORE_FAILURE` for disagreeing rows,
    /// `IDEMPOTENCY_CONFLICT` naming the first changed request field.
    pub(super) fn bind(self, grant: LeaseGrant) -> Bound {
        let record = LeaseGrantRecord {
            version: LEASE_GRANT_RECORD_VERSION.to_string(),
            request: self.request,
            request_digest: self.request_digest,
            subject: self.subject,
            grant,
        };
        record.check().map(|()| record)
    }

    /// Bind the durable row as [`Self::bind`]; it must then equal the reconstruction exactly.
    pub(super) fn bind_row(self, row: LeaseGrantRecord) -> Bound {
        let record = self.bind(row.grant.clone())?;
        (row == record).then_some(record).ok_or_else(store_refusal)
    }
}

fn store_refusal() -> SignedLeaseError {
    SignedLeaseError::Ledger(LeaseGrantRecord::refused())
}

fn conflict(field: &str) -> SignedLeaseError {
    let reason = format!("lease-transport readback changed {field} under the same idempotency key");
    SignedLeaseError::Ledger(DomainError::Idempotency(reason).into())
}

#[cfg(test)]
mod tests {
    use super::super::mint::{grant_truth, idempotency_digest};
    use super::super::{
        KernelLeaseTransport as Kernel, SignedAcquireBody, SignedAdvanceBody, SignedHeartbeatBody,
        SignedReleaseBody,
    };
    use super::*;
    use crate::records::{ActiveLease, HeartbeatRequest, ReleaseRequest};
    use crate::store::{LeaseTransportTxn, Ledger, ProjectionReader};
    use crate::{materialize_plan, LeaseService, MemoryLedger, PlanInput};
    use bullet_domain::WorkPackageId;
    use bullet_domain::{Attempt, AttemptState, RunnerId, TaskClass, VariantId};

    const NOW: u64 = 1_700_000_000_000;
    const REFUSED: &str = "ledger: lease-transport grant record refused";
    const STALE: &str = "lease fence stale: attempt fence 1, lease fence 2";
    type Refusal<T> = Result<T, SignedLeaseError>;
    type BodyMutation = fn(&mut SignedAcquireBody, &Fx);
    type CallMutation = fn(&mut HeartbeatRequest);

    struct Fx {
        ledger: MemoryLedger,
        kernel: Kernel,
        body: SignedAcquireBody,
        other: WorkPackageId,
        grant: LeaseGrant,
        hb: SignedHeartbeatBody,
        rel: SignedReleaseBody,
    }

    impl Fx {
        fn acquired(key: &str) -> Self {
            let mut ledger = MemoryLedger::new();
            let now = ledger.simulation_time();
            let one = ("one".into(), TaskClass::MechanicalCodeEdit);
            let two = ("two".into(), TaskClass::MechanicalCodeEdit);
            let plan = PlanInput {
                title: "readback".into(),
                objective: "txn-local truth".into(),
                packages: vec![one, two],
            };
            let graph = materialize_plan(&mut ledger, "readback", &plan, &now).unwrap();
            let body = SignedAcquireBody {
                work_package_id: graph.packages[0].id.clone(),
                runner_id: RunnerId::from_seed("readback-runner"),
                runner_epoch: 1,
                idempotency_key: key.into(),
                ttl_seconds: 15,
            };
            let kernel = Kernel::generate().unwrap();
            let grant = kernel.acquire(&mut ledger, &body, NOW).unwrap();
            let l = &grant.lease;
            let hb = SignedHeartbeatBody {
                work_package_id: body.work_package_id.clone(),
                idempotency_key: key.into(),
                call: HeartbeatRequest {
                    variant_id: l.variant_id.clone(),
                    attempt_id: l.attempt_id.clone(),
                    fence: l.fence,
                    runner_id: l.runner_id.clone(),
                    runner_epoch: l.runner_epoch,
                    workspace_nonce: l.workspace_nonce,
                    ttl_seconds: l.ttl_seconds,
                },
            };
            let rel = SignedReleaseBody {
                work_package_id: body.work_package_id.clone(),
                runner_id: body.runner_id.clone(),
                runner_epoch: body.runner_epoch,
                idempotency_key: key.into(),
                call: ReleaseRequest {
                    variant_id: l.variant_id.clone(),
                    attempt_id: l.attempt_id.clone(),
                    final_state: AttemptState::Failed,
                    requeue: false,
                },
            };
            let other = graph.packages[1].id.clone();
            Self {
                ledger,
                kernel,
                body,
                other,
                grant,
                hb,
                rel,
            }
        }

        fn acquire(&mut self, body: &SignedAcquireBody, at: u64) -> Refusal<LeaseGrant> {
            self.kernel.acquire(&mut self.ledger, body, NOW + at)
        }

        fn readback(&mut self, body: &SignedAcquireBody, at: u64) -> Refusal<LeaseGrant> {
            self.kernel.readback(&mut self.ledger, body, NOW + at)
        }

        fn heartbeat(&mut self, body: &SignedHeartbeatBody, at: u64) -> Refusal<()> {
            self.kernel.heartbeat(&mut self.ledger, body, NOW + at)
        }

        fn release(&mut self, body: &SignedReleaseBody, at: u64) -> Refusal<()> {
            self.kernel.release(&mut self.ledger, body, NOW + at)
        }

        fn advance(&mut self, state: AttemptState, at: u64) -> Refusal<Attempt> {
            let body = SignedAdvanceBody {
                work_package_id: self.body.work_package_id.clone(),
                runner_id: self.body.runner_id.clone(),
                runner_epoch: self.body.runner_epoch,
                idempotency_key: self.body.idempotency_key.clone(),
                attempt_id: self.grant.attempt.id.clone(),
                state,
            };
            self.kernel.advance(&mut self.ledger, &body, NOW + at)
        }

        fn state(&self) -> (Vec<ActiveLease>, Attempt) {
            let attempt = Ledger::get_attempt(&self.ledger, &self.grant.attempt.id).unwrap();
            (self.ledger.list_leases().unwrap(), attempt.unwrap())
        }

        fn keyed(&self, key: &str) -> SignedAcquireBody {
            let mut body = self.body.clone();
            body.idempotency_key = key.into();
            body
        }

        fn truth(&mut self, key: &str) -> ExpectedGrant {
            let (body, op) = (self.keyed(key), LeaseTransportOperation::Readback);
            let truth = |txn: &mut dyn LeaseTransportTxn| grant_truth(&*txn, op, &body, NOW);
            Ledger::with_lease_transport(&mut self.ledger, truth)
                .map(|t| t.1)
                .unwrap()
        }

        fn plant(&mut self, key: &str, grant: &LeaseGrant) {
            let (digest, t) = (idempotency_digest(key).unwrap(), self.truth(key));
            let record = LeaseGrantRecord {
                version: LEASE_GRANT_RECORD_VERSION.into(),
                request: t.request,
                request_digest: t.request_digest,
                subject: t.subject,
                grant: grant.clone(),
            };
            let txn = |txn: &mut dyn LeaseTransportTxn| txn.put_transport_grant(&digest, &record);
            Ledger::with_lease_transport(&mut self.ledger, txn).unwrap();
        }

        /// Expire and reclaim the fixture lease; a successor takes fence 2.
        fn supersede(&mut self) -> LeaseGrant {
            self.ledger.advance_simulation_time(16).unwrap();
            assert_eq!(LeaseService::expire_due(&mut self.ledger).unwrap().len(), 1);
            self.acquire(&self.keyed("successor"), 0).unwrap()
        }
    }

    #[test]
    fn same_key_changed_body_is_an_idempotency_conflict_on_readback_and_acquire() {
        let mut fx = Fx::acquired("changed");
        let (own, grant, before) = (fx.body.clone(), fx.grant.clone(), fx.state());
        assert_eq!(fx.readback(&own, 1).unwrap(), grant);
        let cases: [(&str, BodyMutation); 4] = [
            ("runner_id", |b, _| {
                b.runner_id = RunnerId::from_seed("intruder")
            }),
            ("runner_epoch", |b, _| b.runner_epoch += 1),
            ("ttl_seconds", |b, _| b.ttl_seconds = 5),
            ("work_package_id", |b, fx| {
                b.work_package_id = fx.other.clone()
            }),
        ];
        for (field, mutate) in cases {
            let mut hostile = own.clone();
            mutate(&mut hostile, &fx);
            let e = fx.readback(&hostile, 2).unwrap_err();
            assert_eq!(e.reason_code(), "IDEMPOTENCY_CONFLICT", "{field}");
            assert!(e.to_string().contains(field), "{field}: {e}");
            let e = fx.acquire(&hostile, 3).unwrap_err();
            assert_eq!(e.reason_code(), "IDEMPOTENCY_CONFLICT", "{field}");
            assert_eq!(fx.state(), before, "{field}");
        }
        let mut missing = fx.keyed("missing");
        missing.work_package_id = WorkPackageId::from_seed("missing");
        let e = fx.acquire(&missing, 4).unwrap_err();
        assert_eq!(e.reason_code(), "LEASE_TRANSPORT_UNKNOWN");
        let e = fx.readback(&fx.keyed("absent"), 4).unwrap_err();
        assert_eq!(e.reason_code(), "LEASE_TRANSPORT_UNKNOWN");
        assert_eq!(fx.state(), before);
        assert_eq!(fx.readback(&own, 5).unwrap(), grant);
    }

    #[test]
    fn planted_inconsistent_or_foreign_grants_fail_closed_and_disclose_nothing() {
        let mut fx = Fx::acquired("source");
        let mut torn = fx.grant.clone();
        torn.lease.fence += 1;
        fx.plant("torn", &torn);
        fx.plant("foreign", &fx.grant.clone());
        let before = fx.state();
        for key in ["torn", "foreign"] {
            let e = fx.readback(&fx.keyed(key), 1).unwrap_err();
            assert_eq!(e.reason_code(), "STORE_FAILURE", "{key}");
            assert_eq!(e.to_string(), REFUSED, "{key}");
            assert_eq!(fx.state(), before, "{key}");
        }
    }

    #[test]
    fn record_codec_is_strict_versioned_and_refuses_bare_grants() {
        let mut fx = Fx::acquired("codec");
        let grant = fx.grant.clone();
        let record = fx.truth("codec").bind(grant.clone()).unwrap();
        let text = record.encode().unwrap();
        assert_eq!(LeaseGrantRecord::decode(&text).unwrap(), record);
        let mut torn = record.clone();
        torn.grant.lease.runner_epoch += 1;
        let bare = String::from_utf8(canonical_json(&grant).unwrap()).unwrap();
        let cases = [
            ("bare grant", bare),
            ("version", text.replace(LEASE_GRANT_RECORD_VERSION, "v0")),
            (
                "unknown field",
                text.replacen("{\"grant\":", "{\"a\":1,\"grant\":", 1),
            ),
            ("non-canonical", text.replacen(',', ", ", 1)),
            ("torn rows", torn.encode().unwrap()),
            ("empty", String::new()),
        ];
        for (case, hostile) in cases {
            assert_ne!(hostile, text, "{case}");
            let e = LeaseGrantRecord::decode(&hostile).unwrap_err();
            assert_eq!(e.reason_code(), "STORE_FAILURE", "{case}");
            assert_eq!(e.to_string(), REFUSED, "{case}");
        }
    }

    #[test]
    fn incarnation_identity_is_proved_against_the_transaction_local_attempt() {
        let mut fx = Fx::acquired("identity");
        let before = fx.state();
        let cases: [(&str, CallMutation); 6] = [
            ("subject mismatch: runner_id", |c| {
                c.runner_id = RunnerId::from_seed("x")
            }),
            ("subject mismatch: runner_epoch", |c| c.runner_epoch += 1),
            ("subject mismatch: variant_id", |c| {
                c.variant_id = VariantId::from_seed("x")
            }),
            ("subject mismatch: fence", |c| c.fence += 1),
            ("subject mismatch: workspace_nonce_digest", |c| {
                c.workspace_nonce = [7; 32]
            }),
            ("unknown", |c| {
                c.attempt_id = AttemptId::from_seed("missing")
            }),
        ];
        for (tail, mutate) in cases {
            let mut hb = fx.hb.clone();
            mutate(&mut hb.call);
            let e = fx.heartbeat(&hb, 1).unwrap_err();
            assert_eq!(e.to_string(), format!("lease transport {tail}"));
            assert_eq!(fx.state(), before, "{tail}");
        }
        let mut wrong = fx.rel.clone();
        wrong.call.variant_id = VariantId::from_seed("other");
        let e = fx.release(&wrong, 1).unwrap_err();
        assert_eq!(
            e.to_string(),
            "lease transport subject mismatch: variant_id"
        );
        assert_eq!(fx.state(), before);
        fx.heartbeat(&fx.hb.clone(), 2).unwrap();
        fx.release(&fx.rel.clone(), 3).unwrap();
        assert!(fx.ledger.list_leases().unwrap().is_empty());
    }

    #[test]
    fn expired_or_superseded_incarnations_refuse_heartbeat_and_release_unchanged() {
        let mut fx = Fx::acquired("expired");
        fx.ledger.advance_simulation_time(16).unwrap();
        let (hb, rel, before) = (fx.hb.clone(), fx.rel.clone(), fx.state());
        for e in [
            fx.heartbeat(&hb, 0).unwrap_err(),
            fx.release(&rel, 0).unwrap_err(),
        ] {
            assert_eq!(e.reason_code(), "LEASE_NOT_ACTIVE", "{e}");
        }
        assert_eq!(fx.state(), before);
        let second = fx.supersede();
        let before = fx.state();
        assert_eq!(before.1.state, AttemptState::Crashed);
        for e in [
            fx.heartbeat(&hb, 0).unwrap_err(),
            fx.release(&rel, 0).unwrap_err(),
        ] {
            assert_eq!(e.reason_code(), "LEASE_FENCE_STALE");
            assert_eq!(e.to_string(), STALE);
        }
        assert_eq!(fx.state(), before);
        assert_eq!(before.0, vec![second.lease]);
        assert_eq!(fx.readback(&fx.body.clone(), 1).unwrap(), fx.grant);
    }

    #[test]
    fn advance_walks_legal_edges_and_refuses_self_edges() {
        let mut fx = Fx::acquired("advance-legal");
        let advanced = fx.advance(AttemptState::Running, 0).unwrap();
        assert_eq!(fx.state().1.state, AttemptState::Running);
        let e = fx.advance(AttemptState::Running, 1).unwrap_err();
        assert_eq!(e.reason_code(), "ATTEMPT_TRANSITION_ILLEGAL");
        assert_eq!(fx.state().1, advanced);
    }

    #[test]
    fn illegal_transition_leaves_the_attempt_unchanged() {
        let mut fx = Fx::acquired("advance-illegal");
        let e = fx.advance(AttemptState::Succeeded, 0).unwrap_err();
        assert_eq!(e.reason_code(), "ATTEMPT_TRANSITION_ILLEGAL");
        assert_eq!(
            e.to_string(),
            "attempt transition illegal: starting -> succeeded"
        );
        assert_eq!(fx.state().1, fx.grant.attempt);
    }

    #[test]
    fn expired_lease_refuses_advance_and_leaves_the_attempt_unchanged() {
        let mut fx = Fx::acquired("advance-expired");
        fx.ledger.advance_simulation_time(16).unwrap();
        let before = fx.state();
        let e = fx.advance(AttemptState::Running, 0).unwrap_err();
        assert_eq!(e.reason_code(), "LEASE_NOT_ACTIVE");
        assert_eq!(fx.state(), before);
    }

    #[test]
    fn stale_fence_refuses_advance_and_leaves_the_attempt_unchanged() {
        let mut fx = Fx::acquired("advance-stale");
        let second = fx.supersede();
        let before = fx.state();
        assert_eq!(before.1.state, AttemptState::Crashed);
        let e = fx.advance(AttemptState::Running, 0).unwrap_err();
        assert_eq!(e.reason_code(), "LEASE_FENCE_STALE");
        assert_eq!(e.to_string(), STALE);
        assert_eq!(fx.state(), before);
        assert_eq!(before.0, vec![second.lease]);
    }
}
