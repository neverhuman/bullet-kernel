//! Immediate-transaction lease-transport nonce and grant index.

use super::{authority, events, graph, lease_time, leases, store};
use bullet_application::lease_transport::{LeaseGrantRecord, LeaseSettlementRecord};
use bullet_application::store::{
    incarnation_subject, CurrentPackage, LeaseTransportTxn, NonceConsumption,
};
use bullet_application::{
    ActiveLease, HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerError, NormalizedAuthority,
    ReleaseRequest,
};
use bullet_domain::{Attempt, AttemptId, VariantId, WorkPackageId};
use rusqlite::{params, OptionalExtension, Transaction};

pub(super) struct TransportSession<'a, 'failpoint> {
    pub(super) tx: Transaction<'a>,
    pub(super) settlement_fail_after: &'failpoint mut Option<u8>,
}

impl LeaseTransportTxn for TransportSession<'_, '_> {
    fn reserve_transport_nonce(
        &mut self,
        nonce: &str,
        binding: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), LedgerError> {
        let reserved_at = lease_time::database_time(&self.tx)?;
        let inserted = self
            .tx
            .execute(
                "INSERT OR IGNORE INTO lease_transport_nonces
                 (permit_nonce, binding, expires_at_unix_ms, reserved_at, consumed_at)
                 VALUES (?1, ?2, ?3, ?4, NULL)",
                params![
                    nonce,
                    binding,
                    i64::try_from(expires_at_unix_ms).map_err(store)?,
                    reserved_at
                ],
            )
            .map_err(store)?;
        if inserted != 1 {
            return Err(LedgerError::Store(
                "lease-transport nonce already reserved".into(),
            ));
        }
        Ok(())
    }

    fn consume_transport_nonce(
        &mut self,
        nonce: &str,
        binding: &str,
        now_unix_ms: u64,
    ) -> Result<NonceConsumption, LedgerError> {
        let row: Option<(String, i64, Option<String>)> = self
            .tx
            .query_row(
                "SELECT binding, expires_at_unix_ms, consumed_at
                 FROM lease_transport_nonces WHERE permit_nonce = ?1",
                params![nonce],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(store)?;
        let Some((stored_binding, expires_at, consumed_at)) = row else {
            return Ok(NonceConsumption::Unknown);
        };
        if stored_binding != binding {
            return Ok(NonceConsumption::Unknown);
        }
        if consumed_at.is_some() {
            return Ok(NonceConsumption::Replayed);
        }
        let expires = u64::try_from(expires_at).map_err(store)?;
        if now_unix_ms >= expires {
            return Ok(NonceConsumption::Expired);
        }
        let consumed_at = lease_time::database_time(&self.tx)?;
        let changed = self
            .tx
            .execute(
                "UPDATE lease_transport_nonces SET consumed_at = ?2
                 WHERE permit_nonce = ?1 AND consumed_at IS NULL",
                params![nonce, consumed_at],
            )
            .map_err(store)?;
        if changed != 1 {
            return Ok(NonceConsumption::Replayed);
        }
        Ok(NonceConsumption::Consumed)
    }

    fn acquire_lease(&mut self, request: &LeaseRequest) -> Result<LeaseGrant, LedgerError> {
        let mut fail_after = None;
        leases::acquire_on(&self.tx, &mut fail_after, request)
    }

    fn heartbeat(&mut self, request: &HeartbeatRequest) -> Result<(), LedgerError> {
        leases::heartbeat_on(&self.tx, request)
    }

    fn release_lease(&mut self, request: &ReleaseRequest) -> Result<(), LedgerError> {
        leases::release_on(&self.tx, request)
    }

    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError> {
        graph::put_attempt_on(&self.tx, attempt)
    }

    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError> {
        graph::get_attempt(&self.tx, id)
    }

    fn resolve_package(&self, package: &WorkPackageId) -> Result<CurrentPackage, LedgerError> {
        for mission in graph::list_missions(&self.tx)? {
            let stored = graph::get_graph(&self.tx, &mission.id)?.ok_or_else(|| {
                LedgerError::Store(format!(
                    "graph {} vanished inside the open transaction",
                    mission.id
                ))
            })?;
            if let Some(found) = CurrentPackage::from_graph(&stored, package)? {
                return Ok(found);
            }
        }
        Err(CurrentPackage::unknown(package))
    }

    fn resolve_variant(
        &self,
        package: &WorkPackageId,
        variant: &VariantId,
    ) -> Result<CurrentPackage, LedgerError> {
        for mission in graph::list_missions(&self.tx)? {
            let stored = graph::get_graph(&self.tx, &mission.id)?.ok_or_else(|| {
                LedgerError::Store(format!(
                    "graph {} vanished inside the open transaction",
                    mission.id
                ))
            })?;
            if let Some(found) = CurrentPackage::from_graph_variant(&stored, package, variant)? {
                return Ok(found);
            }
        }
        Err(CurrentPackage::unknown(package))
    }

    fn current_authority(&self) -> Result<NormalizedAuthority, LedgerError> {
        authority::current(&self.tx)
    }

    fn get_lease(&self, attempt: &AttemptId) -> Result<Option<ActiveLease>, LedgerError> {
        let Some(stored) = graph::get_attempt(&self.tx, attempt)? else {
            return Ok(None);
        };
        Ok(leases::get_lease(&self.tx, &stored.variant_id)?
            .filter(|lease| lease.attempt_id == *attempt))
    }

    fn check_active_lease(&self, attempt: &AttemptId, fence: u64) -> Result<(), LedgerError> {
        let stored = graph::get_attempt(&self.tx, attempt)?;
        leases::check_active_lease_in(&self.tx, &incarnation_subject(stored, attempt, fence)?)
    }

    fn put_transport_grant(
        &mut self,
        idempotency_digest: &str,
        record: &LeaseGrantRecord,
    ) -> Result<(), LedgerError> {
        let recorded_at = lease_time::database_time(&self.tx)?;
        let grant_json = record.encode().map_err(|_| LeaseGrantRecord::refused())?;
        if let Some(existing) = self.get_transport_grant(idempotency_digest)? {
            if existing == *record {
                return Ok(());
            }
            return Err(LedgerError::Store(
                "lease-transport grant digest already records a different record".into(),
            ));
        }
        self.tx
            .execute(
                "INSERT INTO lease_transport_grants
                 (idempotency_digest, grant_json, recorded_at) VALUES (?1, ?2, ?3)",
                params![idempotency_digest, grant_json, recorded_at],
            )
            .map_err(store)?;
        Ok(())
    }

    fn get_transport_grant(
        &self,
        idempotency_digest: &str,
    ) -> Result<Option<LeaseGrantRecord>, LedgerError> {
        let text: Option<String> = self
            .tx
            .query_row(
                "SELECT grant_json FROM lease_transport_grants WHERE idempotency_digest = ?1",
                params![idempotency_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(store)?;
        text.as_deref()
            .map(|text| LeaseGrantRecord::decode(text).map_err(|_| LeaseGrantRecord::refused()))
            .transpose()
    }

    fn put_transport_settlement(
        &mut self,
        record: &LeaseSettlementRecord,
    ) -> Result<(), LedgerError> {
        let encoded = record
            .encode()
            .map_err(|_| LeaseSettlementRecord::refused())?;
        if let Some(existing) = self.get_transport_settlement(&record.settlement_id)? {
            if existing == *record {
                return Ok(());
            }
            return Err(LedgerError::Store(
                "lease-transport settlement identity already records another outcome".into(),
            ));
        }
        settlement_step(self.settlement_fail_after)?;
        let recorded_at = lease_time::database_time(&self.tx)?;
        self.tx
            .execute(
                "INSERT INTO lease_transport_settlements
                 (settlement_id, request_digest, record_json, recorded_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.settlement_id,
                    record.request_digest,
                    encoded,
                    recorded_at
                ],
            )
            .map_err(store)?;
        events::insert_event(
            &self.tx,
            "lease_transport_settled",
            &record.settlement_id,
            Some(&record.settlement_id),
            Some(&record.request_digest),
            None,
        )
    }

    fn get_transport_settlement(
        &self,
        settlement_id: &str,
    ) -> Result<Option<LeaseSettlementRecord>, LedgerError> {
        let row: Option<(String, String)> = self
            .tx
            .query_row(
                "SELECT request_digest, record_json
                 FROM lease_transport_settlements WHERE settlement_id = ?1",
                params![settlement_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(store)?;
        let Some((request_digest, text)) = row else {
            return Ok(None);
        };
        let record =
            LeaseSettlementRecord::decode(&text).map_err(|_| LeaseSettlementRecord::refused())?;
        if record.settlement_id != settlement_id || record.request_digest != request_digest {
            return Err(LeaseSettlementRecord::refused());
        }
        Ok(Some(record))
    }
}

fn settlement_step(fail_after: &mut Option<u8>) -> Result<(), LedgerError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(LedgerError::Store(
                "injected lease-transport settlement failure".into(),
            ))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}
