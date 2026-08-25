//! Immediate-transaction lease-transport nonce and grant index.

use super::{from_json, graph, json, lease_time, leases, store};
use bullet_application::store::{LeaseTransportTxn, NonceConsumption};
use bullet_application::{HeartbeatRequest, LeaseGrant, LeaseRequest, LedgerError, ReleaseRequest};
use bullet_domain::{Attempt, AttemptId};
use rusqlite::{params, OptionalExtension, Transaction};

pub(super) struct TransportSession<'a> {
    pub(super) tx: Transaction<'a>,
}

impl LeaseTransportTxn for TransportSession<'_> {
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

    fn put_transport_grant(
        &mut self,
        idempotency_digest: &str,
        grant: &LeaseGrant,
    ) -> Result<(), LedgerError> {
        let recorded_at = lease_time::database_time(&self.tx)?;
        let grant_json = json(grant)?;
        if let Some(existing) = self.get_transport_grant(idempotency_digest)? {
            if existing == *grant {
                return Ok(());
            }
            return Err(LedgerError::Store(
                "lease-transport grant digest already records a different grant".into(),
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
    ) -> Result<Option<LeaseGrant>, LedgerError> {
        let text: Option<String> = self
            .tx
            .query_row(
                "SELECT grant_json FROM lease_transport_grants WHERE idempotency_digest = ?1",
                params![idempotency_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(store)?;
        text.as_deref().map(from_json).transpose()
    }
}
