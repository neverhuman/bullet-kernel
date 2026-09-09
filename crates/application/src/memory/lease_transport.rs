use crate::lease_transport::{LeaseGrantRecord, LeaseSettlementRecord};

impl LeaseTransportTxn for MemoryLedger {
    fn reserve_transport_nonce(
        &mut self,
        nonce: &str,
        binding: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), LedgerError> {
        if self.lease_transport_nonces.contains_key(nonce) {
            return Err(LedgerError::Store(
                "lease-transport nonce already reserved".into(),
            ));
        }
        self.lease_transport_nonces.insert(
            nonce.to_string(),
            MemoryTransportNonce {
                binding: binding.to_string(),
                expires_at_unix_ms,
                consumed: false,
            },
        );
        Ok(())
    }

    fn consume_transport_nonce(
        &mut self,
        nonce: &str,
        binding: &str,
        now_unix_ms: u64,
    ) -> Result<NonceConsumption, LedgerError> {
        let Some(record) = self.lease_transport_nonces.get_mut(nonce) else {
            return Ok(NonceConsumption::Unknown);
        };
        if record.binding != binding {
            return Ok(NonceConsumption::Unknown);
        }
        if record.consumed {
            return Ok(NonceConsumption::Replayed);
        }
        if now_unix_ms >= record.expires_at_unix_ms {
            return Ok(NonceConsumption::Expired);
        }
        record.consumed = true;
        Ok(NonceConsumption::Consumed)
    }

    fn acquire_lease(&mut self, request: &LeaseRequest) -> Result<LeaseGrant, LedgerError> {
        self.acquire_lease_impl(request)
    }

    fn heartbeat(&mut self, request: &HeartbeatRequest) -> Result<(), LedgerError> {
        self.heartbeat_impl(request)
    }

    fn release_lease(&mut self, request: &ReleaseRequest) -> Result<(), LedgerError> {
        self.release_lease_impl(request)
    }

    fn put_attempt(&mut self, attempt: &Attempt) -> Result<(), LedgerError> {
        Ledger::put_attempt(self, attempt)
    }

    fn get_attempt(&self, id: &AttemptId) -> Result<Option<Attempt>, LedgerError> {
        Ledger::get_attempt(self, id)
    }

    fn resolve_package(&self, package: &WorkPackageId) -> Result<CurrentPackage, LedgerError> {
        for graph in self.graphs.values() {
            if let Some(found) = CurrentPackage::from_graph(graph, package)? {
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
        for graph in self.graphs.values() {
            if let Some(found) = CurrentPackage::from_graph_variant(graph, package, variant)? {
                return Ok(found);
            }
        }
        Err(CurrentPackage::unknown(package))
    }

    fn current_authority(&self) -> Result<NormalizedAuthority, LedgerError> {
        Ledger::current_authority(self)
    }

    fn get_lease(&self, attempt: &AttemptId) -> Result<Option<ActiveLease>, LedgerError> {
        let Some(stored) = self.attempts.get(attempt.as_str()) else {
            return Ok(None);
        };
        Ok(self
            .leases
            .get(stored.variant_id.as_str())
            .filter(|lease| lease.attempt_id == *attempt)
            .cloned())
    }

    fn check_active_lease(&self, attempt: &AttemptId, fence: u64) -> Result<(), LedgerError> {
        let stored = self.attempts.get(attempt.as_str()).cloned();
        self.check_active_lease_impl(&incarnation_subject(stored, attempt, fence)?)
    }

    fn put_transport_grant(
        &mut self,
        idempotency_digest: &str,
        record: &LeaseGrantRecord,
    ) -> Result<(), LedgerError> {
        let grant_json = record.encode().map_err(|_| LeaseGrantRecord::refused())?;
        if let Some(existing) = self.get_transport_grant(idempotency_digest)? {
            if existing == *record {
                return Ok(());
            }
            return Err(LedgerError::Store(
                "lease-transport grant digest already records a different record".into(),
            ));
        }
        self.lease_transport_grants
            .insert(idempotency_digest.to_string(), grant_json);
        Ok(())
    }

    fn get_transport_grant(
        &self,
        idempotency_digest: &str,
    ) -> Result<Option<LeaseGrantRecord>, LedgerError> {
        self.lease_transport_grants
            .get(idempotency_digest)
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
        self.tick()?;
        self.lease_transport_settlements
            .insert(record.settlement_id.clone(), encoded);
        self.push_event(
            "lease_transport_settled",
            &record.settlement_id,
            Some(record.settlement_id.clone()),
            Some(record.request_digest.clone()),
            None,
        );
        Ok(())
    }

    fn get_transport_settlement(
        &self,
        settlement_id: &str,
    ) -> Result<Option<LeaseSettlementRecord>, LedgerError> {
        self.lease_transport_settlements
            .get(settlement_id)
            .map(|text| {
                LeaseSettlementRecord::decode(text)
                    .map_err(|_| LeaseSettlementRecord::refused())
            })
            .transpose()
    }
}

impl MemoryLedger {
    /// Hostile-row seam: the opaque `grant_json` rows exactly as the memory
    /// ledger holds them, bypassing the port and its codec the way a raw
    /// SQLite connection bypasses the adapter. Tests plant legacy or corrupt
    /// bytes here; nothing in the product reads through it.
    pub fn transport_grant_rows_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.lease_transport_grants
    }

    /// Hostile-row seam for strict settlement codec tests.
    pub fn transport_settlement_rows_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.lease_transport_settlements
    }
}
