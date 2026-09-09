-- Durable Kernel-minted lease-transport nonce and grant index.
-- Public /v1/leases/* stay absent. Readback after farmd restart returns
-- the last acquire for an idempotency digest. Nonce replay survives restart.

CREATE TABLE lease_transport_nonces (
  permit_nonce TEXT PRIMARY KEY CHECK (
    typeof(permit_nonce) = 'text'
    AND length(permit_nonce) = 64
    AND permit_nonce NOT GLOB '*[^0-9a-f]*'
  ),
  binding TEXT NOT NULL CHECK (typeof(binding) = 'text' AND length(binding) > 0),
  expires_at_unix_ms INTEGER NOT NULL CHECK (
    typeof(expires_at_unix_ms) = 'integer' AND expires_at_unix_ms > 0
  ),
  reserved_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE lease_transport_grants (
  idempotency_digest TEXT PRIMARY KEY CHECK (
    typeof(idempotency_digest) = 'text'
    AND length(idempotency_digest) = 64
    AND idempotency_digest NOT GLOB '*[^0-9a-f]*'
  ),
  grant_json TEXT NOT NULL CHECK (typeof(grant_json) = 'text' AND length(grant_json) > 0),
  recorded_at TEXT NOT NULL
);
