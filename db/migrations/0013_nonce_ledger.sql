-- Generic one-use nonce ledger. This table deliberately does not replace the
-- launch-grant or lease-transport nonce tables: those bind different subjects
-- and expiry rules. Observation never inserts a row.

CREATE TABLE authority_nonces (
  nonce_key TEXT PRIMARY KEY CHECK (
    typeof(nonce_key) = 'text'
    AND length(nonce_key) = 64
    AND nonce_key NOT GLOB '*[^0-9a-f]*'
  ),
  request_digest TEXT NOT NULL CHECK (
    typeof(request_digest) = 'text'
    AND length(request_digest) = 64
    AND request_digest NOT GLOB '*[^0-9a-f]*'
  ),
  issued_at TEXT NOT NULL CHECK (
    typeof(issued_at) = 'text' AND length(issued_at) > 0
  ),
  consumed_at TEXT CHECK (
    consumed_at IS NULL
    OR (typeof(consumed_at) = 'text' AND length(consumed_at) > 0)
  )
);
