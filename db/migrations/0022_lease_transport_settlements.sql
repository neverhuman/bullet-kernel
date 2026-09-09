-- Immutable exact terminal outcomes. The application strictly decodes the
-- canonical record and re-derives both identity columns on every read.

CREATE TABLE lease_transport_settlements (
  settlement_id TEXT PRIMARY KEY CHECK (
    typeof(settlement_id) = 'text'
    AND length(settlement_id) = 68
    AND substr(settlement_id, 1, 4) = 'lts_'
    AND substr(settlement_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  request_digest TEXT NOT NULL CHECK (
    typeof(request_digest) = 'text'
    AND length(request_digest) = 64
    AND request_digest NOT GLOB '*[^0-9a-f]*'
  ),
  record_json TEXT NOT NULL CHECK (
    typeof(record_json) = 'text' AND length(record_json) BETWEEN 2 AND 65536
  ),
  recorded_at TEXT NOT NULL CHECK (
    typeof(recorded_at) = 'text' AND length(recorded_at) BETWEEN 1 AND 64
  )
);

CREATE TRIGGER lease_transport_settlements_no_update
BEFORE UPDATE ON lease_transport_settlements
BEGIN
  SELECT RAISE(ABORT, 'lease transport settlements are immutable');
END;

CREATE TRIGGER lease_transport_settlements_no_delete
BEFORE DELETE ON lease_transport_settlements
BEGIN
  SELECT RAISE(ABORT, 'lease transport settlements are append-only');
END;
