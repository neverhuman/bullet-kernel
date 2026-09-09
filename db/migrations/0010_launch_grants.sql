-- Single-use launch-grant nonces. The issuer inserts one row per minted
-- grant inside the durable active lease; admission consumes it exactly once.
-- A consumed or expired nonce can never authorize a second spawn.

CREATE TABLE launch_grant_nonces (
  grant_nonce        TEXT PRIMARY KEY CHECK (
    typeof(grant_nonce) = 'text'
    AND length(grant_nonce) = 64
    AND grant_nonce NOT GLOB '*[^0-9a-f]*'
  ),
  grant_id           TEXT NOT NULL UNIQUE CHECK (
    typeof(grant_id) = 'text'
    AND length(grant_id) = 64
    AND grant_id NOT GLOB '*[^0-9a-f]*'
  ),
  attempt_id         TEXT NOT NULL CHECK (
    typeof(attempt_id) = 'text'
    AND length(attempt_id) = 68
    AND substr(attempt_id, 1, 4) = 'atm_'
    AND substr(attempt_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  attempt_fence      INTEGER NOT NULL CHECK (
    typeof(attempt_fence) = 'integer' AND attempt_fence >= 1
  ),
  expires_at_unix_ms INTEGER NOT NULL CHECK (
    typeof(expires_at_unix_ms) = 'integer' AND expires_at_unix_ms > 0
  ),
  issued_at          TEXT NOT NULL,
  consumed_at        TEXT
);

CREATE INDEX launch_grant_nonces_attempt ON launch_grant_nonces(attempt_id, expires_at_unix_ms);
