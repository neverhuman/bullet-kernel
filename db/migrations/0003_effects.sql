-- Effect broker tables per spec section 26.2. An intent is unique on
-- (provider, logical_effect_key) so a replayed proposal returns the stored
-- row instead of dispatching a second remote mutation. Receipts are
-- append-only read-back observations.

CREATE TABLE IF NOT EXISTS effect_intents (
  id                       TEXT PRIMARY KEY,
  logical_effect_key       TEXT NOT NULL,
  provider                 TEXT NOT NULL,
  target_identity          TEXT NOT NULL,
  desired_state_hash       TEXT NOT NULL,
  expected_old_oid         TEXT NOT NULL,
  attempt_id               TEXT NOT NULL,
  fence                    INTEGER NOT NULL,
  policy_version           TEXT NOT NULL,
  payload_hash             TEXT NOT NULL,
  provider_idempotency_key TEXT,
  state                    TEXT NOT NULL,
  unknown_retries          INTEGER NOT NULL DEFAULT 0,
  created_at               TEXT NOT NULL,
  UNIQUE(provider, logical_effect_key)
);

CREATE INDEX IF NOT EXISTS idx_effect_intents_state ON effect_intents(state);
CREATE INDEX IF NOT EXISTS idx_effect_intents_attempt ON effect_intents(attempt_id);

CREATE TABLE IF NOT EXISTS effect_receipts (
  id                       TEXT PRIMARY KEY,
  effect_intent_id         TEXT NOT NULL REFERENCES effect_intents(id),
  observed_remote_identity TEXT NOT NULL,
  observed_state_hash      TEXT,
  verification_method      TEXT NOT NULL,
  verification_result      TEXT NOT NULL,
  adopted_after_unknown    INTEGER NOT NULL,
  recorded_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_effect_receipts_intent ON effect_receipts(effect_intent_id);
