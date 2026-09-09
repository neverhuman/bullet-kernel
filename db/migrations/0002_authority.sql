-- Authority tables per spec section 26.2. Fences, attempts, leases, the
-- ready queue, and the outbox move to typed columns; mission/plan/package
-- snapshots stay as JSON bodies in `graphs`.

CREATE TABLE IF NOT EXISTS variant_fence_counters (
  variant_id TEXT PRIMARY KEY,
  next_fence INTEGER NOT NULL DEFAULT 0
);

DROP TABLE IF EXISTS attempts;
CREATE TABLE attempts (
  id               TEXT PRIMARY KEY,
  variant_id       TEXT NOT NULL,
  work_package_id  TEXT NOT NULL,
  fence            INTEGER NOT NULL,
  runner_id        TEXT NOT NULL,
  runner_epoch     INTEGER NOT NULL,
  workspace_id     TEXT NOT NULL,
  workspace_nonce  BLOB NOT NULL,
  scope_revision   INTEGER NOT NULL,
  context_revision INTEGER NOT NULL,
  state            TEXT NOT NULL,
  UNIQUE(variant_id, fence)
);

CREATE INDEX IF NOT EXISTS idx_attempts_work_package ON attempts(work_package_id, state);
CREATE INDEX IF NOT EXISTS idx_attempts_variant ON attempts(variant_id);

CREATE TABLE IF NOT EXISTS active_leases (
  variant_id      TEXT PRIMARY KEY,
  attempt_id      TEXT NOT NULL UNIQUE,
  fence           INTEGER NOT NULL,
  runner_id       TEXT NOT NULL,
  runner_epoch    INTEGER NOT NULL,
  workspace_nonce BLOB NOT NULL,
  heartbeat_at    TEXT NOT NULL,
  expires_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ready_queue (
  work_package_id TEXT PRIMARY KEY,
  enqueued_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         TEXT NOT NULL,
  payload      TEXT NOT NULL,
  phase        TEXT NOT NULL,
  delivered_at TEXT,
  acked_at     TEXT
);

ALTER TABLE events ADD COLUMN event_id TEXT;
ALTER TABLE events ADD COLUMN stream_id TEXT;
ALTER TABLE events ADD COLUMN sequence INTEGER;
ALTER TABLE events ADD COLUMN causation_id TEXT;
ALTER TABLE events ADD COLUMN correlation_id TEXT;
ALTER TABLE events ADD COLUMN authority_token_hash TEXT;

ALTER TABLE commands ADD COLUMN response_json TEXT;
