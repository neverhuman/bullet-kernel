-- Immutable exact-replay record for normalized scope admission. Installed only
-- during fresh pre-1.0 initialization; schema-19 databases remain unsupported.

CREATE TABLE authority_scope_admissions (
  idempotency_key TEXT PRIMARY KEY CHECK (
    typeof(idempotency_key) = 'text'
    AND length(idempotency_key) BETWEEN 1 AND 256
  ),
  command_id TEXT NOT NULL UNIQUE CHECK (
    length(command_id) = 68
    AND substr(command_id, 1, 4) = 'cmd_'
    AND substr(command_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  request_digest TEXT NOT NULL CHECK (
    length(request_digest) = 64
    AND request_digest NOT GLOB '*[^0-9a-f]*'
  ),
  scope_grant_id TEXT NOT NULL UNIQUE CHECK (
    length(scope_grant_id) = 68
    AND substr(scope_grant_id, 1, 4) = 'sgr_'
    AND substr(scope_grant_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  grant_bytes BLOB NOT NULL CHECK (
    typeof(grant_bytes) = 'blob'
    AND length(grant_bytes) BETWEEN 1 AND 65536
  ),
  scope_revision INTEGER NOT NULL CHECK (
    scope_revision BETWEEN 1 AND 9007199254740991
  ),
  scope_paths_digest TEXT NOT NULL CHECK (
    length(scope_paths_digest) = 64
    AND scope_paths_digest NOT GLOB '*[^0-9a-f]*'
  ),
  previous_authority_epoch INTEGER NOT NULL CHECK (
    previous_authority_epoch BETWEEN 1 AND 9007199254740990
  ),
  new_authority_epoch INTEGER NOT NULL CHECK (
    new_authority_epoch BETWEEN 2 AND 9007199254740991
    AND new_authority_epoch = previous_authority_epoch + 1
  ),
  freeze_generation INTEGER NOT NULL CHECK (freeze_generation = 0),
  admitted_at TEXT NOT NULL CHECK (
    typeof(admitted_at) = 'text' AND length(admitted_at) BETWEEN 1 AND 64
  ),
  event_sequence INTEGER NOT NULL UNIQUE REFERENCES events(seq)
);

CREATE TRIGGER authority_scope_admissions_insert_guard
BEFORE INSERT ON authority_scope_admissions
WHEN NOT EXISTS (
  SELECT 1
  FROM authority_revisions AS authority
  JOIN events AS event ON event.seq = NEW.event_sequence
  WHERE authority.singleton = 1
    AND authority.scope_digest = NEW.scope_paths_digest
    AND authority.authority_epoch = NEW.new_authority_epoch
    AND authority.freeze_generation = NEW.freeze_generation
    AND event.kind = 'authority_scope_admitted'
    AND event.body = NEW.scope_grant_id
    AND event.stream_id = NEW.scope_grant_id
    AND event.correlation_id = NEW.command_id
)
BEGIN
  SELECT RAISE(ABORT, 'scope admission authority or audit binding is stale');
END;

CREATE TRIGGER authority_scope_admissions_no_update
BEFORE UPDATE ON authority_scope_admissions
BEGIN
  SELECT RAISE(ABORT, 'authority scope admission update is forbidden');
END;

CREATE TRIGGER authority_scope_admissions_no_delete
BEFORE DELETE ON authority_scope_admissions
BEGIN
  SELECT RAISE(ABORT, 'authority scope admission deletion is forbidden');
END;
