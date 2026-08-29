-- Immutable Candidate-preparation preregistration, signed grant storage, and
-- append-only one-use consumption. This schema is installed only while a
-- completely fresh pre-1.0 database is initialized; schema-18 databases are
-- verified and refused rather than incrementally upgraded.

CREATE TABLE candidate_preparation_sources (
  request_digest TEXT PRIMARY KEY CHECK (
    typeof(request_digest) = 'text'
    AND length(request_digest) = 64
    AND request_digest NOT GLOB '*[^0-9a-f]*'
  ),
  source_bytes BLOB NOT NULL CHECK (
    typeof(source_bytes) = 'blob'
    AND length(source_bytes) BETWEEN 1 AND 65536
  ),
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  change_id TEXT NOT NULL UNIQUE CHECK (
    length(change_id) = 68
    AND substr(change_id, 1, 4) = 'chg_'
    AND substr(change_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  root_change INTEGER NOT NULL CHECK (root_change IN (0, 1)),
  execution_envelope_id TEXT NOT NULL CHECK (
    length(execution_envelope_id) = 68
    AND substr(execution_envelope_id, 1, 4) = 'exe_'
    AND substr(execution_envelope_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  registered_at TEXT NOT NULL
);

CREATE TRIGGER candidate_preparation_sources_no_update
BEFORE UPDATE ON candidate_preparation_sources
BEGIN
  SELECT RAISE(ABORT, 'Candidate-preparation source update is forbidden');
END;

CREATE TRIGGER candidate_preparation_sources_no_delete
BEFORE DELETE ON candidate_preparation_sources
BEGIN
  SELECT RAISE(ABORT, 'Candidate-preparation source deletion is forbidden');
END;

CREATE TABLE candidate_preparation_grants (
  request_digest TEXT PRIMARY KEY REFERENCES candidate_preparation_sources(request_digest),
  candidate_preparation_grant_id TEXT NOT NULL UNIQUE CHECK (
    length(candidate_preparation_grant_id) = 68
    AND substr(candidate_preparation_grant_id, 1, 4) = 'cpg_'
    AND substr(candidate_preparation_grant_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  grant_nonce TEXT NOT NULL UNIQUE CHECK (
    length(grant_nonce) = 64
    AND grant_nonce NOT GLOB '*[^0-9a-f]*'
  ),
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  variant_id TEXT NOT NULL,
  attempt_fence INTEGER NOT NULL CHECK (attempt_fence BETWEEN 1 AND 9007199254740991),
  runner_id TEXT NOT NULL,
  runner_epoch INTEGER NOT NULL CHECK (runner_epoch BETWEEN 1 AND 9007199254740991),
  workspace_id TEXT NOT NULL,
  scope_revision INTEGER NOT NULL CHECK (scope_revision BETWEEN 1 AND 9007199254740991),
  context_revision INTEGER NOT NULL CHECK (context_revision BETWEEN 1 AND 9007199254740991),
  authority_epoch INTEGER NOT NULL CHECK (authority_epoch BETWEEN 1 AND 9007199254740991),
  freeze_generation INTEGER NOT NULL CHECK (freeze_generation BETWEEN 0 AND 9007199254740991),
  graph_revision_id TEXT NOT NULL CHECK (
    length(graph_revision_id) = 68
    AND substr(graph_revision_id, 1, 4) = 'grf_'
    AND substr(graph_revision_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  scope_grant_digest TEXT NOT NULL CHECK (
    length(scope_grant_digest) = 64
    AND scope_grant_digest NOT GLOB '*[^0-9a-f]*'
  ),
  execution_envelope_id TEXT NOT NULL,
  environment_digest TEXT NOT NULL CHECK (
    length(environment_digest) = 64
    AND environment_digest NOT GLOB '*[^0-9a-f]*'
  ),
  toolchain_digest TEXT NOT NULL CHECK (
    length(toolchain_digest) = 64
    AND toolchain_digest NOT GLOB '*[^0-9a-f]*'
  ),
  issued_at_unix_ms INTEGER NOT NULL CHECK (
    issued_at_unix_ms BETWEEN 0 AND 9007199254740991
  ),
  expires_at_unix_ms INTEGER NOT NULL CHECK (
    expires_at_unix_ms BETWEEN 1 AND 9007199254740991
  ),
  claims_bytes BLOB NOT NULL CHECK (
    typeof(claims_bytes) = 'blob' AND length(claims_bytes) BETWEEN 1 AND 65536
  ),
  signed_bytes BLOB NOT NULL CHECK (
    typeof(signed_bytes) = 'blob' AND length(signed_bytes) BETWEEN 1 AND 65536
  ),
  envelope_digest TEXT NOT NULL CHECK (
    length(envelope_digest) = 64
    AND envelope_digest NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (issued_at_unix_ms < expires_at_unix_ms)
);

CREATE TRIGGER candidate_preparation_grants_insert_guard
BEFORE INSERT ON candidate_preparation_grants
WHEN NOT EXISTS (
  SELECT 1
  FROM candidate_preparation_sources AS source
  JOIN attempts AS attempt ON attempt.id = source.attempt_id
  JOIN active_leases AS lease
    ON lease.attempt_id = attempt.id
   AND lease.variant_id = attempt.variant_id
   AND lease.fence = attempt.fence
   AND lease.runner_id = attempt.runner_id
   AND lease.runner_epoch = attempt.runner_epoch
   AND lease.workspace_nonce = attempt.workspace_nonce
  JOIN authority_revisions AS authority ON authority.singleton = 1
  JOIN restore_state AS restore ON restore.singleton = 1 AND restore.pending_admission = 0
  WHERE source.request_digest = NEW.request_digest
    AND source.attempt_id = NEW.attempt_id
    AND source.execution_envelope_id = NEW.execution_envelope_id
    AND attempt.variant_id = NEW.variant_id
    AND attempt.fence = NEW.attempt_fence
    AND attempt.runner_id = NEW.runner_id
    AND attempt.runner_epoch = NEW.runner_epoch
    AND attempt.workspace_id = NEW.workspace_id
    AND attempt.scope_revision = NEW.scope_revision
    AND attempt.context_revision = NEW.context_revision
    AND authority.scope_digest = NEW.scope_grant_digest
    AND authority.authority_epoch = NEW.authority_epoch
    AND authority.freeze_generation = NEW.freeze_generation
)
BEGIN
  SELECT RAISE(ABORT, 'stale Candidate-preparation grant authority');
END;

CREATE TRIGGER candidate_preparation_grants_no_update
BEFORE UPDATE ON candidate_preparation_grants
BEGIN
  SELECT RAISE(ABORT, 'Candidate-preparation grant update is forbidden');
END;

CREATE TRIGGER candidate_preparation_grants_no_delete
BEFORE DELETE ON candidate_preparation_grants
BEGIN
  SELECT RAISE(ABORT, 'Candidate-preparation grant deletion is forbidden');
END;

CREATE TABLE candidate_preparation_nonce_consumptions (
  grant_nonce TEXT PRIMARY KEY REFERENCES candidate_preparation_grants(grant_nonce),
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  consumed_at TEXT NOT NULL
);

CREATE TRIGGER candidate_preparation_nonce_consumptions_insert_guard
BEFORE INSERT ON candidate_preparation_nonce_consumptions
WHEN NOT EXISTS (
  SELECT 1
  FROM candidate_preparation_grants AS grant
  JOIN attempts AS attempt ON attempt.id = grant.attempt_id
  JOIN active_leases AS lease
    ON lease.attempt_id = attempt.id
   AND lease.variant_id = attempt.variant_id
   AND lease.fence = attempt.fence
   AND lease.runner_id = attempt.runner_id
   AND lease.runner_epoch = attempt.runner_epoch
   AND lease.workspace_nonce = attempt.workspace_nonce
  JOIN authority_revisions AS authority ON authority.singleton = 1
  JOIN restore_state AS restore ON restore.singleton = 1 AND restore.pending_admission = 0
  WHERE grant.grant_nonce = NEW.grant_nonce
    AND grant.attempt_id = NEW.attempt_id
    AND grant.variant_id = attempt.variant_id
    AND grant.attempt_fence = attempt.fence
    AND grant.runner_id = attempt.runner_id
    AND grant.runner_epoch = attempt.runner_epoch
    AND grant.workspace_id = attempt.workspace_id
    AND grant.scope_revision = attempt.scope_revision
    AND grant.context_revision = attempt.context_revision
    AND grant.scope_grant_digest = authority.scope_digest
    AND grant.authority_epoch = authority.authority_epoch
    AND grant.freeze_generation = authority.freeze_generation
)
BEGIN
  SELECT RAISE(ABORT, 'stale Candidate-preparation nonce authority');
END;

CREATE TRIGGER candidate_preparation_nonce_consumptions_no_update
BEFORE UPDATE ON candidate_preparation_nonce_consumptions
BEGIN
  SELECT RAISE(ABORT, 'Candidate-preparation nonce update is forbidden');
END;

CREATE TRIGGER candidate_preparation_nonce_consumptions_no_delete
BEFORE DELETE ON candidate_preparation_nonce_consumptions
BEGIN
  SELECT RAISE(ABORT, 'Candidate-preparation nonce deletion is forbidden');
END;
