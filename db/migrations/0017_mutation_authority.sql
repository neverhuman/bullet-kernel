-- One-use repository mutation authority. Identity columns never change; only
-- the closed state machine may advance. Freeze/authority or restore movement
-- invalidates every non-terminal row in the same database transaction.

CREATE TABLE lease_authority_fingerprints (
  attempt_id TEXT PRIMARY KEY REFERENCES attempts(id) CHECK (
    length(attempt_id) = 68 AND substr(attempt_id, 1, 4) = 'atm_'
    AND substr(attempt_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  variant_id TEXT NOT NULL CHECK (
    length(variant_id) = 68 AND substr(variant_id, 1, 4) = 'var_'
    AND substr(variant_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  fence INTEGER NOT NULL CHECK (fence BETWEEN 1 AND 9007199254740991),
  authority_epoch INTEGER NOT NULL CHECK (authority_epoch BETWEEN 1 AND 9007199254740991),
  freeze_generation INTEGER NOT NULL CHECK (freeze_generation BETWEEN 0 AND 9007199254740991),
  restore_epoch INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9007199254740991),
  issued_at TEXT NOT NULL,
  UNIQUE (variant_id, fence)
);

CREATE TRIGGER lease_authority_requires_admission
BEFORE INSERT ON active_leases
WHEN NOT EXISTS (SELECT 1 FROM authority_revisions WHERE singleton = 1)
  OR NOT EXISTS (
    SELECT 1 FROM restore_state WHERE singleton = 1 AND pending_admission = 0
  )
BEGIN
  SELECT RAISE(ABORT, 'lease authority requires restore admission');
END;

CREATE TRIGGER lease_authority_capture
AFTER INSERT ON active_leases
BEGIN
  INSERT INTO lease_authority_fingerprints (
    attempt_id, variant_id, fence, authority_epoch, freeze_generation, restore_epoch, issued_at
  ) SELECT
    NEW.attempt_id, NEW.variant_id, NEW.fence, authority_epoch, freeze_generation,
    restore_epoch, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM authority_revisions, restore_state
  WHERE authority_revisions.singleton = 1 AND restore_state.singleton = 1
    AND restore_state.pending_admission = 0;
END;

CREATE TRIGGER lease_authority_fingerprints_no_update
BEFORE UPDATE ON lease_authority_fingerprints
BEGIN
  SELECT RAISE(ABORT, 'lease authority fingerprint update is forbidden');
END;

CREATE TRIGGER lease_authority_fingerprints_no_delete
BEFORE DELETE ON lease_authority_fingerprints
BEGIN
  SELECT RAISE(ABORT, 'lease authority fingerprint deletion is forbidden');
END;

CREATE TABLE mutation_authority (
  reservation_id TEXT PRIMARY KEY CHECK (
    typeof(reservation_id) = 'text' AND length(reservation_id) = 68
    AND substr(reservation_id, 1, 4) = 'rsv_'
    AND substr(reservation_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  mutation_id TEXT NOT NULL UNIQUE CHECK (
    typeof(mutation_id) = 'text' AND length(mutation_id) = 68
    AND substr(mutation_id, 1, 4) = 'mut_'
    AND substr(mutation_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  operation TEXT NOT NULL CHECK (
    operation IN (
      'clone-workspace', 'read-workspace', 'apply-patch', 'checkpoint',
      'prepare-candidate', 'preserve-workspace', 'cleanup-workspace',
      'dispatch-effect', 'reconcile-effect'
    )
  ),
  request_digest TEXT NOT NULL CHECK (
    typeof(request_digest) = 'text' AND length(request_digest) = 64
    AND request_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  variant_id TEXT NOT NULL CHECK (
    length(variant_id) = 68 AND substr(variant_id, 1, 4) = 'var_'
    AND substr(variant_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  attempt_id TEXT NOT NULL CHECK (
    length(attempt_id) = 68 AND substr(attempt_id, 1, 4) = 'atm_'
    AND substr(attempt_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  work_package_id TEXT NOT NULL CHECK (
    length(work_package_id) = 68 AND substr(work_package_id, 1, 4) = 'wpk_'
    AND substr(work_package_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  fence INTEGER NOT NULL CHECK (fence BETWEEN 1 AND 9007199254740991),
  runner_id TEXT NOT NULL CHECK (
    length(runner_id) = 68 AND substr(runner_id, 1, 4) = 'run_'
    AND substr(runner_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  runner_epoch INTEGER NOT NULL CHECK (runner_epoch BETWEEN 1 AND 9007199254740991),
  workspace_id TEXT NOT NULL CHECK (
    length(workspace_id) = 68 AND substr(workspace_id, 1, 4) = 'wsp_'
    AND substr(workspace_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  workspace_nonce BLOB NOT NULL CHECK (length(workspace_nonce) = 32),
  scope_revision INTEGER NOT NULL CHECK (scope_revision BETWEEN 1 AND 9007199254740991),
  context_revision INTEGER NOT NULL CHECK (context_revision BETWEEN 1 AND 9007199254740991),
  authority_epoch INTEGER NOT NULL CHECK (authority_epoch BETWEEN 1 AND 9007199254740991),
  freeze_generation INTEGER NOT NULL CHECK (freeze_generation BETWEEN 0 AND 9007199254740991),
  restore_epoch INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9007199254740991),
  disposition TEXT NOT NULL CHECK (
    disposition IN ('RESERVED', 'CONSUMED', 'SETTLED', 'UNKNOWN', 'INVALIDATED')
  ),
  completion_digest TEXT CHECK (
    completion_digest IS NULL OR (
      typeof(completion_digest) = 'text' AND length(completion_digest) = 64
      AND completion_digest NOT GLOB '*[^0123456789abcdef]*'
    )
  ),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (
    (disposition IN ('RESERVED', 'CONSUMED', 'INVALIDATED') AND completion_digest IS NULL)
    OR (disposition IN ('SETTLED', 'UNKNOWN') AND completion_digest IS NOT NULL)
  )
);

CREATE TRIGGER mutation_authority_fresh_lease_insert
BEFORE INSERT ON mutation_authority
WHEN NOT EXISTS (
  SELECT 1
  FROM lease_authority_fingerprints AS lease_binding,
       authority_revisions AS authority,
       restore_state AS restore
  WHERE lease_binding.attempt_id = NEW.attempt_id
    AND lease_binding.variant_id = NEW.variant_id
    AND lease_binding.fence = NEW.fence
    AND lease_binding.authority_epoch = NEW.authority_epoch
    AND lease_binding.freeze_generation = NEW.freeze_generation
    AND lease_binding.restore_epoch = NEW.restore_epoch
    AND authority.singleton = 1
    AND authority.authority_epoch = lease_binding.authority_epoch
    AND authority.freeze_generation = lease_binding.freeze_generation
    AND restore.singleton = 1
    AND restore.restore_epoch = lease_binding.restore_epoch
    AND restore.pending_admission = 0
)
BEGIN
  SELECT RAISE(ABORT, 'stale mutation authority issuance fingerprint');
END;

CREATE TRIGGER mutation_authority_fresh_lease_consume
BEFORE UPDATE OF disposition ON mutation_authority
WHEN OLD.disposition = 'RESERVED' AND NEW.disposition = 'CONSUMED'
  AND NOT EXISTS (
    SELECT 1
    FROM lease_authority_fingerprints AS lease_binding,
         authority_revisions AS authority,
         restore_state AS restore
    WHERE lease_binding.attempt_id = OLD.attempt_id
      AND lease_binding.variant_id = OLD.variant_id
      AND lease_binding.fence = OLD.fence
      AND lease_binding.authority_epoch = OLD.authority_epoch
      AND lease_binding.freeze_generation = OLD.freeze_generation
      AND lease_binding.restore_epoch = OLD.restore_epoch
      AND authority.singleton = 1
      AND authority.authority_epoch = lease_binding.authority_epoch
      AND authority.freeze_generation = lease_binding.freeze_generation
      AND restore.singleton = 1
      AND restore.restore_epoch = lease_binding.restore_epoch
      AND restore.pending_admission = 0
  )
BEGIN
  SELECT RAISE(ABORT, 'stale mutation authority consumption fingerprint');
END;

CREATE TRIGGER mutation_authority_no_delete
BEFORE DELETE ON mutation_authority
BEGIN
  SELECT RAISE(ABORT, 'mutation authority deletion is forbidden');
END;

CREATE TRIGGER mutation_authority_legal_update
BEFORE UPDATE ON mutation_authority
WHEN
  NEW.reservation_id != OLD.reservation_id
  OR NEW.mutation_id != OLD.mutation_id
  OR NEW.operation != OLD.operation
  OR NEW.request_digest != OLD.request_digest
  OR NEW.variant_id != OLD.variant_id
  OR NEW.attempt_id != OLD.attempt_id
  OR NEW.work_package_id != OLD.work_package_id
  OR NEW.fence != OLD.fence
  OR NEW.runner_id != OLD.runner_id
  OR NEW.runner_epoch != OLD.runner_epoch
  OR NEW.workspace_id != OLD.workspace_id
  OR NEW.workspace_nonce != OLD.workspace_nonce
  OR NEW.scope_revision != OLD.scope_revision
  OR NEW.context_revision != OLD.context_revision
  OR NEW.authority_epoch != OLD.authority_epoch
  OR NEW.freeze_generation != OLD.freeze_generation
  OR NEW.restore_epoch != OLD.restore_epoch
  OR NEW.created_at != OLD.created_at
  OR NOT (
    (OLD.disposition = 'RESERVED' AND NEW.disposition IN ('CONSUMED', 'INVALIDATED'))
    OR (OLD.disposition = 'CONSUMED' AND NEW.disposition IN ('SETTLED', 'UNKNOWN'))
  )
BEGIN
  SELECT RAISE(ABORT, 'illegal mutation authority update');
END;

CREATE TRIGGER mutation_authority_authority_invalidation
AFTER UPDATE OF authority_epoch, freeze_generation ON authority_revisions
WHEN NEW.authority_epoch != OLD.authority_epoch
  OR NEW.freeze_generation != OLD.freeze_generation
BEGIN
  UPDATE mutation_authority
  SET disposition = CASE disposition
        WHEN 'RESERVED' THEN 'INVALIDATED'
        ELSE 'UNKNOWN'
      END,
      completion_digest = CASE disposition
        WHEN 'CONSUMED' THEN 'f35886edaf2920da0a96810b4b9d040f9f73f47ca1f07c20d33b8e65e42505ac'
        ELSE NULL
      END,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition IN ('RESERVED', 'CONSUMED');
END;

CREATE TRIGGER mutation_authority_restore_invalidation
AFTER UPDATE OF restore_epoch, pending_admission ON restore_state
WHEN NEW.restore_epoch != OLD.restore_epoch
  OR NEW.pending_admission != OLD.pending_admission
BEGIN
  UPDATE mutation_authority
  SET disposition = CASE disposition
        WHEN 'RESERVED' THEN 'INVALIDATED'
        ELSE 'UNKNOWN'
      END,
      completion_digest = CASE disposition
        WHEN 'CONSUMED' THEN '769e04884c7a739a82d058e2b2cf5ba8f32c55ebcdc3576ef31aaeb1ff3fd897'
        ELSE NULL
      END,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition IN ('RESERVED', 'CONSUMED');
END;
