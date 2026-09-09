-- Durable presentation of an already-verified signed mutation permit.
-- The supported pre-1.0 path initializes a fresh database. Refuse any direct
-- schema-17 prototype upgrade that already contains mutation rows because its
-- missing authority fields cannot be reconstructed truthfully.

CREATE TABLE mutation_authority_v18_upgrade_guard (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  existing_rows INTEGER NOT NULL CHECK (existing_rows = 0)
);

INSERT INTO mutation_authority_v18_upgrade_guard (singleton, existing_rows)
SELECT 1,
  (SELECT COUNT(*) FROM mutation_authority)
  + (SELECT COUNT(*) FROM active_leases)
  + (SELECT COUNT(*) FROM lease_authority_fingerprints);

DROP TABLE mutation_authority_v18_upgrade_guard;

ALTER TABLE lease_authority_fingerprints ADD COLUMN graph_revision INTEGER CHECK (
  typeof(graph_revision) = 'integer'
  AND graph_revision BETWEEN 1 AND 9007199254740991
);
ALTER TABLE lease_authority_fingerprints ADD COLUMN workspace_generation INTEGER CHECK (
  typeof(workspace_generation) = 'integer'
  AND workspace_generation BETWEEN 1 AND 9007199254740991
);
ALTER TABLE lease_authority_fingerprints ADD COLUMN scope_digest TEXT CHECK (
  typeof(scope_digest) = 'text'
  AND length(scope_digest) = 64
  AND length(CAST(scope_digest AS BLOB)) = 64
  AND scope_digest NOT GLOB '*[^0123456789abcdef]*'
);
ALTER TABLE lease_authority_fingerprints ADD COLUMN policy_generation INTEGER CHECK (
  typeof(policy_generation) = 'integer'
  AND policy_generation BETWEEN 1 AND 9007199254740991
);
ALTER TABLE lease_authority_fingerprints ADD COLUMN routing_generation INTEGER CHECK (
  typeof(routing_generation) = 'integer'
  AND routing_generation BETWEEN 1 AND 9007199254740991
);

DROP TRIGGER lease_authority_capture;

CREATE TRIGGER lease_authority_capture
AFTER INSERT ON active_leases
BEGIN
  INSERT INTO lease_authority_fingerprints (
    attempt_id, variant_id, fence, authority_epoch, freeze_generation, restore_epoch, issued_at,
    graph_revision, workspace_generation, scope_digest, policy_generation, routing_generation
  ) SELECT
    NEW.attempt_id, NEW.variant_id, NEW.fence, authority_epoch, freeze_generation,
    restore_epoch, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), graph_revision,
    workspace_generation, scope_digest, policy_generation, routing_generation
  FROM authority_revisions, restore_state
  WHERE authority_revisions.singleton = 1 AND restore_state.singleton = 1
    AND restore_state.pending_admission = 0;
END;

ALTER TABLE mutation_authority ADD COLUMN graph_revision INTEGER CHECK (
  typeof(graph_revision) = 'integer'
  AND graph_revision BETWEEN 1 AND 9007199254740991
);
ALTER TABLE mutation_authority ADD COLUMN workspace_generation INTEGER CHECK (
  typeof(workspace_generation) = 'integer'
  AND workspace_generation BETWEEN 1 AND 9007199254740991
);
ALTER TABLE mutation_authority ADD COLUMN scope_digest TEXT CHECK (
  typeof(scope_digest) = 'text'
  AND length(scope_digest) = 64
  AND length(CAST(scope_digest AS BLOB)) = 64
  AND scope_digest NOT GLOB '*[^0123456789abcdef]*'
);
ALTER TABLE mutation_authority ADD COLUMN policy_generation INTEGER CHECK (
  typeof(policy_generation) = 'integer'
  AND policy_generation BETWEEN 1 AND 9007199254740991
);
ALTER TABLE mutation_authority ADD COLUMN routing_generation INTEGER CHECK (
  typeof(routing_generation) = 'integer'
  AND routing_generation BETWEEN 1 AND 9007199254740991
);

CREATE TABLE mutation_permit_presentations (
  mutation_id TEXT PRIMARY KEY REFERENCES mutation_authority(mutation_id),
  reservation_id TEXT NOT NULL UNIQUE,
  operation TEXT NOT NULL,
  request_digest TEXT NOT NULL CHECK (
    length(request_digest) = 64
    AND request_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  signed_permit_bytes BLOB NOT NULL CHECK (
    typeof(signed_permit_bytes) = 'blob'
    AND length(signed_permit_bytes) BETWEEN 1 AND 33792
  ),
  permit_digest TEXT NOT NULL CHECK (
    length(permit_digest) = 64
    AND permit_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  claims_bytes BLOB NOT NULL CHECK (
    typeof(claims_bytes) = 'blob'
    AND length(claims_bytes) BETWEEN 1 AND 32768
  ),
  claims_digest TEXT NOT NULL CHECK (
    length(claims_digest) = 64
    AND claims_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  schema_version TEXT NOT NULL CHECK (schema_version = 'v1alpha1'),
  issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 128),
  key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
  audience TEXT NOT NULL CHECK (audience IN ('bullet-gitd', 'effect-broker')),
  authority_envelope_digest TEXT NOT NULL CHECK (
    length(authority_envelope_digest) = 64
    AND authority_envelope_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  authority_token_nonce TEXT NOT NULL CHECK (
    length(authority_token_nonce) = 64
    AND authority_token_nonce NOT GLOB '*[^0123456789abcdef]*'
  ),
  permit_nonce TEXT NOT NULL UNIQUE CHECK (
    length(permit_nonce) = 64
    AND permit_nonce NOT GLOB '*[^0123456789abcdef]*'
  ),
  repository_id TEXT NOT NULL CHECK (
    length(repository_id) = 68 AND substr(repository_id, 1, 4) = 'rep_'
    AND substr(repository_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  workspace_id TEXT NOT NULL,
  workspace_generation INTEGER NOT NULL CHECK (
    workspace_generation BETWEEN 1 AND 9007199254740991
  ),
  attempt_id TEXT NOT NULL,
  attempt_fence INTEGER NOT NULL CHECK (attempt_fence BETWEEN 1 AND 9007199254740991),
  authority_epoch INTEGER NOT NULL CHECK (authority_epoch BETWEEN 1 AND 9007199254740991),
  freeze_generation INTEGER NOT NULL CHECK (freeze_generation BETWEEN 0 AND 9007199254740991),
  issued_at_unix_ms INTEGER NOT NULL CHECK (issued_at_unix_ms BETWEEN 0 AND 9007199254740991),
  not_before_unix_ms INTEGER NOT NULL CHECK (not_before_unix_ms BETWEEN 0 AND 9007199254740991),
  expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms BETWEEN 1 AND 9007199254740991),
  presented_at TEXT NOT NULL,
  CHECK (
    issued_at_unix_ms <= not_before_unix_ms
    AND not_before_unix_ms < expires_at_unix_ms
    AND expires_at_unix_ms - issued_at_unix_ms <= 1000
  ),
  CHECK (
    (operation IN ('dispatch-effect', 'reconcile-effect') AND audience = 'effect-broker')
    OR (
      operation NOT IN ('dispatch-effect', 'reconcile-effect')
      AND audience = 'bullet-gitd'
    )
  )
);

CREATE TRIGGER mutation_permit_presentations_insert_guard
BEFORE INSERT ON mutation_permit_presentations
WHEN NOT EXISTS (
  SELECT 1 FROM mutation_authority AS mutation, authority_revisions AS authority,
                restore_state AS restore
  WHERE mutation.mutation_id = NEW.mutation_id
    AND mutation.reservation_id = NEW.reservation_id
    AND mutation.operation = NEW.operation
    AND mutation.request_digest = NEW.request_digest
    AND mutation.workspace_id = NEW.workspace_id
    AND mutation.attempt_id = NEW.attempt_id
    AND mutation.fence = NEW.attempt_fence
    AND mutation.workspace_generation = NEW.workspace_generation
    AND mutation.authority_epoch = NEW.authority_epoch
    AND mutation.freeze_generation = NEW.freeze_generation
    AND mutation.disposition = 'RESERVED'
    AND authority.singleton = 1
    AND authority.graph_revision = mutation.graph_revision
    AND authority.workspace_generation = mutation.workspace_generation
    AND authority.scope_digest = mutation.scope_digest
    AND authority.policy_generation = mutation.policy_generation
    AND authority.routing_generation = mutation.routing_generation
    AND authority.authority_epoch = mutation.authority_epoch
    AND authority.freeze_generation = mutation.freeze_generation
    AND restore.singleton = 1
    AND restore.restore_epoch = mutation.restore_epoch
    AND restore.pending_admission = 0
)
BEGIN
  SELECT RAISE(ABORT, 'stale or unbound mutation permit presentation');
END;

CREATE TRIGGER mutation_permit_presentations_no_update
BEFORE UPDATE ON mutation_permit_presentations
BEGIN
  SELECT RAISE(ABORT, 'mutation permit presentation update is forbidden');
END;

CREATE TRIGGER mutation_permit_presentations_no_delete
BEFORE DELETE ON mutation_permit_presentations
BEGIN
  SELECT RAISE(ABORT, 'mutation permit presentation deletion is forbidden');
END;

DROP TRIGGER mutation_authority_fresh_lease_insert;
DROP TRIGGER mutation_authority_fresh_lease_consume;
DROP TRIGGER mutation_authority_legal_update;
DROP TRIGGER mutation_authority_authority_invalidation;

CREATE TRIGGER mutation_authority_fresh_lease_insert
BEFORE INSERT ON mutation_authority
WHEN NOT EXISTS (
  SELECT 1 FROM lease_authority_fingerprints AS lease_binding,
                authority_revisions AS authority, restore_state AS restore
  WHERE lease_binding.attempt_id = NEW.attempt_id
    AND lease_binding.variant_id = NEW.variant_id
    AND lease_binding.fence = NEW.fence
    AND lease_binding.authority_epoch = NEW.authority_epoch
    AND lease_binding.freeze_generation = NEW.freeze_generation
    AND lease_binding.restore_epoch = NEW.restore_epoch
    AND lease_binding.graph_revision = NEW.graph_revision
    AND lease_binding.workspace_generation = NEW.workspace_generation
    AND lease_binding.scope_digest = NEW.scope_digest
    AND lease_binding.policy_generation = NEW.policy_generation
    AND lease_binding.routing_generation = NEW.routing_generation
    AND authority.singleton = 1
    AND authority.graph_revision = NEW.graph_revision
    AND authority.workspace_generation = NEW.workspace_generation
    AND authority.scope_digest = NEW.scope_digest
    AND authority.policy_generation = NEW.policy_generation
    AND authority.routing_generation = NEW.routing_generation
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
    SELECT 1 FROM mutation_permit_presentations AS presentation
    WHERE presentation.mutation_id = OLD.mutation_id
      AND presentation.reservation_id = OLD.reservation_id
      AND presentation.operation = OLD.operation
      AND presentation.request_digest = OLD.request_digest
  )
BEGIN
  SELECT RAISE(ABORT, 'mutation permit presentation is required before consumption');
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
  OR NEW.graph_revision IS NOT OLD.graph_revision
  OR NEW.workspace_generation IS NOT OLD.workspace_generation
  OR NEW.scope_digest IS NOT OLD.scope_digest
  OR NEW.policy_generation IS NOT OLD.policy_generation
  OR NEW.routing_generation IS NOT OLD.routing_generation
  OR NEW.created_at != OLD.created_at
  OR NOT (
    (OLD.disposition = 'RESERVED' AND NEW.disposition IN ('CONSUMED', 'INVALIDATED'))
    OR (OLD.disposition = 'CONSUMED' AND NEW.disposition IN ('SETTLED', 'UNKNOWN'))
  )
BEGIN
  SELECT RAISE(ABORT, 'illegal mutation authority update');
END;

CREATE TRIGGER mutation_authority_authority_invalidation
AFTER UPDATE OF graph_revision, workspace_generation, scope_digest,
                policy_generation, routing_generation, authority_epoch,
                freeze_generation ON authority_revisions
WHEN NEW.graph_revision != OLD.graph_revision
  OR NEW.workspace_generation != OLD.workspace_generation
  OR NEW.scope_digest != OLD.scope_digest
  OR NEW.policy_generation != OLD.policy_generation
  OR NEW.routing_generation != OLD.routing_generation
  OR NEW.authority_epoch != OLD.authority_epoch
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
