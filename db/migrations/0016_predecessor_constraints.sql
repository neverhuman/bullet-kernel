-- Append-only repair for the component reservation and normalized-authority
-- tables introduced by 0014/0015. These remain fresh-schema predecessors;
-- no durable application write port is claimed by this migration.

CREATE TABLE budget_reservations_next (
  reservation_id TEXT PRIMARY KEY CHECK (
    typeof(reservation_id) = 'text'
    AND length(reservation_id) > 0
  ),
  amount INTEGER NOT NULL CHECK (
    typeof(amount) = 'integer'
    AND amount BETWEEN 1 AND 9223372036854775807
  ),
  settled_amount INTEGER CHECK (
    settled_amount IS NULL
    OR (
      typeof(settled_amount) = 'integer'
      AND settled_amount BETWEEN 0 AND 9223372036854775807
    )
  ),
  unknown_liability INTEGER NOT NULL DEFAULT 0 CHECK (
    typeof(unknown_liability) = 'integer'
    AND unknown_liability BETWEEN 0 AND 9223372036854775807
  )
);

INSERT INTO budget_reservations_next (
  reservation_id, amount, settled_amount, unknown_liability
)
SELECT reservation_id, amount, settled_amount, unknown_liability
FROM budget_reservations;

DROP TABLE budget_reservations;
ALTER TABLE budget_reservations_next RENAME TO budget_reservations;

CREATE TABLE authority_revisions_next (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  graph_revision INTEGER NOT NULL CHECK (
    typeof(graph_revision) = 'integer'
    AND graph_revision BETWEEN 1 AND 9223372036854775807
  ),
  workspace_generation INTEGER NOT NULL CHECK (
    typeof(workspace_generation) = 'integer'
    AND workspace_generation BETWEEN 1 AND 9223372036854775807
  ),
  scope_digest TEXT NOT NULL CHECK (
    typeof(scope_digest) = 'text'
    AND length(scope_digest) = 64
    AND length(CAST(scope_digest AS BLOB)) = 64
    AND scope_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  policy_generation INTEGER NOT NULL CHECK (
    typeof(policy_generation) = 'integer'
    AND policy_generation BETWEEN 1 AND 9223372036854775807
  ),
  routing_generation INTEGER NOT NULL CHECK (
    typeof(routing_generation) = 'integer'
    AND routing_generation BETWEEN 1 AND 9223372036854775807
  ),
  authority_epoch INTEGER NOT NULL CHECK (
    typeof(authority_epoch) = 'integer'
    AND authority_epoch BETWEEN 1 AND 9223372036854775807
  ),
  freeze_generation INTEGER NOT NULL CHECK (
    typeof(freeze_generation) = 'integer'
    AND freeze_generation BETWEEN 0 AND 9223372036854775807
  )
);

INSERT INTO authority_revisions_next (
  singleton, graph_revision, workspace_generation, scope_digest,
  policy_generation, routing_generation, authority_epoch, freeze_generation
)
SELECT
  singleton, graph_revision, workspace_generation, scope_digest,
  policy_generation, routing_generation, authority_epoch, freeze_generation
FROM authority_revisions;

DROP TABLE authority_revisions;
ALTER TABLE authority_revisions_next RENAME TO authority_revisions;

CREATE TRIGGER authority_revisions_monotonic_update
BEFORE UPDATE ON authority_revisions
WHEN
  NEW.graph_revision < OLD.graph_revision
  OR NEW.workspace_generation < OLD.workspace_generation
  OR NEW.policy_generation < OLD.policy_generation
  OR NEW.routing_generation < OLD.routing_generation
  OR NEW.authority_epoch < OLD.authority_epoch
  OR NEW.freeze_generation < OLD.freeze_generation
  OR (
    NEW.scope_digest != OLD.scope_digest
    AND NEW.authority_epoch <= OLD.authority_epoch
  )
BEGIN
  SELECT RAISE(ABORT, 'authority revision regression');
END;

CREATE TRIGGER authority_revisions_no_delete
BEFORE DELETE ON authority_revisions
BEGIN
  SELECT RAISE(ABORT, 'authority revision deletion is forbidden');
END;

CREATE TRIGGER authority_revisions_no_second_insert
BEFORE INSERT ON authority_revisions
WHEN EXISTS (SELECT 1 FROM authority_revisions WHERE singleton = 1)
BEGIN
  SELECT RAISE(ABORT, 'authority revision replacement is forbidden');
END;
