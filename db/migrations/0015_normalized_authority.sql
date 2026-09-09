-- Normalized authority rows. Counters are integers; grants and denials are
-- text enumerations. This file does not contain INSERT OR REPLACE.

CREATE TABLE authority_revisions (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  graph_revision INTEGER NOT NULL CHECK (
    typeof(graph_revision) = 'integer' AND graph_revision >= 1
  ),
  workspace_generation INTEGER NOT NULL CHECK (
    typeof(workspace_generation) = 'integer' AND workspace_generation >= 1
  ),
  scope_digest TEXT NOT NULL CHECK (
    typeof(scope_digest) = 'text' AND length(scope_digest) = 64
  ),
  policy_generation INTEGER NOT NULL CHECK (
    typeof(policy_generation) = 'integer' AND policy_generation >= 1
  ),
  routing_generation INTEGER NOT NULL CHECK (
    typeof(routing_generation) = 'integer' AND routing_generation >= 1
  ),
  authority_epoch INTEGER NOT NULL CHECK (
    typeof(authority_epoch) = 'integer' AND authority_epoch >= 1
  ),
  freeze_generation INTEGER NOT NULL CHECK (
    typeof(freeze_generation) = 'integer' AND freeze_generation >= 0
  )
);
