-- Immutable revision-one Context Capsules. Plan materialization creates one
-- normalized row per package in the same transaction as graph/ready/event
-- truth. Later capsule evolution requires a new schema and append protocol.

CREATE TABLE context_capsules (
  id               TEXT PRIMARY KEY CHECK (
    typeof(id) = 'text'
    AND length(id) = 68
    AND substr(id, 1, 4) = 'ctx_'
    AND substr(id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  mission_id       TEXT NOT NULL CHECK (
    typeof(mission_id) = 'text'
    AND length(mission_id) = 68
    AND substr(mission_id, 1, 4) = 'mis_'
    AND substr(mission_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  work_package_id  TEXT NOT NULL CHECK (
    typeof(work_package_id) = 'text'
    AND length(work_package_id) = 68
    AND substr(work_package_id, 1, 4) = 'wpk_'
    AND substr(work_package_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  plan_revision_id TEXT NOT NULL CHECK (
    typeof(plan_revision_id) = 'text'
    AND length(plan_revision_id) = 68
    AND substr(plan_revision_id, 1, 4) = 'pln_'
    AND substr(plan_revision_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  revision         INTEGER NOT NULL CHECK (
    typeof(revision) = 'integer' AND revision = 1
  ),
  task_class       TEXT NOT NULL CHECK (task_class IN (
    'deterministic_transform', 'extract_structured', 'classify_route',
    'summarize_local', 'compress_context', 'mechanical_code_edit',
    'bounded_bug_fix', 'feature_implementation', 'broad_refactor',
    'architecture_design', 'security_analysis', 'migration_design',
    'code_review', 'fusion_rank', 'fusion_synthesize',
    'completion_assessment'
  )),
  objective        TEXT NOT NULL,
  package_title    TEXT NOT NULL,
  content_digest   TEXT NOT NULL CHECK (
    typeof(content_digest) = 'text'
    AND length(content_digest) = 64
    AND content_digest NOT GLOB '*[^0-9a-f]*'
  ),
  recorded_at      TEXT NOT NULL,
  UNIQUE(work_package_id, revision)
);

CREATE INDEX context_capsules_mission
  ON context_capsules(mission_id, work_package_id, revision);

