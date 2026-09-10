-- Requested work is durable before any runnable admission or execution authority.
-- Historical commands remain unchanged and acquire no invented task bindings.
CREATE TABLE coding_task_revisions (
    revision_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(revision_id) = 'text' AND length(CAST(revision_id AS BLOB)) = 68 AND substr(revision_id, 1, 4) = 'ctr_' AND substr(revision_id, 5) NOT GLOB '*[^0-9a-f]*'),
    operator_id TEXT NOT NULL REFERENCES local_operator(operator_id),
    task_json TEXT NOT NULL CHECK (typeof(task_json) = 'text' AND length(CAST(task_json AS BLOB)) BETWEEN 2 AND 262144 AND json_valid(task_json) AND json_type(task_json) = 'object'),
    task_digest TEXT NOT NULL CHECK (typeof(task_digest) = 'text' AND length(CAST(task_digest AS BLOB)) = 64 AND task_digest NOT GLOB '*[^0-9a-f]*'),
    accepted_command_id TEXT NOT NULL UNIQUE REFERENCES commands(id),
    accepted_sequence INTEGER NOT NULL UNIQUE REFERENCES events(seq) CHECK (typeof(accepted_sequence) = 'integer' AND accepted_sequence BETWEEN 1 AND 9007199254740991),
    accepted_at TEXT NOT NULL CHECK (typeof(accepted_at) = 'text' AND length(accepted_at) BETWEEN 20 AND 32)
);
CREATE INDEX coding_task_owner ON coding_task_revisions(operator_id, accepted_sequence);
CREATE TABLE coding_task_dependencies (
    revision_id TEXT NOT NULL REFERENCES coding_task_revisions(revision_id),
    dependency_id TEXT NOT NULL REFERENCES coding_task_revisions(revision_id),
    PRIMARY KEY (revision_id, dependency_id),
    CHECK (revision_id <> dependency_id)
);
CREATE TABLE coding_runs (
    run_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(run_id) = 'text' AND length(CAST(run_id AS BLOB)) = 68 AND substr(run_id, 1, 4) = 'crn_' AND substr(run_id, 5) NOT GLOB '*[^0-9a-f]*'),
    command_id TEXT NOT NULL UNIQUE REFERENCES commands(id),
    operator_id TEXT NOT NULL REFERENCES local_operator(operator_id),
    task_revision_id TEXT NOT NULL REFERENCES coding_task_revisions(revision_id),
    request_digest TEXT NOT NULL CHECK (typeof(request_digest) = 'text' AND length(CAST(request_digest AS BLOB)) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
    selection_json TEXT NOT NULL CHECK (typeof(selection_json) = 'text' AND length(CAST(selection_json AS BLOB)) BETWEEN 2 AND 1024 AND json_valid(selection_json) AND json_type(selection_json) = 'object'),
    accepted_sequence INTEGER NOT NULL UNIQUE REFERENCES events(seq) CHECK (typeof(accepted_sequence) = 'integer' AND accepted_sequence BETWEEN 1 AND 9007199254740991),
    accepted_at TEXT NOT NULL CHECK (typeof(accepted_at) = 'text' AND length(accepted_at) BETWEEN 20 AND 32)
);
CREATE INDEX coding_run_task ON coding_runs(task_revision_id, accepted_sequence);
CREATE INDEX coding_run_owner ON coding_runs(operator_id, accepted_sequence);

CREATE TRIGGER coding_task_no_update BEFORE UPDATE ON coding_task_revisions
BEGIN SELECT RAISE(ABORT, 'CODING_TASK_IMMUTABLE'); END;
CREATE TRIGGER coding_task_no_delete BEFORE DELETE ON coding_task_revisions
BEGIN SELECT RAISE(ABORT, 'CODING_TASK_IMMUTABLE'); END;
CREATE TRIGGER coding_task_no_replace BEFORE INSERT ON coding_task_revisions
WHEN EXISTS (SELECT 1 FROM coding_task_revisions WHERE revision_id=NEW.revision_id OR accepted_command_id=NEW.accepted_command_id OR accepted_sequence=NEW.accepted_sequence)
BEGIN SELECT RAISE(ABORT, 'CODING_TASK_IMMUTABLE'); END;
CREATE TRIGGER coding_dependency_no_update BEFORE UPDATE ON coding_task_dependencies
BEGIN SELECT RAISE(ABORT, 'CODING_DEPENDENCY_IMMUTABLE'); END;
CREATE TRIGGER coding_dependency_no_delete BEFORE DELETE ON coding_task_dependencies
BEGIN SELECT RAISE(ABORT, 'CODING_DEPENDENCY_IMMUTABLE'); END;
CREATE TRIGGER coding_dependency_no_replace BEFORE INSERT ON coding_task_dependencies
WHEN EXISTS (SELECT 1 FROM coding_task_dependencies WHERE revision_id=NEW.revision_id AND dependency_id=NEW.dependency_id)
BEGIN SELECT RAISE(ABORT, 'CODING_DEPENDENCY_IMMUTABLE'); END;
CREATE TRIGGER coding_run_no_update BEFORE UPDATE ON coding_runs
BEGIN SELECT RAISE(ABORT, 'CODING_RUN_IMMUTABLE'); END;
CREATE TRIGGER coding_run_no_delete BEFORE DELETE ON coding_runs
BEGIN SELECT RAISE(ABORT, 'CODING_RUN_IMMUTABLE'); END;
CREATE TRIGGER coding_run_no_replace BEFORE INSERT ON coding_runs
WHEN EXISTS (SELECT 1 FROM coding_runs WHERE run_id=NEW.run_id OR command_id=NEW.command_id OR accepted_sequence=NEW.accepted_sequence)
BEGIN SELECT RAISE(ABORT, 'CODING_RUN_IMMUTABLE'); END;
