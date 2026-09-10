-- New public admissions gain ownership in their existing writer transaction.
-- Historical commands deliberately remain unowned; no rows are backfilled.
CREATE TABLE operator_command_ownership (
    command_id TEXT PRIMARY KEY NOT NULL REFERENCES commands(id),
    operator_id TEXT NOT NULL REFERENCES local_operator(operator_id),
    submitted_sequence INTEGER NOT NULL UNIQUE REFERENCES events(seq)
        CHECK (typeof(submitted_sequence) = 'integer' AND submitted_sequence > 0 AND submitted_sequence <= 9007199254740991),
    request_digest TEXT NOT NULL CHECK (typeof(request_digest) = 'text' AND length(CAST(request_digest AS BLOB)) = 64 AND length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
    admitted_at TEXT NOT NULL CHECK (typeof(admitted_at) = 'text' AND length(admitted_at) BETWEEN 20 AND 32)
);
CREATE INDEX operator_command_page ON operator_command_ownership(operator_id, submitted_sequence);
CREATE TRIGGER operator_command_owner_no_update BEFORE UPDATE ON operator_command_ownership
BEGIN SELECT RAISE(ABORT, 'OPERATOR_COMMAND_OWNER_IMMUTABLE'); END;
CREATE TRIGGER operator_command_owner_no_delete BEFORE DELETE ON operator_command_ownership
BEGIN SELECT RAISE(ABORT, 'OPERATOR_COMMAND_OWNER_IMMUTABLE'); END;
CREATE TRIGGER operator_command_owner_no_replace BEFORE INSERT ON operator_command_ownership
WHEN EXISTS (SELECT 1 FROM operator_command_ownership WHERE command_id = NEW.command_id OR submitted_sequence = NEW.submitted_sequence)
BEGIN SELECT RAISE(ABORT, 'OPERATOR_COMMAND_OWNER_IMMUTABLE'); END;
