-- Digest-only local operator authority. Existing bootstrap/session rows are
-- immutable; consumption is the unique bootstrap binding of an issued session.
CREATE TABLE local_operator (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    operator_id TEXT NOT NULL UNIQUE CHECK (typeof(operator_id) = 'text' AND length(CAST(operator_id AS BLOB)) = 68 AND length(operator_id) = 68 AND substr(operator_id, 1, 4) = 'opr_' AND substr(operator_id, 5) NOT GLOB '*[^0-9a-f]*'),
    created_at INTEGER NOT NULL CHECK (typeof(created_at) = 'integer' AND created_at >= 0 AND created_at <= 253402300799)
);
CREATE TABLE operator_bootstraps (
    digest TEXT PRIMARY KEY NOT NULL CHECK (typeof(digest) = 'text' AND length(CAST(digest AS BLOB)) = 64 AND length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'),
    operator_id TEXT NOT NULL REFERENCES local_operator(operator_id),
    origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 256),
    issued_at INTEGER NOT NULL CHECK (typeof(issued_at) = 'integer' AND issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (typeof(expires_at) = 'integer' AND expires_at > issued_at AND expires_at - issued_at <= 600 AND expires_at <= 253402300799),
    restore_epoch INTEGER NOT NULL CHECK (typeof(restore_epoch) = 'integer' AND restore_epoch >= 0),
    UNIQUE (digest, operator_id, origin, restore_epoch)
);
CREATE TABLE operator_sessions (
    session_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(session_id) = 'text' AND length(CAST(session_id AS BLOB)) = 68 AND length(session_id) = 68 AND substr(session_id, 1, 4) = 'sid_' AND substr(session_id, 5) NOT GLOB '*[^0-9a-f]*'),
    bootstrap_digest TEXT NOT NULL UNIQUE,
    operator_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    restore_epoch INTEGER NOT NULL CHECK (typeof(restore_epoch) = 'integer' AND restore_epoch >= 0),
    bearer_digest TEXT NOT NULL UNIQUE CHECK (typeof(bearer_digest) = 'text' AND length(CAST(bearer_digest AS BLOB)) = 64 AND length(bearer_digest) = 64 AND bearer_digest NOT GLOB '*[^0-9a-f]*'),
    csrf_digest TEXT NOT NULL UNIQUE CHECK (typeof(csrf_digest) = 'text' AND length(CAST(csrf_digest AS BLOB)) = 64 AND length(csrf_digest) = 64 AND csrf_digest NOT GLOB '*[^0-9a-f]*'),
    issued_at INTEGER NOT NULL CHECK (typeof(issued_at) = 'integer' AND issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (typeof(expires_at) = 'integer' AND expires_at > issued_at AND expires_at - issued_at <= 28800 AND expires_at <= 253402300799),
    FOREIGN KEY (bootstrap_digest, operator_id, origin, restore_epoch) REFERENCES operator_bootstraps(digest, operator_id, origin, restore_epoch),
    UNIQUE (session_id, operator_id)
);
CREATE TABLE operator_session_revocations (
    session_id TEXT PRIMARY KEY NOT NULL,
    operator_id TEXT NOT NULL,
    revoked_at INTEGER NOT NULL CHECK (typeof(revoked_at) = 'integer' AND revoked_at >= 0 AND revoked_at <= 253402300799),
    FOREIGN KEY (session_id, operator_id) REFERENCES operator_sessions(session_id, operator_id)
);
CREATE TRIGGER local_operator_no_update BEFORE UPDATE ON local_operator
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER local_operator_no_delete BEFORE DELETE ON local_operator
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_bootstraps_no_update BEFORE UPDATE ON operator_bootstraps
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_bootstraps_no_delete BEFORE DELETE ON operator_bootstraps
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_sessions_no_update BEFORE UPDATE ON operator_sessions
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_sessions_no_delete BEFORE DELETE ON operator_sessions
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_session_revocations_no_update BEFORE UPDATE ON operator_session_revocations
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_session_revocations_no_delete BEFORE DELETE ON operator_session_revocations
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER local_operator_no_replace BEFORE INSERT ON local_operator
WHEN EXISTS (SELECT 1 FROM local_operator)
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_bootstraps_no_replace BEFORE INSERT ON operator_bootstraps
WHEN EXISTS (SELECT 1 FROM operator_bootstraps WHERE digest = NEW.digest)
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_sessions_no_replace BEFORE INSERT ON operator_sessions
WHEN EXISTS (SELECT 1 FROM operator_sessions WHERE session_id = NEW.session_id OR bootstrap_digest = NEW.bootstrap_digest OR bearer_digest = NEW.bearer_digest OR csrf_digest = NEW.csrf_digest)
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
CREATE TRIGGER operator_session_revocations_no_replace BEFORE INSERT ON operator_session_revocations
WHEN EXISTS (SELECT 1 FROM operator_session_revocations WHERE session_id = NEW.session_id)
BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_IMMUTABLE'); END;
