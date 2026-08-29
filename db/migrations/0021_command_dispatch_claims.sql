-- Durable ownership and read-back for public command dispatch. Claims bind
-- one exact command/outbox request to one registered Runner incarnation and
-- to the current authority/freeze/restore generations.

CREATE TABLE command_dispatch_claim_identity_contract (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  identity_format TEXT NOT NULL CHECK (
    identity_format = 'bullet.command-dispatch-claim.v1'
  )
);

INSERT INTO command_dispatch_claim_identity_contract (singleton, identity_format)
VALUES (1, 'bullet.command-dispatch-claim.v1');

CREATE TABLE command_dispatch_claims (
  claim_id TEXT PRIMARY KEY CHECK (
    typeof(claim_id) = 'text'
    AND length(claim_id) = 68
    AND substr(claim_id, 1, 4) = 'dcl_'
    AND substr(claim_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  command_id TEXT NOT NULL UNIQUE REFERENCES commands(id),
  outbox_sequence INTEGER NOT NULL UNIQUE REFERENCES outbox(seq) CHECK (
    typeof(outbox_sequence) = 'integer'
    AND outbox_sequence BETWEEN 1 AND 9007199254740991
  ),
  request_digest TEXT NOT NULL CHECK (
    typeof(request_digest) = 'text'
    AND length(request_digest) = 64
    AND request_digest NOT GLOB '*[^0-9a-f]*'
  ),
  runner_id TEXT NOT NULL CHECK (
    typeof(runner_id) = 'text'
    AND length(runner_id) = 68
    AND substr(runner_id, 1, 4) = 'run_'
    AND substr(runner_id, 5) NOT GLOB '*[^0-9a-f]*'
  ),
  runner_epoch INTEGER NOT NULL CHECK (
    typeof(runner_epoch) = 'integer'
    AND runner_epoch BETWEEN 1 AND 9007199254740991
  ),
  authority_epoch INTEGER NOT NULL CHECK (
    typeof(authority_epoch) = 'integer'
    AND authority_epoch BETWEEN 1 AND 9007199254740991
  ),
  freeze_generation INTEGER NOT NULL CHECK (
    typeof(freeze_generation) = 'integer'
    AND freeze_generation BETWEEN 0 AND 9007199254740991
  ),
  restore_epoch INTEGER NOT NULL CHECK (
    typeof(restore_epoch) = 'integer'
    AND restore_epoch BETWEEN 0 AND 9007199254740991
  ),
  disposition TEXT NOT NULL CHECK (
    disposition IN ('CLAIMED', 'UNKNOWN', 'FAILED', 'INVALIDATED')
  ),
  completion_digest TEXT CHECK (
    completion_digest IS NULL
    OR (
      typeof(completion_digest) = 'text'
      AND length(completion_digest) = 64
      AND completion_digest NOT GLOB '*[^0-9a-f]*'
    )
  ),
  claimed_at TEXT NOT NULL CHECK (
    typeof(claimed_at) = 'text' AND length(claimed_at) BETWEEN 1 AND 64
  ),
  updated_at TEXT NOT NULL CHECK (
    typeof(updated_at) = 'text' AND length(updated_at) BETWEEN 1 AND 64
  ),
  CHECK (
    (disposition IN ('CLAIMED', 'INVALIDATED') AND completion_digest IS NULL)
    OR
    (disposition IN ('UNKNOWN', 'FAILED') AND completion_digest IS NOT NULL)
  )
);

CREATE UNIQUE INDEX command_dispatch_one_open_claim_per_runner_incarnation
ON command_dispatch_claims(runner_id, runner_epoch)
WHERE disposition = 'CLAIMED';

CREATE TRIGGER command_dispatch_claim_insert_guard
BEFORE INSERT ON command_dispatch_claims
WHEN NOT EXISTS (
  SELECT 1
  FROM commands AS command
  JOIN outbox AS dispatch
    ON dispatch.seq = NEW.outbox_sequence
   AND dispatch.command_id = command.id
  JOIN authority_revisions AS authority ON authority.singleton = 1
  JOIN restore_state AS restore ON restore.singleton = 1
  WHERE command.id = NEW.command_id
    AND command.payload_digest = NEW.request_digest
    AND command.phase = 'pending'
    AND command.response_json IS NULL
    AND dispatch.kind = 'command_dispatch'
    AND dispatch.phase = 'pending'
    AND dispatch.delivered_at IS NULL
    AND dispatch.acked_at IS NULL
    AND authority.authority_epoch = NEW.authority_epoch
    AND authority.freeze_generation = NEW.freeze_generation
    AND restore.restore_epoch = NEW.restore_epoch
    AND restore.pending_admission = 0
)
BEGIN
  SELECT RAISE(ABORT, 'command dispatch claim subject is stale or incomplete');
END;

CREATE TRIGGER command_dispatch_claim_update_guard
BEFORE UPDATE ON command_dispatch_claims
WHEN NEW.claim_id != OLD.claim_id
  OR NEW.command_id != OLD.command_id
  OR NEW.outbox_sequence != OLD.outbox_sequence
  OR NEW.request_digest != OLD.request_digest
  OR NEW.runner_id != OLD.runner_id
  OR NEW.runner_epoch != OLD.runner_epoch
  OR NEW.authority_epoch != OLD.authority_epoch
  OR NEW.freeze_generation != OLD.freeze_generation
  OR NEW.restore_epoch != OLD.restore_epoch
  OR NEW.claimed_at != OLD.claimed_at
  OR NOT (
    OLD.disposition = 'CLAIMED'
    AND NEW.disposition IN ('UNKNOWN', 'INVALIDATED')
  )
BEGIN
  SELECT RAISE(ABORT, 'command dispatch claim transition is forbidden');
END;

CREATE TRIGGER command_dispatch_claim_no_delete
BEFORE DELETE ON command_dispatch_claims
BEGIN
  SELECT RAISE(ABORT, 'command dispatch claim deletion is forbidden');
END;

CREATE TRIGGER command_dispatch_claim_authority_invalidation
AFTER UPDATE OF authority_epoch, freeze_generation ON authority_revisions
BEGIN
  UPDATE command_dispatch_claims
  SET disposition = 'INVALIDATED',
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition = 'CLAIMED'
    AND (
      authority_epoch != NEW.authority_epoch
      OR freeze_generation != NEW.freeze_generation
    );
END;

CREATE TRIGGER command_dispatch_claim_restore_invalidation
AFTER UPDATE OF restore_epoch, pending_admission ON restore_state
BEGIN
  UPDATE command_dispatch_claims
  SET disposition = 'INVALIDATED',
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition = 'CLAIMED'
    AND (
      restore_epoch != NEW.restore_epoch
      OR NEW.pending_admission != 0
    );
END;
