CREATE TABLE restore_state (
  singleton              INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  restore_epoch          INTEGER NOT NULL CHECK (
    typeof(restore_epoch) = 'integer' AND restore_epoch >= 0
  ),
  pending_admission      INTEGER NOT NULL CHECK (
    typeof(pending_admission) = 'integer' AND pending_admission IN (0, 1)
  ),
  source_snapshot_digest TEXT,
  restored_at            TEXT,
  CHECK (
    (restore_epoch = 0 AND pending_admission = 0
      AND source_snapshot_digest IS NULL AND restored_at IS NULL)
    OR
    (restore_epoch > 0 AND source_snapshot_digest IS NOT NULL
      AND restored_at IS NOT NULL)
  )
);

INSERT INTO restore_state (
  singleton, restore_epoch, pending_admission, source_snapshot_digest, restored_at
) VALUES (1, 0, 0, NULL, NULL);
