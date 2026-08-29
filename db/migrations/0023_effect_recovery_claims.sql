-- Restart-safe recovery claims for unresolved local-bare create-only Candidate
-- ref delivery. Claims bind the immutable original intent, exact successor
-- attempt/lease, full normalized authority, restore epoch, and a DB-owned
-- outbox sequence. Claim rows are append-only except for closed disposition
-- transitions and automatic stale-owner invalidation.

CREATE TABLE effect_recovery_claim_identity_contract (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  authority_format TEXT NOT NULL CHECK (
    authority_format = 'bullet.effect-recovery-authority.v1'
  ),
  claim_format TEXT NOT NULL CHECK (
    claim_format = 'bullet.effect-recovery-claim.v1'
  ),
  transition_format TEXT NOT NULL CHECK (
    transition_format = 'bullet.effect-recovery-transition.v1'
  ),
  receipt_format TEXT NOT NULL CHECK (
    receipt_format = 'bullet.effect-recovery-receipt.v1'
  )
);

INSERT INTO effect_recovery_claim_identity_contract (
  singleton, authority_format, claim_format, transition_format, receipt_format
) VALUES (
  1,
  'bullet.effect-recovery-authority.v1',
  'bullet.effect-recovery-claim.v1',
  'bullet.effect-recovery-transition.v1',
  'bullet.effect-recovery-receipt.v1'
);

CREATE TABLE effect_recovery_claims (
  claim_id TEXT PRIMARY KEY CHECK (
    typeof(claim_id) = 'text'
    AND length(claim_id) = 68
    AND substr(claim_id, 1, 4) = 'ecl_'
    AND substr(claim_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  effect_intent_id TEXT NOT NULL REFERENCES effect_intents(id) CHECK (
    length(effect_intent_id) = 68
    AND substr(effect_intent_id, 1, 4) = 'efi_'
    AND substr(effect_intent_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  claim_generation INTEGER NOT NULL CHECK (
    typeof(claim_generation) = 'integer'
    AND claim_generation BETWEEN 1 AND 9007199254740991
  ),
  outbox_sequence INTEGER NOT NULL UNIQUE REFERENCES outbox(seq) CHECK (
    typeof(outbox_sequence) = 'integer'
    AND outbox_sequence BETWEEN 1 AND 9007199254740991
  ),
  intent_payload_digest TEXT NOT NULL CHECK (
    typeof(intent_payload_digest) = 'text'
    AND length(intent_payload_digest) = 64
    AND intent_payload_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  intent_state TEXT NOT NULL CHECK (
    intent_state IN (
      'OUTCOME_UNKNOWN', 'DISPATCHING', 'COMMITTED',
      'ORPHANED_REMOTE', 'QUARANTINED'
    )
  ),
  intent_unknown_retries INTEGER NOT NULL CHECK (
    typeof(intent_unknown_retries) = 'integer'
    AND intent_unknown_retries BETWEEN 0 AND 1
  ),
  work_package_id TEXT NOT NULL CHECK (
    length(work_package_id) = 68
    AND substr(work_package_id, 1, 4) = 'wpk_'
    AND substr(work_package_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  original_attempt_id TEXT NOT NULL REFERENCES attempts(id) CHECK (
    length(original_attempt_id) = 68
    AND substr(original_attempt_id, 1, 4) = 'atm_'
    AND substr(original_attempt_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  original_variant_id TEXT NOT NULL CHECK (
    length(original_variant_id) = 68
    AND substr(original_variant_id, 1, 4) = 'var_'
    AND substr(original_variant_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  original_fence INTEGER NOT NULL CHECK (
    typeof(original_fence) = 'integer'
    AND original_fence BETWEEN 1 AND 9007199254740991
  ),
  successor_authority_digest TEXT NOT NULL CHECK (
    typeof(successor_authority_digest) = 'text'
    AND length(successor_authority_digest) = 64
    AND successor_authority_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  successor_authority_fingerprint TEXT NOT NULL CHECK (
    typeof(successor_authority_fingerprint) = 'text'
    AND length(successor_authority_fingerprint) = 64
    AND successor_authority_fingerprint NOT GLOB '*[^0123456789abcdef]*'
  ),
  recovery_attempt_id TEXT NOT NULL REFERENCES attempts(id) CHECK (
    length(recovery_attempt_id) = 68
    AND substr(recovery_attempt_id, 1, 4) = 'atm_'
    AND substr(recovery_attempt_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  recovery_variant_id TEXT NOT NULL CHECK (
    length(recovery_variant_id) = 68
    AND substr(recovery_variant_id, 1, 4) = 'var_'
    AND substr(recovery_variant_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  recovery_attempt_fence INTEGER NOT NULL CHECK (
    typeof(recovery_attempt_fence) = 'integer'
    AND recovery_attempt_fence BETWEEN 1 AND 9007199254740991
  ),
  recovery_runner_id TEXT NOT NULL CHECK (
    length(recovery_runner_id) = 68
    AND substr(recovery_runner_id, 1, 4) = 'run_'
    AND substr(recovery_runner_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  recovery_runner_epoch INTEGER NOT NULL CHECK (
    typeof(recovery_runner_epoch) = 'integer'
    AND recovery_runner_epoch BETWEEN 1 AND 9007199254740991
  ),
  recovery_workspace_id TEXT NOT NULL CHECK (
    length(recovery_workspace_id) = 68
    AND substr(recovery_workspace_id, 1, 4) = 'wsp_'
    AND substr(recovery_workspace_id, 5) NOT GLOB '*[^0123456789abcdef]*'
  ),
  recovery_workspace_nonce BLOB NOT NULL CHECK (
    typeof(recovery_workspace_nonce) = 'blob'
    AND length(recovery_workspace_nonce) = 32
  ),
  graph_revision INTEGER NOT NULL CHECK (
    typeof(graph_revision) = 'integer'
    AND graph_revision BETWEEN 1 AND 9007199254740991
  ),
  workspace_generation INTEGER NOT NULL CHECK (
    typeof(workspace_generation) = 'integer'
    AND workspace_generation BETWEEN 1 AND 9007199254740991
  ),
  scope_digest TEXT NOT NULL CHECK (
    typeof(scope_digest) = 'text'
    AND length(scope_digest) = 64
    AND length(CAST(scope_digest AS BLOB)) = 64
    AND scope_digest NOT GLOB '*[^0123456789abcdef]*'
  ),
  policy_generation INTEGER NOT NULL CHECK (
    typeof(policy_generation) = 'integer'
    AND policy_generation BETWEEN 1 AND 9007199254740991
  ),
  routing_generation INTEGER NOT NULL CHECK (
    typeof(routing_generation) = 'integer'
    AND routing_generation BETWEEN 1 AND 9007199254740991
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
    disposition IN (
      'CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN',
      'ADOPTED', 'ORPHANED', 'QUARANTINED', 'INVALIDATED'
    )
  ),
  invalidated_from TEXT CHECK (
    invalidated_from IS NULL
    OR invalidated_from IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN')
  ),
  receipt_id TEXT REFERENCES effect_receipts(id) CHECK (
    receipt_id IS NULL
    OR (
      length(receipt_id) = 68
      AND substr(receipt_id, 1, 4) = 'efr_'
      AND substr(receipt_id, 5) NOT GLOB '*[^0123456789abcdef]*'
    )
  ),
  containment_reason TEXT CHECK (
    containment_reason IS NULL
    OR containment_reason IN ('RETRY_SPENT_AFTER_ABSENCE', 'READBACK_UNAVAILABLE')
  ),
  claimed_at TEXT NOT NULL CHECK (
    typeof(claimed_at) = 'text'
    AND length(claimed_at) BETWEEN 1 AND 64
  ),
  updated_at TEXT NOT NULL CHECK (
    typeof(updated_at) = 'text'
    AND length(updated_at) BETWEEN 1 AND 64
  ),
  CHECK (
    (disposition = 'INVALIDATED' AND invalidated_from IS NOT NULL)
    OR (disposition != 'INVALIDATED' AND invalidated_from IS NULL)
  ),
  CHECK (
    (disposition = 'QUARANTINED' AND containment_reason IS NOT NULL)
    OR (disposition != 'QUARANTINED' AND containment_reason IS NULL)
  ),
  CHECK (
    (disposition = 'CLAIMED'
      AND intent_state = 'OUTCOME_UNKNOWN'
      AND intent_unknown_retries = 0)
    OR (disposition = 'RETRY_RESERVED'
      AND intent_state IN ('OUTCOME_UNKNOWN', 'DISPATCHING')
      AND intent_unknown_retries = 1)
    OR (disposition = 'READBACK_UNKNOWN'
      AND intent_state = 'OUTCOME_UNKNOWN'
      AND intent_unknown_retries BETWEEN 0 AND 1)
    OR (disposition = 'ADOPTED'
      AND intent_state = 'COMMITTED')
    OR (disposition = 'ORPHANED'
      AND intent_state = 'ORPHANED_REMOTE')
    OR (disposition = 'QUARANTINED'
      AND intent_state = 'QUARANTINED')
    OR (disposition = 'INVALIDATED'
      AND invalidated_from = 'CLAIMED'
      AND intent_state = 'OUTCOME_UNKNOWN'
      AND intent_unknown_retries = 0)
    OR (disposition = 'INVALIDATED'
      AND invalidated_from = 'RETRY_RESERVED'
      AND intent_state IN ('OUTCOME_UNKNOWN', 'DISPATCHING')
      AND intent_unknown_retries = 1)
    OR (disposition = 'INVALIDATED'
      AND invalidated_from = 'READBACK_UNKNOWN'
      AND intent_state = 'OUTCOME_UNKNOWN'
      AND intent_unknown_retries BETWEEN 0 AND 1)
  ),
  CHECK (
    (disposition IN ('CLAIMED', 'READBACK_UNKNOWN') AND receipt_id IS NULL)
    OR (disposition = 'RETRY_RESERVED' AND receipt_id IS NOT NULL)
    OR (disposition IN ('ADOPTED', 'ORPHANED') AND receipt_id IS NOT NULL)
    OR (
      disposition = 'QUARANTINED'
      AND containment_reason = 'RETRY_SPENT_AFTER_ABSENCE'
      AND receipt_id IS NOT NULL
    )
    OR (
      disposition = 'QUARANTINED'
      AND containment_reason = 'READBACK_UNAVAILABLE'
      AND receipt_id IS NULL
    )
    OR (
      disposition = 'INVALIDATED'
      AND invalidated_from = 'RETRY_RESERVED'
      AND receipt_id IS NOT NULL
    )
    OR (
      disposition = 'INVALIDATED'
      AND invalidated_from IN ('CLAIMED', 'READBACK_UNKNOWN')
      AND receipt_id IS NULL
    )
  )
);

CREATE UNIQUE INDEX effect_recovery_claim_generation_per_intent
ON effect_recovery_claims(effect_intent_id, claim_generation);

CREATE UNIQUE INDEX effect_recovery_one_active_claim_per_intent
ON effect_recovery_claims(effect_intent_id)
WHERE disposition IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN');

CREATE INDEX effect_recovery_claim_owner
ON effect_recovery_claims(recovery_runner_id, recovery_runner_epoch)
WHERE disposition IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN');

CREATE INDEX effect_recovery_claim_outbox
ON effect_recovery_claims(outbox_sequence);

CREATE INDEX effect_recovery_claim_receipt
ON effect_recovery_claims(receipt_id)
WHERE receipt_id IS NOT NULL;

CREATE TRIGGER effect_recovery_claim_insert_guard
BEFORE INSERT ON effect_recovery_claims
WHEN NOT EXISTS (
  SELECT 1
  FROM effect_intents AS intent
  JOIN attempts AS original
    ON original.id = intent.attempt_id
   AND original.id = NEW.original_attempt_id
   AND original.variant_id = NEW.original_variant_id
   AND original.work_package_id = NEW.work_package_id
   AND original.fence = intent.fence
   AND original.fence = NEW.original_fence
  JOIN attempts AS recovery
    ON recovery.id = NEW.recovery_attempt_id
   AND recovery.variant_id = NEW.recovery_variant_id
   AND recovery.variant_id = original.variant_id
   AND recovery.work_package_id = NEW.work_package_id
   AND recovery.fence = NEW.recovery_attempt_fence
   AND recovery.fence > original.fence
   AND recovery.runner_id = NEW.recovery_runner_id
   AND recovery.runner_epoch = NEW.recovery_runner_epoch
   AND recovery.workspace_id = NEW.recovery_workspace_id
   AND recovery.workspace_nonce = NEW.recovery_workspace_nonce
  JOIN active_leases AS lease
    ON lease.variant_id = recovery.variant_id
   AND lease.attempt_id = recovery.id
   AND lease.fence = recovery.fence
   AND lease.runner_id = recovery.runner_id
   AND lease.runner_epoch = recovery.runner_epoch
   AND lease.workspace_nonce = recovery.workspace_nonce
   AND strftime('%Y-%m-%dT%H:%M:%fZ', 'now') < lease.expires_at
  JOIN lease_authority_fingerprints AS lease_binding
    ON lease_binding.attempt_id = recovery.id
   AND lease_binding.variant_id = recovery.variant_id
   AND lease_binding.fence = recovery.fence
   AND lease_binding.authority_epoch = NEW.authority_epoch
   AND lease_binding.freeze_generation = NEW.freeze_generation
   AND lease_binding.restore_epoch = NEW.restore_epoch
   AND lease_binding.graph_revision = NEW.graph_revision
   AND lease_binding.workspace_generation = NEW.workspace_generation
   AND lease_binding.scope_digest = NEW.scope_digest
   AND lease_binding.policy_generation = NEW.policy_generation
   AND lease_binding.routing_generation = NEW.routing_generation
  JOIN authority_revisions AS authority
    ON authority.singleton = 1
   AND authority.graph_revision = NEW.graph_revision
   AND authority.workspace_generation = NEW.workspace_generation
   AND authority.scope_digest = NEW.scope_digest
   AND authority.policy_generation = NEW.policy_generation
   AND authority.routing_generation = NEW.routing_generation
   AND authority.authority_epoch = NEW.authority_epoch
   AND authority.freeze_generation = NEW.freeze_generation
  JOIN restore_state AS restore
    ON restore.singleton = 1
   AND restore.restore_epoch = NEW.restore_epoch
   AND restore.pending_admission = 0
  JOIN outbox AS dispatch
    ON dispatch.seq = NEW.outbox_sequence
   AND dispatch.command_id IS NULL
   AND dispatch.kind = 'effect_recovery'
   AND dispatch.payload = NEW.claim_id
   AND dispatch.phase = 'pending'
   AND dispatch.delivered_at IS NULL
   AND dispatch.acked_at IS NULL
  WHERE intent.id = NEW.effect_intent_id
    AND intent.provider = 'local-bare'
    AND length(intent.target_identity) = 96
    AND substr(intent.target_identity, 1, 28) = 'refs/heads/bullet/candidate/'
    AND substr(intent.target_identity, 29, 4) = 'can_'
    AND substr(intent.target_identity, 33) NOT GLOB '*[^0123456789abcdef]*'
    AND intent.desired_state_hash != '0000000000000000000000000000000000000000'
    AND length(intent.desired_state_hash) = 40
    AND intent.desired_state_hash NOT GLOB '*[^0123456789abcdef]*'
    AND intent.expected_old_oid = '0000000000000000000000000000000000000000'
    AND intent.provider_idempotency_key IS NULL
    AND intent.payload_hash = NEW.intent_payload_digest
    AND intent.state = NEW.intent_state
    AND intent.unknown_retries = NEW.intent_unknown_retries
    AND (
      (NEW.disposition = 'CLAIMED'
       AND intent.state = 'OUTCOME_UNKNOWN'
       AND intent.unknown_retries = 0)
      OR (NEW.disposition = 'RETRY_RESERVED'
       AND intent.state IN ('OUTCOME_UNKNOWN', 'DISPATCHING')
       AND intent.unknown_retries = 1)
      OR (NEW.disposition = 'READBACK_UNKNOWN'
       AND intent.state = 'OUTCOME_UNKNOWN'
       AND intent.unknown_retries BETWEEN 0 AND 1)
    )
)
BEGIN
  SELECT RAISE(ABORT, 'effect recovery claim subject is stale or incomplete');
END;

CREATE TRIGGER effect_recovery_claim_receipt_insert_guard
BEFORE INSERT ON effect_recovery_claims
WHEN NOT (
  NEW.receipt_id IS NULL
  OR EXISTS (
    SELECT 1
    FROM effect_receipts AS receipt
    JOIN effect_intents AS intent ON intent.id = NEW.effect_intent_id
    WHERE receipt.id = NEW.receipt_id
      AND receipt.effect_intent_id = NEW.effect_intent_id
      AND receipt.observed_remote_identity = intent.target_identity
      AND receipt.verification_method = 'local-bare-read-ref-v1'
      AND (
        (
          NEW.disposition IN ('RETRY_RESERVED', 'INVALIDATED')
          AND COALESCE(NEW.invalidated_from, NEW.disposition) = 'RETRY_RESERVED'
          AND receipt.observed_state_hash IS NULL
          AND receipt.verification_result = 'ABSENT'
        )
        OR (
          NEW.disposition = 'ADOPTED'
          AND receipt.observed_state_hash = intent.desired_state_hash
          AND receipt.verification_result = 'MATCH'
        )
        OR (
          NEW.disposition = 'ORPHANED'
          AND receipt.observed_state_hash IS NOT NULL
          AND receipt.observed_state_hash != intent.desired_state_hash
          AND receipt.verification_result = 'MISMATCH'
        )
        OR (
          NEW.disposition = 'QUARANTINED'
          AND NEW.containment_reason = 'RETRY_SPENT_AFTER_ABSENCE'
          AND receipt.observed_state_hash IS NULL
          AND receipt.verification_result = 'ABSENT'
        )
      )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'effect recovery receipt correlation is forbidden');
END;

CREATE TRIGGER effect_recovery_claim_retry_outbox_insert
AFTER INSERT ON effect_recovery_claims
WHEN NEW.disposition = 'RETRY_RESERVED'
BEGIN
  UPDATE outbox
  SET phase = 'applied',
      delivered_at = NEW.claimed_at
  WHERE seq = NEW.outbox_sequence
    AND kind = 'effect_recovery'
    AND payload = NEW.claim_id
    AND command_id IS NULL
    AND phase = 'pending'
    AND delivered_at IS NULL
    AND acked_at IS NULL;
END;

CREATE TRIGGER effect_recovery_claim_update_guard
BEFORE UPDATE ON effect_recovery_claims
WHEN NEW.claim_id != OLD.claim_id
  OR NEW.effect_intent_id != OLD.effect_intent_id
  OR NEW.claim_generation != OLD.claim_generation
  OR NEW.outbox_sequence != OLD.outbox_sequence
  OR NEW.intent_payload_digest != OLD.intent_payload_digest
  OR NOT (
    (OLD.disposition = 'CLAIMED'
      AND NEW.disposition = 'RETRY_RESERVED'
      AND OLD.intent_state = 'OUTCOME_UNKNOWN'
      AND OLD.intent_unknown_retries = 0
      AND NEW.intent_state = 'DISPATCHING'
      AND NEW.intent_unknown_retries = 1)
    OR (OLD.disposition IN ('CLAIMED', 'RETRY_RESERVED')
      AND NEW.disposition = 'READBACK_UNKNOWN'
      AND NEW.intent_state = 'OUTCOME_UNKNOWN'
      AND NEW.intent_unknown_retries = OLD.intent_unknown_retries)
    OR (OLD.disposition = 'READBACK_UNKNOWN'
      AND NEW.disposition = 'RETRY_RESERVED'
      AND OLD.intent_state = 'OUTCOME_UNKNOWN'
      AND OLD.intent_unknown_retries = 0
      AND NEW.intent_state = 'DISPATCHING'
      AND NEW.intent_unknown_retries = 1)
    OR (NEW.disposition = 'ADOPTED'
      AND NEW.intent_state = 'COMMITTED'
      AND NEW.intent_unknown_retries = OLD.intent_unknown_retries)
    OR (NEW.disposition = 'ORPHANED'
      AND NEW.intent_state = 'ORPHANED_REMOTE'
      AND NEW.intent_unknown_retries = OLD.intent_unknown_retries)
    OR (NEW.disposition = 'QUARANTINED'
      AND NEW.intent_state = 'QUARANTINED'
      AND NEW.intent_unknown_retries = OLD.intent_unknown_retries)
    OR (NEW.disposition = 'INVALIDATED'
      AND NEW.intent_state = OLD.intent_state
      AND NEW.intent_unknown_retries = OLD.intent_unknown_retries)
  )
  OR NEW.work_package_id != OLD.work_package_id
  OR NEW.original_attempt_id != OLD.original_attempt_id
  OR NEW.original_variant_id != OLD.original_variant_id
  OR NEW.original_fence != OLD.original_fence
  OR NEW.successor_authority_digest != OLD.successor_authority_digest
  OR NEW.successor_authority_fingerprint != OLD.successor_authority_fingerprint
  OR NEW.recovery_attempt_id != OLD.recovery_attempt_id
  OR NEW.recovery_variant_id != OLD.recovery_variant_id
  OR NEW.recovery_attempt_fence != OLD.recovery_attempt_fence
  OR NEW.recovery_runner_id != OLD.recovery_runner_id
  OR NEW.recovery_runner_epoch != OLD.recovery_runner_epoch
  OR NEW.recovery_workspace_id != OLD.recovery_workspace_id
  OR NEW.recovery_workspace_nonce != OLD.recovery_workspace_nonce
  OR NEW.graph_revision != OLD.graph_revision
  OR NEW.workspace_generation != OLD.workspace_generation
  OR NEW.scope_digest != OLD.scope_digest
  OR NEW.policy_generation != OLD.policy_generation
  OR NEW.routing_generation != OLD.routing_generation
  OR NEW.authority_epoch != OLD.authority_epoch
  OR NEW.freeze_generation != OLD.freeze_generation
  OR NEW.restore_epoch != OLD.restore_epoch
  OR NEW.claimed_at != OLD.claimed_at
  OR NOT (
    (OLD.disposition = 'CLAIMED'
      AND NEW.disposition IN (
        'RETRY_RESERVED', 'READBACK_UNKNOWN', 'ADOPTED',
        'ORPHANED', 'QUARANTINED', 'INVALIDATED'
      ))
    OR (OLD.disposition = 'RETRY_RESERVED'
      AND NEW.disposition IN (
        'READBACK_UNKNOWN', 'ADOPTED', 'ORPHANED',
        'QUARANTINED', 'INVALIDATED'
      ))
    OR (OLD.disposition = 'READBACK_UNKNOWN'
      AND NEW.disposition IN (
        'RETRY_RESERVED', 'ADOPTED', 'ORPHANED',
        'QUARANTINED', 'INVALIDATED'
      ))
  )
  OR (
    NEW.disposition = 'INVALIDATED'
    AND NEW.invalidated_from != OLD.disposition
  )
  OR (
    NEW.disposition != 'INVALIDATED'
    AND NEW.invalidated_from IS NOT OLD.invalidated_from
  )
BEGIN
  SELECT RAISE(ABORT, 'effect recovery claim transition is forbidden');
END;

CREATE TRIGGER effect_recovery_claim_receipt_update_guard
BEFORE UPDATE ON effect_recovery_claims
WHEN NOT (
  NEW.receipt_id IS NULL
  OR EXISTS (
    SELECT 1
    FROM effect_receipts AS receipt
    JOIN effect_intents AS intent ON intent.id = NEW.effect_intent_id
    WHERE receipt.id = NEW.receipt_id
      AND receipt.effect_intent_id = NEW.effect_intent_id
      AND receipt.observed_remote_identity = intent.target_identity
      AND receipt.verification_method = 'local-bare-read-ref-v1'
      AND (
        (
          NEW.disposition IN ('RETRY_RESERVED', 'INVALIDATED')
          AND COALESCE(NEW.invalidated_from, NEW.disposition) = 'RETRY_RESERVED'
          AND receipt.observed_state_hash IS NULL
          AND receipt.verification_result = 'ABSENT'
        )
        OR (
          NEW.disposition = 'ADOPTED'
          AND receipt.observed_state_hash = intent.desired_state_hash
          AND receipt.verification_result = 'MATCH'
        )
        OR (
          NEW.disposition = 'ORPHANED'
          AND receipt.observed_state_hash IS NOT NULL
          AND receipt.observed_state_hash != intent.desired_state_hash
          AND receipt.verification_result = 'MISMATCH'
        )
        OR (
          NEW.disposition = 'QUARANTINED'
          AND NEW.containment_reason = 'RETRY_SPENT_AFTER_ABSENCE'
          AND receipt.observed_state_hash IS NULL
          AND receipt.verification_result = 'ABSENT'
        )
      )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'effect recovery receipt correlation is forbidden');
END;

CREATE TRIGGER effect_recovery_claim_invalidated_outbox_update
AFTER UPDATE OF disposition ON effect_recovery_claims
WHEN OLD.disposition IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN')
  AND NEW.disposition = 'INVALIDATED'
BEGIN
  UPDATE outbox
  SET phase = 'unknown',
      acked_at = NEW.updated_at
  WHERE seq = NEW.outbox_sequence
    AND kind = 'effect_recovery'
    AND payload = NEW.claim_id
    AND command_id IS NULL
    AND phase IN ('pending', 'applied')
    AND acked_at IS NULL;
END;

CREATE TRIGGER effect_recovery_claim_no_delete
BEFORE DELETE ON effect_recovery_claims
BEGIN
  SELECT RAISE(ABORT, 'effect recovery claim deletion is forbidden');
END;

CREATE TRIGGER effect_recovery_claim_authority_invalidation
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
  UPDATE effect_recovery_claims
  SET disposition = 'INVALIDATED',
      invalidated_from = disposition,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN')
    AND (
      graph_revision != NEW.graph_revision
      OR workspace_generation != NEW.workspace_generation
      OR scope_digest != NEW.scope_digest
      OR policy_generation != NEW.policy_generation
      OR routing_generation != NEW.routing_generation
      OR authority_epoch != NEW.authority_epoch
      OR freeze_generation != NEW.freeze_generation
    );
END;

CREATE TRIGGER effect_recovery_claim_restore_invalidation
AFTER UPDATE OF restore_epoch, pending_admission ON restore_state
WHEN NEW.restore_epoch != OLD.restore_epoch
  OR NEW.pending_admission != OLD.pending_admission
BEGIN
  UPDATE effect_recovery_claims
  SET disposition = 'INVALIDATED',
      invalidated_from = disposition,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN')
    AND (
      restore_epoch != NEW.restore_epoch
      OR NEW.pending_admission != 0
    );
END;

CREATE TRIGGER effect_recovery_claim_lease_delete_invalidation
AFTER DELETE ON active_leases
BEGIN
  UPDATE effect_recovery_claims
  SET disposition = 'INVALIDATED',
      invalidated_from = disposition,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN')
    AND recovery_variant_id = OLD.variant_id
    AND recovery_attempt_id = OLD.attempt_id
    AND recovery_attempt_fence = OLD.fence
    AND recovery_runner_id = OLD.runner_id
    AND recovery_runner_epoch = OLD.runner_epoch
    AND recovery_workspace_nonce = OLD.workspace_nonce;
END;

CREATE TRIGGER effect_recovery_claim_lease_update_invalidation
AFTER UPDATE ON active_leases
WHEN NEW.variant_id != OLD.variant_id
  OR NEW.attempt_id != OLD.attempt_id
  OR NEW.fence != OLD.fence
  OR NEW.runner_id != OLD.runner_id
  OR NEW.runner_epoch != OLD.runner_epoch
  OR NEW.workspace_nonce != OLD.workspace_nonce
BEGIN
  UPDATE effect_recovery_claims
  SET disposition = 'INVALIDATED',
      invalidated_from = disposition,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE disposition IN ('CLAIMED', 'RETRY_RESERVED', 'READBACK_UNKNOWN')
    AND recovery_variant_id = OLD.variant_id
    AND recovery_attempt_id = OLD.attempt_id
    AND recovery_attempt_fence = OLD.fence
    AND recovery_runner_id = OLD.runner_id
    AND recovery_runner_epoch = OLD.runner_epoch
    AND recovery_workspace_nonce = OLD.workspace_nonce;
END;
