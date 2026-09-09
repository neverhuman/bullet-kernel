//! Atomic public-command dispatch ownership and component settlement.

use super::{commands, events, SqliteLedger};
use bullet_application::{
    CommandDispatchClaim, CommandDispatchDisposition, CommandDispatchError, CommandDispatchStore,
    CommandRecord, CommandRequest, ComponentCommandCompletionV1,
};
use bullet_domain::{CommandId, CommandPhase, Digest, RunnerId};
use rusqlite::{params, Connection, Transaction};

mod storage;

use storage::*;

const DISPATCH_KIND: &str = "command_dispatch";
const CLAIMED_EVENT: &str = "command_dispatch_claimed";
const RECONCILED_EVENT: &str = "command_reconciled";

impl CommandDispatchStore for SqliteLedger {
    fn claim_next_command_dispatch(
        &mut self,
        runner_id: &RunnerId,
        runner_epoch: u64,
        now: &str,
    ) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
        claim_next(
            &mut self.conn,
            &mut self.command_dispatch_claim_fail_after,
            runner_id,
            runner_epoch,
            now,
        )
    }

    fn readback_command_dispatch(
        &self,
        runner_id: &RunnerId,
        runner_epoch: u64,
    ) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
        validate_epoch(runner_epoch)?;
        let claim = claim_for_runner(&self.conn, runner_id, runner_epoch)?;
        if let Some(value) = claim.as_ref() {
            require_current(&self.conn, value)?;
        }
        Ok(claim)
    }

    fn command_dispatch_claim_for_command(
        &self,
        command_id: &CommandId,
    ) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
        claim_for_command(&self.conn, command_id)
    }

    fn settle_component_command_dispatch(
        &mut self,
        claim_id: &str,
        runner_id: &RunnerId,
        runner_epoch: u64,
        completion: &ComponentCommandCompletionV1,
        now: &str,
    ) -> Result<CommandRecord, CommandDispatchError> {
        settle(
            &mut self.conn,
            &mut self.command_dispatch_settlement_fail_after,
            claim_id,
            runner_id,
            runner_epoch,
            completion,
            now,
        )
    }
}

fn claim_next(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    runner_id: &RunnerId,
    runner_epoch: u64,
    now: &str,
) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
    validate_epoch(runner_epoch)?;
    let transaction = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(dispatch_store)?;
    if let Some(existing) = claim_for_runner(&transaction, runner_id, runner_epoch)? {
        require_current(&transaction, &existing)?;
        transaction.commit().map_err(dispatch_store)?;
        return Ok(Some(existing));
    }
    let pending = oldest_pending(&transaction)?;
    let Some((sequence, command_id, payload)) = pending else {
        transaction.commit().map_err(dispatch_store)?;
        return Ok(None);
    };
    let record = commands::get_command_by_id(&transaction, &command_id)
        .map_err(dispatch_ledger)?
        .ok_or_else(|| dispatch_store("dispatch references an absent command"))?;
    if record.phase != CommandPhase::Pending || record.response.is_some() {
        return Err(dispatch_store("pending dispatch command is not pending"));
    }
    let request = exact_request(&transaction, &record, sequence, &payload)?;
    let (authority_epoch, freeze_generation, restore_epoch) = fingerprint(&transaction)?;
    let claim_id = derive_claim_id(
        &command_id,
        sequence,
        request.digest(),
        runner_id,
        runner_epoch,
        authority_epoch,
        freeze_generation,
        restore_epoch,
    );

    if request.kind != "run_demo" {
        refuse_unsupported(
            &transaction,
            fail_after,
            &claim_id,
            &record,
            &request,
            sequence,
            runner_id,
            runner_epoch,
            authority_epoch,
            freeze_generation,
            restore_epoch,
            now,
        )?;
        transaction.commit().map_err(dispatch_store)?;
        return Ok(None);
    }

    insert_claim(
        &transaction,
        &claim_id,
        &record.id,
        sequence,
        request.digest(),
        runner_id,
        runner_epoch,
        authority_epoch,
        freeze_generation,
        restore_epoch,
        CommandDispatchDisposition::Claimed,
        None,
        now,
    )?;
    fail_boundary(fail_after, "claim")?;
    let changed = transaction
        .execute(
            "UPDATE outbox SET phase = 'applied', delivered_at = ?1
             WHERE seq = ?2 AND command_id = ?3 AND kind = ?4
               AND phase = 'pending' AND delivered_at IS NULL AND acked_at IS NULL",
            params![now, to_i64(sequence)?, record.id.as_str(), DISPATCH_KIND],
        )
        .map_err(dispatch_store)?;
    require_one(changed, "dispatch changed during claim")?;
    fail_boundary(fail_after, "claim")?;
    events::insert_event(
        &transaction,
        CLAIMED_EVENT,
        &claim_id,
        Some(record.id.as_str()),
        Some(record.id.as_str()),
        None,
    )
    .map_err(dispatch_ledger)?;
    fail_boundary(fail_after, "claim")?;
    transaction.commit().map_err(dispatch_store)?;
    claim_for_command(conn, &record.id)?
        .ok_or_else(|| dispatch_store("claim was not retained"))
        .map(Some)
}

#[allow(clippy::too_many_arguments)]
fn refuse_unsupported(
    tx: &Transaction<'_>,
    fail_after: &mut Option<u8>,
    claim_id: &str,
    record: &CommandRecord,
    request: &CommandRequest,
    sequence: u64,
    runner_id: &RunnerId,
    runner_epoch: u64,
    authority_epoch: u64,
    freeze_generation: u64,
    restore_epoch: u64,
    now: &str,
) -> Result<(), CommandDispatchError> {
    let resolution = request
        .offline_worker_resolution()
        .map_err(dispatch_store)?;
    if resolution.phase() != CommandPhase::Failed {
        return Err(dispatch_store(
            "unsupported command did not resolve to failed",
        ));
    }
    let response = resolution.response();
    insert_claim(
        tx,
        claim_id,
        &record.id,
        sequence,
        request.digest(),
        runner_id,
        runner_epoch,
        authority_epoch,
        freeze_generation,
        restore_epoch,
        CommandDispatchDisposition::Failed,
        Some(Digest::of(response.as_bytes())),
        now,
    )?;
    fail_boundary(fail_after, "claim")?;
    let changed = tx
        .execute(
            "UPDATE commands SET phase = 'failed', response_json = ?1
             WHERE id = ?2 AND phase = 'pending' AND response_json IS NULL",
            params![response, record.id.as_str()],
        )
        .map_err(dispatch_store)?;
    require_one(changed, "unsupported command changed during refusal")?;
    let changed = tx
        .execute(
            "UPDATE outbox SET phase = 'failed', acked_at = ?1
             WHERE seq = ?2 AND command_id = ?3 AND phase = 'pending'
               AND delivered_at IS NULL AND acked_at IS NULL",
            params![now, to_i64(sequence)?, record.id.as_str()],
        )
        .map_err(dispatch_store)?;
    require_one(changed, "unsupported dispatch changed during refusal")?;
    fail_boundary(fail_after, "claim")?;
    events::insert_event(
        tx,
        RECONCILED_EVENT,
        response,
        Some(record.id.as_str()),
        Some(record.id.as_str()),
        None,
    )
    .map_err(dispatch_ledger)?;
    fail_boundary(fail_after, "claim")
}

fn settle(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    claim_id: &str,
    runner_id: &RunnerId,
    runner_epoch: u64,
    completion: &ComponentCommandCompletionV1,
    now: &str,
) -> Result<CommandRecord, CommandDispatchError> {
    validate_epoch(runner_epoch)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(dispatch_store)?;
    let claim = claim_by_id(&tx, claim_id)?.ok_or(CommandDispatchError::UnknownClaim)?;
    if claim.runner_id != *runner_id || claim.runner_epoch != runner_epoch {
        return Err(CommandDispatchError::SubjectMismatch(
            "settling Runner incarnation does not own the claim".into(),
        ));
    }
    completion.validate_for(&claim)?;
    let completion_digest = completion.digest()?;
    let response = completion.unknown_response(&claim)?;
    if claim.disposition == CommandDispatchDisposition::Unknown {
        if claim.completion_digest != Some(completion_digest) {
            return Err(CommandDispatchError::SubjectMismatch(
                "settlement replay uses another completion".into(),
            ));
        }
        let record = exact_settled_truth(&tx, &claim, &response)?;
        tx.commit().map_err(dispatch_store)?;
        return Ok(record);
    }
    if claim.disposition != CommandDispatchDisposition::Claimed {
        return Err(CommandDispatchError::StaleAuthority(
            "claim is not executable".into(),
        ));
    }
    require_current(&tx, &claim)?;
    let changed = tx
        .execute(
            "UPDATE commands SET phase = 'unknown', response_json = ?1
             WHERE id = ?2 AND phase = 'pending' AND response_json IS NULL",
            params![response, claim.command_id.as_str()],
        )
        .map_err(dispatch_store)?;
    require_one(changed, "command changed during component settlement")?;
    fail_boundary(fail_after, "settlement")?;
    let changed = tx
        .execute(
            "UPDATE outbox SET phase = 'unknown', acked_at = ?1
             WHERE seq = ?2 AND command_id = ?3 AND phase = 'applied'
               AND delivered_at IS NOT NULL AND acked_at IS NULL",
            params![
                now,
                to_i64(claim.outbox_sequence)?,
                claim.command_id.as_str()
            ],
        )
        .map_err(dispatch_store)?;
    require_one(changed, "dispatch changed during component settlement")?;
    fail_boundary(fail_after, "settlement")?;
    let changed = tx
        .execute(
            "UPDATE command_dispatch_claims
             SET disposition = 'UNKNOWN', completion_digest = ?1, updated_at = ?2
             WHERE claim_id = ?3 AND disposition = 'CLAIMED'",
            params![completion_digest.to_hex(), now, claim.claim_id],
        )
        .map_err(dispatch_store)?;
    require_one(changed, "claim changed during component settlement")?;
    fail_boundary(fail_after, "settlement")?;
    events::insert_event(
        &tx,
        RECONCILED_EVENT,
        &response,
        Some(claim.command_id.as_str()),
        Some(claim.command_id.as_str()),
        None,
    )
    .map_err(dispatch_ledger)?;
    let record = commands::get_command_by_id(&tx, &claim.command_id)
        .map_err(dispatch_ledger)?
        .ok_or_else(|| dispatch_store("settled command disappeared"))?;
    tx.commit().map_err(dispatch_store)?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
fn insert_claim(
    conn: &Connection,
    claim_id: &str,
    command_id: &CommandId,
    outbox_sequence: u64,
    request_digest: Digest,
    runner_id: &RunnerId,
    runner_epoch: u64,
    authority_epoch: u64,
    freeze_generation: u64,
    restore_epoch: u64,
    disposition: CommandDispatchDisposition,
    completion_digest: Option<Digest>,
    now: &str,
) -> Result<(), CommandDispatchError> {
    conn.execute(
        "INSERT INTO command_dispatch_claims (
           claim_id, command_id, outbox_sequence, request_digest, runner_id,
           runner_epoch, authority_epoch, freeze_generation, restore_epoch,
           disposition, completion_digest, claimed_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
        params![
            claim_id,
            command_id.as_str(),
            to_i64(outbox_sequence)?,
            request_digest.to_hex(),
            runner_id.as_str(),
            to_i64(runner_epoch)?,
            to_i64(authority_epoch)?,
            to_i64(freeze_generation)?,
            to_i64(restore_epoch)?,
            disposition.as_str(),
            completion_digest.map(Digest::to_hex),
            now,
        ],
    )
    .map_err(dispatch_store)?;
    Ok(())
}
