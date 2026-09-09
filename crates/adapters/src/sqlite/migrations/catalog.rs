//! Ordered, embedded SQLite migration catalog.

use super::super::store;
use bullet_application::LedgerError;
use bullet_domain::{AttemptId, Digest, RunnerId, VariantId, WorkPackageId, WorkspaceId};
use rusqlite::Connection;

#[derive(Clone, Copy)]
pub(in crate::sqlite) struct Migration {
    pub(in crate::sqlite) version: i64,
    pub(in crate::sqlite) name: &'static str,
    pub(in crate::sqlite) sql: &'static str,
}

macro_rules! migration {
    ($version:literal, $name:literal) => {
        Migration {
            version: $version,
            name: $name,
            sql: include_str!(concat!("../../../../../db/migrations/", $name)),
        }
    };
}

pub(in crate::sqlite) const MIGRATIONS: &[Migration] = &[
    migration!(1, "0001_ledger.sql"),
    migration!(2, "0002_authority.sql"),
    migration!(3, "0003_effects.sql"),
    migration!(4, "0004_event_time.sql"),
    migration!(5, "0005_lease_ttl.sql"),
    migration!(6, "0006_command_correlation.sql"),
    migration!(7, "0007_restore_epoch.sql"),
    migration!(8, "0008_identity_contract.sql"),
    migration!(9, "0009_effect_receipt_identity.sql"),
    migration!(10, "0010_launch_grants.sql"),
    migration!(11, "0011_context_capsules.sql"),
    migration!(12, "0012_lease_transport.sql"),
    migration!(13, "0013_nonce_ledger.sql"),
    migration!(14, "0014_reservations.sql"),
    migration!(15, "0015_normalized_authority.sql"),
    migration!(16, "0016_predecessor_constraints.sql"),
    migration!(17, "0017_mutation_authority.sql"),
    migration!(18, "0018_mutation_permit_presentation.sql"),
    migration!(19, "0019_candidate_preparation.sql"),
    migration!(20, "0020_authority_scope_admission.sql"),
    migration!(21, "0021_command_dispatch_claims.sql"),
    migration!(22, "0022_lease_transport_settlements.sql"),
    migration!(23, "0023_effect_recovery_claims.sql"),
];

const MUTATION_OPERATIONS: &str = "clone-workspace,read-workspace,apply-patch,checkpoint,prepare-candidate,preserve-workspace,cleanup-workspace,dispatch-effect,reconcile-effect";

pub(in crate::sqlite) fn valid_mutation_contract(id: &str, operation: &str, digest: &str) -> bool {
    id.strip_prefix("mut_").is_some_and(valid_digest)
        && MUTATION_OPERATIONS
            .split(',')
            .any(|allowed| allowed == operation)
        && valid_digest(digest)
}

pub(in crate::sqlite) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(in crate::sqlite) fn validate_mutation_row(
    conn: &Connection,
    mutation_id: &str,
) -> Result<(), LedgerError> {
    let row = conn
        .query_row(
            "SELECT reservation_id, operation, request_digest, disposition, completion_digest,
                    variant_id, attempt_id, work_package_id, fence, runner_id, runner_epoch,
                    workspace_id, workspace_nonce, scope_revision, context_revision,
                    authority_epoch, freeze_generation, restore_epoch, graph_revision,
                    workspace_generation, scope_digest, policy_generation, routing_generation
             FROM mutation_authority WHERE mutation_id = ?1",
            [mutation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, i64>(21)?,
                    row.get::<_, i64>(22)?,
                ))
            },
        )
        .map_err(store)?;
    let expected_reservation = format!("rsv_{}", Digest::of(mutation_id.as_bytes()).to_hex());
    let positive = [
        row.8, row.10, row.13, row.14, row.15, row.18, row.19, row.21, row.22,
    ];
    let safe = |value: i64, zero_allowed: bool| {
        value >= i64::from(!zero_allowed) && value <= 9_007_199_254_740_991
    };
    let completion_valid = match (row.3.as_str(), row.4.as_deref()) {
        ("RESERVED" | "CONSUMED" | "INVALIDATED", None) => true,
        ("SETTLED" | "UNKNOWN", Some(digest)) => valid_digest(digest),
        _ => false,
    };
    let typed_subject = VariantId::parse(&row.5).is_ok()
        && AttemptId::parse(&row.6).is_ok()
        && WorkPackageId::parse(&row.7).is_ok()
        && RunnerId::parse(&row.9).is_ok()
        && WorkspaceId::parse(&row.11).is_ok();
    let (bound, current, presented): (i64, i64, i64) = conn
        .query_row(
            "SELECT EXISTS (
               SELECT 1 FROM mutation_authority AS mutation
               JOIN attempts AS attempt
                 ON attempt.id = mutation.attempt_id
                AND attempt.variant_id = mutation.variant_id
                AND attempt.work_package_id = mutation.work_package_id
                AND attempt.fence = mutation.fence
                AND attempt.runner_id = mutation.runner_id
                AND attempt.runner_epoch = mutation.runner_epoch
                AND attempt.workspace_id = mutation.workspace_id
                AND attempt.workspace_nonce = mutation.workspace_nonce
                AND attempt.scope_revision = mutation.scope_revision
                AND attempt.context_revision = mutation.context_revision
               JOIN lease_authority_fingerprints AS binding
                 ON binding.attempt_id = mutation.attempt_id
                AND binding.variant_id = mutation.variant_id
                AND binding.fence = mutation.fence
                AND binding.authority_epoch = mutation.authority_epoch
                AND binding.freeze_generation = mutation.freeze_generation
                AND binding.restore_epoch = mutation.restore_epoch
                AND binding.graph_revision = mutation.graph_revision
                AND binding.workspace_generation = mutation.workspace_generation
                AND binding.scope_digest = mutation.scope_digest
                AND binding.policy_generation = mutation.policy_generation
                AND binding.routing_generation = mutation.routing_generation
               WHERE mutation.mutation_id = ?1
             ), EXISTS (
               SELECT 1 FROM mutation_authority AS mutation
               JOIN authority_revisions AS authority
                 ON authority.singleton = 1
                AND authority.graph_revision = mutation.graph_revision
                AND authority.workspace_generation = mutation.workspace_generation
                AND authority.scope_digest = mutation.scope_digest
                AND authority.policy_generation = mutation.policy_generation
                AND authority.routing_generation = mutation.routing_generation
                AND authority.authority_epoch = mutation.authority_epoch
                AND authority.freeze_generation = mutation.freeze_generation
               JOIN restore_state AS restore
                 ON restore.singleton = 1
                AND restore.restore_epoch = mutation.restore_epoch
                AND restore.pending_admission = 0
               WHERE mutation.mutation_id = ?1
             ), EXISTS (
               SELECT 1 FROM mutation_permit_presentations
               WHERE mutation_id = ?1
             )",
            [mutation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(store)?;
    let needs_current = matches!(row.3.as_str(), "RESERVED" | "CONSUMED");
    let presentation_valid = match row.3.as_str() {
        "RESERVED" | "INVALIDATED" => presented == 0,
        "CONSUMED" | "SETTLED" | "UNKNOWN" => presented == 1,
        _ => false,
    };
    if row.0 != expected_reservation
        || !valid_mutation_contract(mutation_id, &row.1, &row.2)
        || !typed_subject
        || row.12.len() != 32
        || positive.into_iter().any(|value| !safe(value, false))
        || !safe(row.16, true)
        || !safe(row.17, true)
        || !valid_digest(&row.20)
        || !completion_valid
        || !presentation_valid
        || bound != 1
        || (needs_current && current != 1)
    {
        return Err(store("corrupt mutation authority persisted row"));
    }
    Ok(())
}
