//! Durable subject a lease-transport permit binds: the workspace, all seven
//! material `NormalizedAuthority` fields in force, and — for incarnation-class operations —
//! the fenced Attempt incarnation. Every field is part of the canonical
//! signed claims; shape validity is never authority.

use super::{
    bounded, first_deviation, hex_64, invalid, map_harness, positive, LeaseTransportError,
    LeaseTransportOperation,
};
use crate::launch_grant::validate_label;
use serde::{Deserialize, Serialize};

/// Fenced Attempt incarnation named by an incarnation-class permit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseIncarnationClaims {
    /// Variant whose single writer is leased.
    pub variant_id: String,
    /// Attempt incarnation holding the durable lease.
    pub attempt_id: String,
    /// Permanent fence on Attempt and lease; at least 1.
    pub fence: u64,
    /// Scope grant revision bound to the Attempt; at least 1.
    pub scope_revision: u64,
    /// Context capsule revision bound to the Attempt; at least 1.
    pub context_revision: u64,
}

/// Durable subject every lease-transport permit binds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseSubjectClaims {
    /// Private workspace bound to the Attempt.
    pub workspace_id: String,
    /// Workspace generation from the authority row; at least 1.
    pub workspace_generation: u64,
    /// Framed BLAKE3 of the 32-byte workspace nonce.
    pub workspace_nonce_digest: String,
    /// Exact scope digest from the authority row (64 lowercase hex).
    pub scope_digest: String,
    /// Policy generation from the authority row; at least 1.
    pub policy_generation: u64,
    /// Freeze generation from the authority row; 0 when none was recorded.
    pub freeze_generation: u64,
    /// Graph revision from the authority row; at least 1.
    pub graph_revision: u64,
    /// Routing generation from the authority row; at least 1.
    pub routing_generation: u64,
    /// Authority epoch from the authority row; at least 1. The outer claim
    /// `authority_epoch` is derived from this value, never supplied twice.
    pub authority_epoch: u64,
    /// Present exactly for incarnation-class operations.
    pub incarnation: Option<LeaseIncarnationClaims>,
}

impl LeaseSubjectClaims {
    /// Validate every subject field against the operation class.
    ///
    /// # Errors
    /// `LEASE_TRANSPORT_INVALID` naming the offending field.
    pub fn validate_shape(
        &self,
        operation: LeaseTransportOperation,
    ) -> Result<(), LeaseTransportError> {
        validate_label("subject.workspace_id", &self.workspace_id).map_err(map_harness)?;
        hex_64(
            "subject.workspace_nonce_digest",
            &self.workspace_nonce_digest,
        )?;
        hex_64("subject.scope_digest", &self.scope_digest)?;
        positive("subject.workspace_generation", self.workspace_generation)?;
        positive("subject.policy_generation", self.policy_generation)?;
        bounded("subject.freeze_generation", self.freeze_generation)?;
        positive("subject.graph_revision", self.graph_revision)?;
        positive("subject.routing_generation", self.routing_generation)?;
        positive("subject.authority_epoch", self.authority_epoch)?;
        match (&self.incarnation, operation.binds_incarnation()) {
            (None, false) => Ok(()),
            (Some(incarnation), true) => incarnation.validate_shape(),
            (Some(_), false) => Err(invalid(&format!(
                "subject.incarnation must be absent for {}",
                operation.as_str()
            ))),
            (None, true) => Err(invalid(&format!(
                "subject.incarnation is required for {}",
                operation.as_str()
            ))),
        }
    }

    /// Name of the first field on which `presented` deviates from `self`.
    #[must_use]
    pub fn first_mismatch(&self, presented: &Self) -> Option<&'static str> {
        let (e, p) = (self, presented);
        first_deviation([
            (e.workspace_id != p.workspace_id, "workspace_id"),
            (
                e.workspace_generation != p.workspace_generation,
                "workspace_generation",
            ),
            (
                e.workspace_nonce_digest != p.workspace_nonce_digest,
                "workspace_nonce_digest",
            ),
            (e.scope_digest != p.scope_digest, "scope_digest"),
            (
                e.policy_generation != p.policy_generation,
                "policy_generation",
            ),
            (
                e.freeze_generation != p.freeze_generation,
                "freeze_generation",
            ),
            (e.graph_revision != p.graph_revision, "graph_revision"),
            (
                e.routing_generation != p.routing_generation,
                "routing_generation",
            ),
            (
                e.authority_epoch != p.authority_epoch,
                "subject.authority_epoch",
            ),
        ])
        .or_else(|| match (&e.incarnation, &p.incarnation) {
            (None, None) => None,
            (Some(expected), Some(actual)) => expected.first_mismatch(actual),
            _ => Some("incarnation"),
        })
    }
}

impl LeaseIncarnationClaims {
    fn validate_shape(&self) -> Result<(), LeaseTransportError> {
        validate_label("subject.variant_id", &self.variant_id).map_err(map_harness)?;
        validate_label("subject.attempt_id", &self.attempt_id).map_err(map_harness)?;
        positive("subject.fence", self.fence)?;
        positive("subject.scope_revision", self.scope_revision)?;
        positive("subject.context_revision", self.context_revision)
    }

    fn first_mismatch(&self, p: &Self) -> Option<&'static str> {
        first_deviation([
            (self.variant_id != p.variant_id, "variant_id"),
            (self.attempt_id != p.attempt_id, "attempt_id"),
            (self.fence != p.fence, "fence"),
            (self.scope_revision != p.scope_revision, "scope_revision"),
            (
                self.context_revision != p.context_revision,
                "context_revision",
            ),
        ])
    }
}
