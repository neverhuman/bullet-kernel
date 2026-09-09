//! Read-only projection port (spec section 25). Every method is a plain
//! read over durable rows in a deterministic order; callers wrap them in
//! one store snapshot so the rows and the event watermark describe one view.

use crate::effects::{EffectIntentRecord, EffectReceiptRecord};
use crate::records::ActiveLease;
use crate::store::LedgerError;
use crate::ContextCapsule;
use bullet_domain::{Attempt, Candidate, Effect, Evidence};

/// Read-only projection reads. Nothing here mutates or authorizes, and a
/// failed read is an error, never an empty list.
pub trait ProjectionReader {
    /// Every immutable initial Context Capsule, ordered by package and revision.
    ///
    /// # Errors
    /// Store failure or corrupt persisted capsule truth.
    fn list_context_capsules(&self) -> Result<Vec<ContextCapsule>, LedgerError>;

    /// The store's own clock as fixed-width RFC 3339 UTC. Lease liveness is
    /// judged against this value, never against a caller clock.
    ///
    /// # Errors
    /// Store failure.
    fn authority_time(&self) -> Result<String, LedgerError>;

    /// Every active lease row, ordered by variant id.
    ///
    /// # Errors
    /// Store failure or a corrupt persisted lease window.
    fn list_leases(&self) -> Result<Vec<ActiveLease>, LedgerError>;

    /// Every attempt row, ordered by variant id then fence.
    ///
    /// # Errors
    /// Store failure or a corrupt persisted attempt.
    fn list_all_attempts(&self) -> Result<Vec<Attempt>, LedgerError>;

    /// Every candidate row, ordered by id.
    ///
    /// # Errors
    /// Store failure or a corrupt persisted body.
    fn list_candidates(&self) -> Result<Vec<Candidate>, LedgerError>;

    /// Every evidence row, ordered by id.
    ///
    /// # Errors
    /// Store failure or a corrupt persisted body.
    fn list_evidence(&self) -> Result<Vec<Evidence>, LedgerError>;

    /// Every first-slice effect row, ordered by id.
    ///
    /// # Errors
    /// Store failure or a corrupt persisted body.
    fn list_effects(&self) -> Result<Vec<Effect>, LedgerError>;

    /// Every effect intent row, ordered by creation time then id.
    ///
    /// # Errors
    /// Store failure or a corrupt persisted intent.
    fn list_effect_intents(&self) -> Result<Vec<EffectIntentRecord>, LedgerError>;

    /// Every effect receipt row, ordered by recording time then id.
    ///
    /// # Errors
    /// Store failure or a corrupt persisted receipt.
    fn list_effect_receipts(&self) -> Result<Vec<EffectReceiptRecord>, LedgerError>;
}
