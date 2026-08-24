//! Effect and delivery plane (spec section 23): durable intents unique on
//! `(provider, logical_effect_key)`, a typed state machine where a lost
//! response is `OUTCOME_UNKNOWN`, read-back verified receipts, and
//! reconcile-before-retry by construction.

pub mod broker;
pub mod error;
pub mod forge;
pub mod git_env;
pub mod jeryu;
pub mod local;
pub mod lost;

pub use broker::{authorize, dispatch, propose, reconcile, IntentInput, ReconcileOutcome};
pub use bullet_application::{
    receipt_id, EffectIntentRecord, EffectReceiptRecord, EffectState, ReceiptVerdict, ZERO_OID,
};
pub use error::EffectsError;
pub use forge::{
    is_create, require_candidate_ref, require_oid, ForgeDescriptor, ForgeEffects, PushRequest,
    CANDIDATE_REF_PREFIX,
};
pub use jeryu::{JeryuForge, JERYU_BASE_URL, JERYU_PROVIDER};
pub use local::{LocalBareForge, LOCAL_PROVIDER};
pub use lost::{LossMode, LostResponseForge};
