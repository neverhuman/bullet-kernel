//! Lost-response injection double: performs (or skips) the real push, then
//! drops the answer so the broker must land in `OUTCOME_UNKNOWN` and prove
//! remote truth by read-back before any retry.

use crate::error::EffectsError;
use crate::forge::{ForgeDescriptor, ForgeEffects, PushRequest};

/// When the wrapped forge loses the next push response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossMode {
    /// The push executes remotely; only the response is dropped.
    AfterPush,
    /// The push never reaches the remote; the response is dropped.
    BeforePush,
}

/// Forge wrapper that drops push responses on demand.
pub struct LostResponseForge<F: ForgeEffects> {
    inner: F,
    lose_next: Option<LossMode>,
}

impl<F: ForgeEffects> LostResponseForge<F> {
    /// Wrap `inner` with no loss armed.
    pub fn new(inner: F) -> Self {
        Self {
            inner,
            lose_next: None,
        }
    }

    /// Arm exactly one lost response.
    pub fn lose_next(&mut self, mode: LossMode) {
        self.lose_next = Some(mode);
    }

    /// Access the wrapped forge.
    pub fn inner(&self) -> &F {
        &self.inner
    }

    /// Consume the injector after its armed response-loss fault has been
    /// exercised. This is the handoff from settled delivery reconciliation to
    /// later forge phases; an unconsumed fault refuses rather than disappearing.
    ///
    /// # Errors
    ///
    /// Returns `DURABLE_QUEUE_INVALID` while a response loss remains armed.
    pub fn into_inner(self) -> Result<F, EffectsError> {
        if self.lose_next.is_some() {
            return Err(EffectsError::DurableQueueInvalid(
                "cannot discard an armed lost-response fault".into(),
            ));
        }
        Ok(self.inner)
    }
}

impl<F: ForgeEffects> ForgeEffects for LostResponseForge<F> {
    fn descriptor(&self) -> ForgeDescriptor {
        self.inner.descriptor()
    }

    fn push_candidate_ref(&mut self, request: &PushRequest) -> Result<(), EffectsError> {
        match self.lose_next.take() {
            None => self.inner.push_candidate_ref(request),
            Some(LossMode::AfterPush) => {
                self.inner.push_candidate_ref(request)?;
                Err(EffectsError::ResponseLost(
                    "push executed; response dropped".into(),
                ))
            }
            Some(LossMode::BeforePush) => Err(EffectsError::ResponseLost(
                "push never dispatched; response dropped".into(),
            )),
        }
    }

    fn read_ref(&self, ref_name: &str) -> Result<Option<String>, EffectsError> {
        self.inner.read_ref(ref_name)
    }
}
