//! Quarantined Jeryu boundary scaffold. Wave 0 permits no credential lookup,
//! network probe, or forge mutation until signed admission exists.

use crate::error::EffectsError;
use crate::forge::{require_candidate_ref, ForgeDescriptor, ForgeEffects, PushRequest};

/// Default Jeryu base URL from ADR 0002.
pub const JERYU_BASE_URL: &str = "http://127.0.0.1:8787";
/// Provider label for intents targeting Jeryu.
pub const JERYU_PROVIDER: &str = "jeryu";
/// Forge adapter placeholder. Construction performs no credential or network
/// access, and every operation is unconditionally refused.
pub struct JeryuForge {
    base_url: String,
}

impl JeryuForge {
    /// Construct the quarantined boundary without reading environment, HOME,
    /// credential stores, or the network.
    #[must_use]
    pub fn quarantined(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
        }
    }

    fn refuse(&self, method: &str) -> EffectsError {
        EffectsError::LiveAdmissionUnavailable(format!(
            "{method} against {} is quarantined until signed admission is implemented",
            self.base_url
        ))
    }
}

impl ForgeEffects for JeryuForge {
    fn descriptor(&self) -> ForgeDescriptor {
        ForgeDescriptor {
            provider: JERYU_PROVIDER.into(),
            authenticated: false,
            can_push_candidate_ref: false,
            notes: "Wave-0 quarantine: credential and network access unavailable".into(),
        }
    }

    fn push_candidate_ref(&mut self, request: &PushRequest) -> Result<(), EffectsError> {
        require_candidate_ref(&request.ref_name)?;
        Err(self.refuse("push_candidate_ref"))
    }

    fn read_ref(&self, ref_name: &str) -> Result<Option<String>, EffectsError> {
        require_candidate_ref(ref_name)?;
        Err(self.refuse("read_ref"))
    }
}
