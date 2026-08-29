//! GitHub App adapter. Live dispatch stays refused until OD-C.

use crate::error::EffectsError;
use crate::forge::{require_candidate_ref, ForgeDescriptor, ForgeEffects, PushRequest};
use crate::integration::{
    CheckPublication, CheckReceipt, ForgeIntegration, IntegrationDescriptor, IntegrationReceipt,
    IntegrationSubject, IntegrationSubjectRequest, MergeGroupSubject, ProtectedIntegrationRequest,
    ProtectionState,
};

/// Provider label.
pub const GITHUB_PROVIDER: &str = "github";

/// Quarantined GitHub App boundary. Construction performs no network I/O.
#[derive(Clone, Debug, Default)]
pub struct GitHubForge;

impl GitHubForge {
    /// Construct without reading credentials or the network.
    #[must_use]
    pub const fn quarantined() -> Self {
        Self
    }

    fn refuse(&self, method: &str) -> EffectsError {
        EffectsError::LiveAdmissionUnavailable(format!(
            "{method} against GitHub is quarantined until a ratified App test repository exists"
        ))
    }
}

impl ForgeEffects for GitHubForge {
    fn descriptor(&self) -> ForgeDescriptor {
        ForgeDescriptor {
            provider: GITHUB_PROVIDER.into(),
            authenticated: false,
            can_push_candidate_ref: false,
            notes: "github-adapter-v1: App credentials and live effect are operator-blocked".into(),
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

impl ForgeIntegration for GitHubForge {
    fn integration_descriptor(&self) -> IntegrationDescriptor {
        IntegrationDescriptor::unprobed()
    }

    fn read_protection(&self, _target: &str) -> Result<ProtectionState, EffectsError> {
        Err(self.refuse("read_protection"))
    }

    fn publish_check(&mut self, _req: &CheckPublication) -> Result<CheckReceipt, EffectsError> {
        Err(self.refuse("publish_check"))
    }

    fn read_check(&self, _sha: &str, _name: &str) -> Result<Option<CheckReceipt>, EffectsError> {
        Err(self.refuse("read_check"))
    }

    fn ensure_integration_subject(
        &mut self,
        _req: &IntegrationSubjectRequest,
    ) -> Result<IntegrationSubject, EffectsError> {
        Err(self.refuse("ensure_integration_subject"))
    }

    fn integrate_protected(
        &mut self,
        _req: &ProtectedIntegrationRequest,
    ) -> Result<IntegrationReceipt, EffectsError> {
        Err(self.refuse("integrate_protected"))
    }

    fn merge_group_subject(
        &self,
        _subject: &IntegrationSubject,
    ) -> Result<Option<MergeGroupSubject>, EffectsError> {
        Err(EffectsError::MergeGroupOpaque(
            "GitHub merge queue does not disclose the composed SHA".into(),
        ))
    }

    fn read_target(&self, _target: &str) -> Result<Option<String>, EffectsError> {
        Err(self.refuse("read_target"))
    }
}
