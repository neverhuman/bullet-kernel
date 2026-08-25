//! GitLab adapter. Accepted by the parser, refused by every operation.

use crate::error::EffectsError;
use crate::forge::{require_candidate_ref, ForgeDescriptor, ForgeEffects, PushRequest};
use crate::integration::{
    Capability, CheckPublication, CheckReceipt, ForgeIntegration, IntegrationDescriptor,
    IntegrationSubject, IntegrationSubjectRequest, MergeGroupSubject, ProtectionState,
};

/// Provider label.
pub const GITLAB_PROVIDER: &str = "gitlab";

/// Typed refuse-all GitLab boundary.
#[derive(Clone, Debug, Default)]
pub struct GitLabForge;

impl GitLabForge {
    /// Construct without credentials or network I/O.
    #[must_use]
    pub const fn quarantined() -> Self {
        Self
    }

    fn refuse(&self, method: &str) -> EffectsError {
        EffectsError::UnsupportedByAdapter(format!(
            "{method}: gitlab-adapter-v1 is not implemented"
        ))
    }
}

impl ForgeEffects for GitLabForge {
    fn descriptor(&self) -> ForgeDescriptor {
        ForgeDescriptor {
            provider: GITLAB_PROVIDER.into(),
            authenticated: false,
            can_push_candidate_ref: false,
            notes: "gitlab-adapter-v1: typed refusal; no adapter exists".into(),
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

impl ForgeIntegration for GitLabForge {
    fn integration_descriptor(&self) -> IntegrationDescriptor {
        IntegrationDescriptor {
            exact_oid_cas: Capability::Unsupported,
            protected_refs: Capability::Unsupported,
            check_runs: Capability::Unsupported,
            merge_group: Capability::Unsupported,
            exact_oid_readback: Capability::Unsupported,
            third_party_credential: Capability::Unsupported,
        }
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

    fn merge_group_subject(
        &self,
        _subject: &IntegrationSubject,
    ) -> Result<Option<MergeGroupSubject>, EffectsError> {
        Err(self.refuse("merge_group_subject"))
    }

    fn read_target(&self, _target: &str) -> Result<Option<String>, EffectsError> {
        Err(self.refuse("read_target"))
    }
}
