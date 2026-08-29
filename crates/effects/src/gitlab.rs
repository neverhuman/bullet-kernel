//! GitLab adapter. Accepted by the parser, refused by every operation.

use crate::error::EffectsError;
use crate::forge::{require_candidate_ref, ForgeDescriptor, ForgeEffects, PushRequest};
use crate::integration::{
    Capability, CheckPublication, CheckReceipt, ForgeIntegration, IntegrationDescriptor,
    IntegrationReceipt, IntegrationSubject, IntegrationSubjectRequest, MergeGroupSubject,
    ProtectedIntegrationRequest, ProtectionState,
};

/// Provider label.
pub const GITLAB_PROVIDER: &str = "gitlab";

/// Independent GitLab profiles. A receipt for one never certifies the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabProfile {
    /// `release.profile.gitlab-adapter-v1` / OD-I.
    GitlabCom,
    /// `release.profile.gitlab-self-managed-v1` / OD-J.
    SelfManaged,
}

/// Typed refuse-all GitLab boundary.
#[derive(Clone, Debug)]
pub struct GitLabForge {
    profile: GitLabProfile,
}

impl Default for GitLabForge {
    fn default() -> Self {
        Self::quarantined()
    }
}

impl GitLabForge {
    /// Construct the GitLab.com profile without credentials or network I/O.
    #[must_use]
    pub const fn quarantined() -> Self {
        Self::gitlab_com()
    }

    /// GitLab.com adapter profile. Does not certify a self-managed endpoint.
    #[must_use]
    pub const fn gitlab_com() -> Self {
        Self {
            profile: GitLabProfile::GitlabCom,
        }
    }

    /// Self-managed GitLab adapter profile. Does not certify GitLab.com.
    #[must_use]
    pub const fn self_managed() -> Self {
        Self {
            profile: GitLabProfile::SelfManaged,
        }
    }

    /// Which independent profile this refuse-all boundary represents.
    #[must_use]
    pub const fn profile(&self) -> GitLabProfile {
        self.profile
    }

    fn refuse(&self, method: &str) -> EffectsError {
        let profile = match self.profile {
            GitLabProfile::GitlabCom => "gitlab-adapter-v1",
            GitLabProfile::SelfManaged => "gitlab-self-managed-v1",
        };
        EffectsError::UnsupportedByAdapter(format!("{method}: {profile} is not implemented"))
    }
}

impl ForgeEffects for GitLabForge {
    fn descriptor(&self) -> ForgeDescriptor {
        ForgeDescriptor {
            provider: GITLAB_PROVIDER.into(),
            authenticated: false,
            can_push_candidate_ref: false,
            notes: match self.profile {
                GitLabProfile::GitlabCom => {
                    "gitlab-adapter-v1: typed refusal; GitLab.com only; no adapter exists"
                }
                GitLabProfile::SelfManaged => {
                    "gitlab-self-managed-v1: typed refusal; self-managed only; no adapter exists"
                }
            }
            .into(),
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
        Err(self.refuse("merge_group_subject"))
    }

    fn read_target(&self, _target: &str) -> Result<Option<String>, EffectsError> {
        Err(self.refuse("read_target"))
    }
}
