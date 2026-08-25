//! `LocalBareForge`: a local bare repository behind the `ForgeEffects`
//! port. Pushes use `--force-with-lease` with the exact expected OID, and
//! read-backs use `git ls-remote` against the bare repository itself.

use crate::error::EffectsError;
use crate::forge::{
    require_candidate_ref, require_oid, ForgeDescriptor, ForgeEffects, PushRequest,
};
use crate::git_env::run_git;
use crate::integration::{
    Capability, CheckPublication, CheckReceipt, ForgeIntegration, IntegrationDescriptor,
    IntegrationSubject, IntegrationSubjectRequest, MergeGroupSubject, ProtectionState,
};
use bullet_application::ZERO_OID;
use std::path::{Path, PathBuf};

/// Provider label for intents targeting the local bare forge.
pub const LOCAL_PROVIDER: &str = "local-bare";

/// Local bare repository forge.
#[derive(Clone, Debug)]
pub struct LocalBareForge {
    bare: PathBuf,
}

impl LocalBareForge {
    /// Initialize a new bare repository at `path`.
    ///
    /// # Errors
    ///
    /// Returns `GIT_FAILED` when the repository cannot be created.
    pub fn init(path: &Path) -> Result<Self, EffectsError> {
        let (code, _out, err) =
            run_git(None, &["init", "--bare", "-q", &path.display().to_string()])?;
        if code != 0 {
            return Err(EffectsError::GitFailed(format!("init --bare: {err}")));
        }
        Ok(Self {
            bare: path.to_path_buf(),
        })
    }

    /// Open an existing bare repository.
    ///
    /// # Errors
    ///
    /// Returns `GIT_FAILED` when `path` is not a bare git repository.
    pub fn open(path: &Path) -> Result<Self, EffectsError> {
        let (code, out, err) = run_git(Some(path), &["rev-parse", "--is-bare-repository"])?;
        if code != 0 || out != "true" {
            return Err(EffectsError::GitFailed(format!(
                "{} is not a bare repository: {err}",
                path.display()
            )));
        }
        Ok(Self {
            bare: path.to_path_buf(),
        })
    }

    /// Path of the bare repository.
    #[must_use]
    pub fn bare_path(&self) -> &Path {
        &self.bare
    }
}

impl ForgeEffects for LocalBareForge {
    fn descriptor(&self) -> ForgeDescriptor {
        ForgeDescriptor {
            provider: LOCAL_PROVIDER.into(),
            authenticated: true,
            can_push_candidate_ref: true,
            notes: format!("local bare repository at {}", self.bare.display()),
        }
    }

    fn push_candidate_ref(&mut self, request: &PushRequest) -> Result<(), EffectsError> {
        require_candidate_ref(&request.ref_name)?;
        require_oid("new_oid", &request.new_oid)?;
        require_oid("expected_old_oid", &request.expected_old_oid)?;
        // Empty expectation in --force-with-lease means the ref must not
        // exist; a concrete OID must match the current remote value.
        let expect = if request.expected_old_oid == ZERO_OID {
            String::new()
        } else {
            request.expected_old_oid.clone()
        };
        let lease = format!("--force-with-lease={}:{expect}", request.ref_name);
        let refspec = format!("{}:{}", request.new_oid, request.ref_name);
        let bare = self.bare.display().to_string();
        let (code, _out, err) = run_git(
            Some(&request.workspace_repo),
            &["push", "-q", &lease, &bare, &refspec],
        )?;
        if code == 0 {
            return Ok(());
        }
        if err.contains("stale info")
            || err.contains("[rejected]")
            || err.contains("[remote rejected]")
        {
            let observed = self.read_ref(&request.ref_name)?;
            return Err(EffectsError::PushRejected {
                ref_name: request.ref_name.clone(),
                observed,
            });
        }
        Err(EffectsError::GitFailed(format!("push: {err}")))
    }

    fn read_ref(&self, ref_name: &str) -> Result<Option<String>, EffectsError> {
        require_candidate_ref(ref_name)?;
        let bare = self.bare.display().to_string();
        let (code, out, err) = run_git(None, &["ls-remote", &bare, ref_name])?;
        if code != 0 {
            return Err(EffectsError::GitFailed(format!("ls-remote: {err}")));
        }
        Ok(out
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
            .map(ToString::to_string))
    }
}

impl ForgeIntegration for LocalBareForge {
    fn integration_descriptor(&self) -> IntegrationDescriptor {
        IntegrationDescriptor {
            exact_oid_cas: Capability::SupportedWithLimitations(
                "client --force-with-lease against a local bare repo",
            ),
            protected_refs: Capability::Unsupported,
            check_runs: Capability::Unsupported,
            merge_group: Capability::Unsupported,
            exact_oid_readback: Capability::Supported,
            third_party_credential: Capability::Unsupported,
        }
    }

    fn read_protection(&self, target: &str) -> Result<ProtectionState, EffectsError> {
        Err(EffectsError::UnsupportedByAdapter(format!(
            "local bare forge has no protection rules on {target}"
        )))
    }

    fn publish_check(&mut self, _req: &CheckPublication) -> Result<CheckReceipt, EffectsError> {
        Err(EffectsError::UnsupportedByAdapter(
            "local bare forge cannot publish check runs".into(),
        ))
    }

    fn read_check(&self, _sha: &str, _name: &str) -> Result<Option<CheckReceipt>, EffectsError> {
        Err(EffectsError::UnsupportedByAdapter(
            "local bare forge cannot store check runs".into(),
        ))
    }

    fn ensure_integration_subject(
        &mut self,
        _req: &IntegrationSubjectRequest,
    ) -> Result<IntegrationSubject, EffectsError> {
        Err(EffectsError::UnsupportedByAdapter(
            "local bare forge has no pull-request subject".into(),
        ))
    }

    fn merge_group_subject(
        &self,
        _subject: &IntegrationSubject,
    ) -> Result<Option<MergeGroupSubject>, EffectsError> {
        Ok(None)
    }

    fn read_target(&self, target: &str) -> Result<Option<String>, EffectsError> {
        let bare = self.bare.display().to_string();
        let (code, out, err) = run_git(None, &["ls-remote", &bare, target])?;
        if code != 0 {
            return Err(EffectsError::TargetReadbackUnavailable(format!(
                "ls-remote {target}: {err}"
            )));
        }
        Ok(out
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
            .map(ToString::to_string))
    }
}
