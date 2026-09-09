//! `LocalBareForge`: a local bare repository behind the `ForgeEffects`
//! port. Pushes use `--force-with-lease` with the exact expected OID, and
//! read-backs use `git ls-remote` against the bare repository itself.

use crate::error::EffectsError;
use crate::forge::{
    require_candidate_ref, require_oid, ForgeDescriptor, ForgeEffects, PushRequest,
};
use crate::git_env::run_git;
use crate::local_state::LocalState;
use bullet_application::ZERO_OID;
use std::path::{Path, PathBuf};

/// Provider label for intents targeting the local bare forge.
pub const LOCAL_PROVIDER: &str = "local-bare";

/// Local bare repository forge.
#[derive(Clone, Debug)]
pub struct LocalBareForge {
    pub(crate) bare: PathBuf,
    pub(crate) state: LocalState,
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
        let bare = path.to_path_buf();
        let state = LocalState::open(&bare)?;
        Ok(Self { bare, state })
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
        let bare = path.to_path_buf();
        let state = LocalState::open(&bare)?;
        Ok(Self { bare, state })
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
