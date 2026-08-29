//! Fail-closed setup for the first Attempt's production BulletGit session.

use super::support::{fail, init_source, private_dir};
use bullet_runner_core::lease::AcquireGrant;
use bullet_runner_core::{gitd_binary, GitdSession};
use std::path::{Path, PathBuf};

pub(super) struct GitdSetup {
    pub(super) session: GitdSession,
    pub(super) source: PathBuf,
    pub(super) base: String,
    pub(super) work_root: PathBuf,
}

pub(super) async fn prepare_gitd(
    scratch: &Path,
    grant: &AcquireGrant,
) -> Result<GitdSetup, String> {
    let binary =
        gitd_binary().map_err(|error| fail(format!("{}: {error}", error.reason_code())))?;
    let (source, base) = init_source(scratch)?;
    let work_root = private_dir(&scratch.join("farm"))?;
    let token = serde_json::to_value(&grant.authority_token)
        .map_err(|error| fail(format!("encode Gitd authority token: {error}")))?;
    let session = GitdSession::spawn_with(binary, std::iter::empty::<&str>(), token)
        .await
        .map_err(|error| fail(error.to_string()))?;
    Ok(GitdSetup {
        session,
        source,
        base,
        work_root,
    })
}
