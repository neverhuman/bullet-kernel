//! A small local Git origin and deterministic gate for synthetic integration.

use std::path::{Path, PathBuf};
use std::process::Command;

use bullet_runner_core::REPOSITORY_GATE_ID;

/// The demonstration objective (spec s33.13 first mandatory scenario).
pub const OBJECTIVE: &str = "Create PONG.txt containing exactly PONG";

const README: &str =
    "# synthetic integration fixture\n\nObjective: Create PONG.txt containing exactly \
PONG.\nThe writer gate is the sealed full-width `gat_` registry entry.\n";

/// A prepared origin repository.
#[derive(Clone, Debug)]
pub struct Fixture {
    /// Origin repository path.
    pub origin: PathBuf,
    /// Exact base commit.
    pub base_sha: String,
    /// Writer gates admitted before provider dispatch.
    pub writer_gate_ids: Vec<String>,
}

fn git(repo: &Path, home: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", home)
        .output()
        .map_err(|err| format!("git {args:?}: {err}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn create_origin(root: &Path) -> Result<(PathBuf, String), String> {
    let repo = root.join("origin");
    if repo.join(".git").is_dir() {
        let sha = git(&repo, root, &["rev-parse", "HEAD"])?;
        return Ok((repo, sha));
    }
    std::fs::create_dir_all(&repo).map_err(|err| format!("create fixture dir: {err}"))?;
    std::fs::write(repo.join("README.md"), README).map_err(|err| format!("write README: {err}"))?;
    git(&repo, root, &["init", "-q", "-b", "main"])?;
    git(&repo, root, &["config", "user.email", "farm@bullet.local"])?;
    git(&repo, root, &["config", "user.name", "Bullet Farm"])?;
    git(&repo, root, &["add", "README.md"])?;
    git(
        &repo,
        root,
        &["commit", "-q", "-m", "synthetic fixture base"],
    )?;
    let sha = git(&repo, root, &["rev-parse", "HEAD"])?;
    Ok((repo, sha))
}

/// Create the fixture origin, or accept an existing target repository.
pub fn prepare(data_dir: &Path, target: Option<PathBuf>) -> Result<Fixture, String> {
    if let Some(target) = target {
        let sha = git(&target, &target, &["rev-parse", "HEAD"])?;
        return Ok(Fixture {
            origin: target,
            base_sha: sha,
            writer_gate_ids: vec![REPOSITORY_GATE_ID.into()],
        });
    }
    let root = data_dir.join("fixture");
    std::fs::create_dir_all(&root).map_err(|err| format!("create fixture root: {err}"))?;
    let (origin, base_sha) = create_origin(&root)?;
    Ok(Fixture {
        origin,
        base_sha,
        writer_gate_ids: vec![REPOSITORY_GATE_ID.into()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_creation_is_idempotent_and_real() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = prepare(dir.path(), None).expect("fixture");
        assert_eq!(first.base_sha.len(), 40);
        let second = prepare(dir.path(), None).expect("replay");
        assert_eq!(first.base_sha, second.base_sha);
        assert_eq!(first.writer_gate_ids, [REPOSITORY_GATE_ID]);
    }
}
