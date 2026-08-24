//! A small local Git origin and deterministic gate for synthetic integration.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The demonstration objective (spec s33.13 first mandatory scenario).
pub const OBJECTIVE: &str = "Create PONG.txt containing exactly PONG";
/// Gate used when a target repository carries no gate script.
pub const DEFAULT_GATE: &str = "test -f PONG.txt && grep -qx PONG PONG.txt";

const README: &str =
    "# synthetic integration fixture\n\nObjective: Create PONG.txt containing exactly \
PONG.\nThe deterministic gate is `sh ./gate.sh`.\n";
const GATE_SH: &str = "#!/bin/sh\ntest -f PONG.txt && grep -qx PONG PONG.txt\n";

/// A prepared origin repository.
#[derive(Clone, Debug)]
pub struct Fixture {
    /// Origin repository path.
    pub origin: PathBuf,
    /// Exact base commit.
    pub base_sha: String,
    /// Deterministic gate command (run via `sh -c` inside the clone).
    pub gate_command: String,
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
    std::fs::write(repo.join("gate.sh"), GATE_SH).map_err(|err| format!("write gate.sh: {err}"))?;
    git(&repo, root, &["init", "-q", "-b", "main"])?;
    git(&repo, root, &["config", "user.email", "farm@bullet.local"])?;
    git(&repo, root, &["config", "user.name", "Bullet Farm"])?;
    git(&repo, root, &["add", "README.md", "gate.sh"])?;
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
        let gate_command = if target.join("gate.sh").is_file() {
            "sh ./gate.sh".to_string()
        } else {
            DEFAULT_GATE.to_string()
        };
        return Ok(Fixture {
            origin: target,
            base_sha: sha,
            gate_command,
        });
    }
    let root = data_dir.join("fixture");
    std::fs::create_dir_all(&root).map_err(|err| format!("create fixture root: {err}"))?;
    let (origin, base_sha) = create_origin(&root)?;
    Ok(Fixture {
        origin,
        base_sha,
        gate_command: "sh ./gate.sh".to_string(),
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
        assert!(first.origin.join("gate.sh").is_file());
        let second = prepare(dir.path(), None).expect("replay");
        assert_eq!(first.base_sha, second.base_sha);
    }
}
