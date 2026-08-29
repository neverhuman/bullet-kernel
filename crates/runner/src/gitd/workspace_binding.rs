//! Independent validation of daemon-returned workspace-generation identity.

mod guard;
pub(crate) use guard::{WorkspaceGenerationGuard, WorkspaceRootGuard};

use super::{ApplyProposalReceipt, CheckpointBinding, WorkspaceInfo};
use crate::error::RunnerError;
use bullet_domain::{AuthorityToken, Digest};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_DOMAIN: &[u8] = b"bullet-git-generation-manifest-v1";
const POINTER_DOMAIN: &[u8] = b"bullet-git-active-generation-v1";
const CHECKPOINT_DOMAIN: &[u8] = b"bullet-git.checkpoint.v3";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Parent link committed by a non-root generation manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationParentBinding {
    /// Prior generation number.
    pub generation: u64,
    /// Exact prior manifest digest.
    pub manifest_digest: String,
}

/// Recursively closed checkpoint committed by a generation manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCheckpointBinding {
    /// Full-width checkpoint identity.
    pub id: String,
    /// Inclusive journal sequence.
    pub through_seq: u64,
    /// Journal tree digest.
    pub tree: String,
    /// Exact algorithm-tagged Git tree.
    pub git_tree: Option<String>,
    /// Full checkpoint digest.
    pub digest: String,
}

/// Exact manifest, pointer, and checkpoint identity of one active generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveGenerationBinding {
    /// Monotonic generation number.
    pub generation: u64,
    /// Parent identity, absent only for generation zero.
    pub parent: Option<GenerationParentBinding>,
    /// Exact generation-manifest digest.
    pub manifest_digest: String,
    /// Exact active-pointer digest.
    pub pointer_digest: String,
    /// Exact checkpoint committed by the generation manifest.
    pub checkpoint: GenerationCheckpointBinding,
}

impl WorkspaceInfo {
    pub(crate) fn validate_initial(
        &self,
        admitted_root: &Path,
        admitted_base_sha: &str,
        authority: &AuthorityToken,
    ) -> Result<(), RunnerError> {
        require_canonical_directory(admitted_root, "admitted workspace root")?;
        let expected_runtime = admitted_root
            .join("runtime")
            .join(authority.attempt_id.as_str());
        require_exact_directory(&self.runtime_dir, &expected_runtime, "clone runtime")?;
        let expected_repo = generation_repo(admitted_root, authority, 0);
        require_exact_directory(&self.repo_dir, &expected_repo, "clone repository")?;
        if self.base_sha != admitted_base_sha {
            return Err(protocol("clone base SHA differs from the admitted base"));
        }
        self.active_generation.validate(
            authority,
            0,
            None,
            &CheckpointBinding {
                id: self.base_checkpoint_id.clone(),
                digest: self.base_checkpoint_digest.clone(),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn accept_successor(
        &mut self,
        receipt: &ApplyProposalReceipt,
        authority: &AuthorityToken,
    ) -> Result<(), RunnerError> {
        self.validate_successor(receipt, authority)?;
        self.commit_successor(receipt);
        Ok(())
    }

    pub(crate) fn validate_successor(
        &self,
        receipt: &ApplyProposalReceipt,
        authority: &AuthorityToken,
    ) -> Result<u64, RunnerError> {
        let generation = receipt.active_generation.generation;
        if generation <= self.active_generation.generation {
            return Err(protocol("workspace generation did not advance"));
        }
        receipt.active_generation.validate(
            authority,
            generation,
            Some((
                self.active_generation.generation,
                &self.active_generation.manifest_digest,
            )),
            &receipt.checkpoint,
        )?;
        let generations = self
            .repo_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| protocol("active repository lacks its generations root"))?;
        let expected = generations
            .join(format!("generation-{generation:020}"))
            .join("repo");
        require_exact_directory(&receipt.repo_dir, &expected, "apply repository")?;
        Ok(generation)
    }

    pub(crate) fn commit_successor(&mut self, receipt: &ApplyProposalReceipt) {
        self.repo_dir.clone_from(&receipt.repo_dir);
        self.active_generation
            .clone_from(&receipt.active_generation);
    }
}

impl ActiveGenerationBinding {
    fn validate(
        &self,
        authority: &AuthorityToken,
        expected_generation: u64,
        expected_parent: Option<(u64, &str)>,
        expected_checkpoint: &CheckpointBinding,
    ) -> Result<(), RunnerError> {
        if self.generation != expected_generation
            || self.checkpoint.id != expected_checkpoint.id
            || self.checkpoint.digest != expected_checkpoint.digest
        {
            return Err(protocol(
                "active generation does not bind the expected generation/checkpoint",
            ));
        }
        let parent = match (self.parent.as_ref(), expected_parent) {
            (None, None) => None,
            (Some(actual), Some((generation, digest)))
                if actual.generation == generation && actual.manifest_digest == digest =>
            {
                Some(actual)
            }
            _ => return Err(protocol("active generation parent identity mismatch")),
        };
        let checkpoint = self.checkpoint.validate()?;
        let parent_generation = parent.map_or([0; 8], |value| value.generation.to_le_bytes());
        let parent_digest = match parent {
            Some(value) => *parse_digest(&value.manifest_digest, "parent manifest")?.as_bytes(),
            None => [0; 32],
        };
        let generation = self.generation.to_le_bytes();
        let nonce = hex::encode(authority.workspace_nonce);
        let tag: &[u8] = if parent.is_some() { b"parent" } else { b"root" };
        let expected_manifest = framed_digest(&[
            MANIFEST_DOMAIN,
            authority.attempt_id.as_str().as_bytes(),
            nonce.as_bytes(),
            &generation,
            tag,
            &parent_generation,
            &parent_digest,
            checkpoint.as_bytes(),
        ]);
        if self.manifest_digest != expected_manifest.to_hex() {
            return Err(protocol("active generation manifest digest mismatch"));
        }
        let expected_pointer =
            framed_digest(&[POINTER_DOMAIN, &generation, expected_manifest.as_bytes()]);
        if self.pointer_digest != expected_pointer.to_hex() {
            return Err(protocol("active generation pointer digest mismatch"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_only(
        authority: &AuthorityToken,
        generation: u64,
        parent: Option<&Self>,
        checkpoint_seed: &str,
        git_tree: &str,
    ) -> Self {
        let parent = parent.map(|value| GenerationParentBinding {
            generation: value.generation,
            manifest_digest: value.manifest_digest.clone(),
        });
        let parent_generation = parent
            .as_ref()
            .map_or([0; 8], |value| value.generation.to_le_bytes());
        let parent_digest = parent.as_ref().map_or([0; 32], |value| {
            *Digest::from_hex(&value.manifest_digest)
                .expect("test parent digest")
                .as_bytes()
        });
        let generation_bytes = generation.to_le_bytes();
        let nonce = hex::encode(authority.workspace_nonce);
        let checkpoint =
            GenerationCheckpointBinding::test_only(generation, checkpoint_seed, git_tree);
        let checkpoint_digest = Digest::from_hex(&checkpoint.digest).expect("test checkpoint");
        let tag: &[u8] = if parent.is_some() { b"parent" } else { b"root" };
        let manifest = framed_digest(&[
            MANIFEST_DOMAIN,
            authority.attempt_id.as_str().as_bytes(),
            nonce.as_bytes(),
            &generation_bytes,
            tag,
            &parent_generation,
            &parent_digest,
            checkpoint_digest.as_bytes(),
        ]);
        let pointer = framed_digest(&[POINTER_DOMAIN, &generation_bytes, manifest.as_bytes()]);
        Self {
            generation,
            parent,
            manifest_digest: manifest.to_hex(),
            pointer_digest: pointer.to_hex(),
            checkpoint,
        }
    }

    #[cfg(test)]
    pub(crate) fn checkpoint_binding(&self) -> CheckpointBinding {
        CheckpointBinding {
            id: self.checkpoint.id.clone(),
            digest: self.checkpoint.digest.clone(),
        }
    }
}

impl GenerationCheckpointBinding {
    fn validate(&self) -> Result<Digest, RunnerError> {
        if self.through_seq > MAX_SAFE_INTEGER {
            return Err(protocol("checkpoint sequence exceeds safe integer range"));
        }
        let tree = parse_digest(&self.tree, "checkpoint tree")?;
        let git_tree = self
            .git_tree
            .as_deref()
            .ok_or_else(|| protocol("generation checkpoint lacks an exact Git tree"))?;
        validate_git_oid(git_tree)?;
        let sequence = self.through_seq.to_le_bytes();
        let digest = framed_digest(&[
            CHECKPOINT_DOMAIN,
            &sequence,
            tree.as_bytes(),
            git_tree.as_bytes(),
        ]);
        if self.digest != digest.to_hex() {
            return Err(protocol("checkpoint digest mismatch"));
        }
        let id_digest = Digest::of(format!("ckp:{}", digest.to_hex()).as_bytes());
        if self.id != format!("ckp_{}", id_digest.to_hex()) {
            return Err(protocol("checkpoint identity mismatch"));
        }
        Ok(digest)
    }

    #[cfg(test)]
    fn test_only(through_seq: u64, seed: &str, git_tree: &str) -> Self {
        let tree = Digest::of(format!("TEST_ONLY_TREE:{seed}").as_bytes());
        let sequence = through_seq.to_le_bytes();
        let digest = framed_digest(&[
            CHECKPOINT_DOMAIN,
            &sequence,
            tree.as_bytes(),
            git_tree.as_bytes(),
        ]);
        let id_digest = Digest::of(format!("ckp:{}", digest.to_hex()).as_bytes());
        Self {
            id: format!("ckp_{}", id_digest.to_hex()),
            through_seq,
            tree: tree.to_hex(),
            git_tree: Some(git_tree.to_string()),
            digest: digest.to_hex(),
        }
    }
}

fn generation_repo(root: &Path, authority: &AuthorityToken, generation: u64) -> PathBuf {
    root.join("work")
        .join(authority.attempt_id.as_str())
        .join("generations")
        .join(format!("generation-{generation:020}"))
        .join("repo")
}

fn require_exact_directory(actual: &Path, expected: &Path, label: &str) -> Result<(), RunnerError> {
    if actual != expected {
        return Err(protocol(format!(
            "{label} is outside its admitted identity"
        )));
    }
    require_canonical_directory(actual, label)
}

fn require_canonical_directory(path: &Path, label: &str) -> Result<(), RunnerError> {
    if !path.is_absolute() {
        return Err(protocol(format!("{label} is not absolute")));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| protocol(format!("inspect {label}: {error}")))?;
    if !metadata.file_type().is_dir() {
        return Err(protocol(format!("{label} is not a no-symlink directory")));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| protocol(format!("canonicalize {label}: {error}")))?;
    if canonical != path {
        return Err(protocol(format!("{label} is not already canonical")));
    }
    Ok(())
}

fn parse_digest(text: &str, label: &str) -> Result<Digest, RunnerError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(protocol(format!(
            "{label} digest is not 64 lowercase hexadecimal characters"
        )));
    }
    Digest::from_hex(text).map_err(|error| protocol(format!("parse {label} digest: {error}")))
}

fn validate_git_oid(value: &str) -> Result<(), RunnerError> {
    let valid = value
        .strip_prefix("sha1:")
        .is_some_and(|body| is_lower_hex(body, 40))
        || value
            .strip_prefix("sha256:")
            .is_some_and(|body| is_lower_hex(body, 64));
    if !valid {
        return Err(protocol("checkpoint Git tree is not a tagged Git OID"));
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn framed_digest(fields: &[&[u8]]) -> Digest {
    let mut bytes = Vec::new();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field);
    }
    Digest::of(&bytes)
}

fn protocol(reason: impl Into<String>) -> RunnerError {
    RunnerError::Protocol(reason.into())
}

#[cfg(test)]
mod tests;
