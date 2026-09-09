//! Independent reconstruction of the proposal's generation-zero checkpoint.

use super::{fail, git, strip_oid};
use bullet_domain::Digest;
use bullet_runner_core::gitd::CheckpointBinding;
use std::path::Path;

const CHECKPOINT_DOMAIN: &[u8] = b"bullet-git.checkpoint.v3";
const JOURNAL_TREE_DOMAIN: &[u8] = b"bullet-git.journal-tree.v2";

pub(super) fn initial_checkpoint(
    preserved_repository: &Path,
    base: &str,
) -> Result<CheckpointBinding, String> {
    let tree = framed(&[JOURNAL_TREE_DOMAIN]);
    let git_tree = base_tree(preserved_repository, base)?;
    let sequence = 0_u64.to_le_bytes();
    let expected_checkpoint = framed(&[
        CHECKPOINT_DOMAIN,
        &sequence,
        tree.as_bytes(),
        git_tree.as_bytes(),
    ]);
    Ok(CheckpointBinding {
        id: format!(
            "ckp_{}",
            Digest::of(format!("ckp:{}", expected_checkpoint.to_hex()).as_bytes()).to_hex()
        ),
        digest: expected_checkpoint.to_hex(),
    })
}

fn base_tree(repository: &Path, base: &str) -> Result<String, String> {
    let expression = format!("{}^{{tree}}", strip_oid(base));
    let tree = git(repository, &["rev-parse", &expression])?;
    let algorithm = base
        .split_once(':')
        .map(|(algorithm, _)| algorithm)
        .ok_or_else(|| fail("base Git OID lacks an algorithm tag"))?;
    let expected_length = if algorithm == "sha1" {
        40
    } else if algorithm == "sha256" {
        64
    } else {
        return Err(fail("base Git OID algorithm is unsupported"));
    };
    if !lower_hex(&tree, expected_length) {
        return Err(fail("base Git tree is malformed"));
    }
    Ok(format!("{algorithm}:{tree}"))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn framed(fields: &[&[u8]]) -> Digest {
    let mut bytes = Vec::new();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field);
    }
    Digest::of(&bytes)
}
