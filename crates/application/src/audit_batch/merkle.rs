//! Deterministic Merkle tree over ordered leaf digests (spec section 43.9).
//!
//! Framing is domain-separated with the family's fixed `u64` little-endian
//! length prefix: a leaf is `frame(LEAF_DOMAIN) || frame(payload)`, an inner
//! node is `frame(NODE_DOMAIN) || left || right`. A leaf digest can therefore
//! never be replayed as a node and vice versa.
//!
//! Duplicate-last-leaf rule: when a level has an odd number of nodes the last
//! node is paired with itself. Consequently the root alone does not commit the
//! leaf count (`[a, b, c]` and `[a, b, c, c]` share a root). Every consumer
//! must commit the count out of band; the audit batch does so through its
//! `first_sequence..=last_sequence` range and inclusion proofs carry
//! `leaf_count`, which fixes the proof height.

use bullet_domain::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const LEAF_DOMAIN: &[u8] = b"bullet-kernel.audit-merkle.leaf.v1";
const NODE_DOMAIN: &[u8] = b"bullet-kernel.audit-merkle.node.v1";

/// Fail-closed Merkle errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum MerkleError {
    /// A tree over zero leaves has no root.
    #[error("merkle tree has no leaves")]
    Empty,
    /// Leaf index is outside the tree.
    #[error("merkle leaf index {index} is outside {leaf_count} leaves")]
    IndexOutOfRange {
        /// Requested index.
        index: u64,
        /// Leaves in the tree.
        leaf_count: u64,
    },
    /// Proof height does not match the committed leaf count.
    #[error("merkle proof carries {found} siblings, {expected} required")]
    ProofShape {
        /// Siblings required by `leaf_count`.
        expected: usize,
        /// Siblings supplied.
        found: usize,
    },
    /// Recomputed root differs from the committed root.
    #[error("merkle root mismatch")]
    RootMismatch,
}

impl MerkleError {
    /// Stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Empty => "MERKLE_EMPTY",
            Self::IndexOutOfRange { .. } => "MERKLE_INDEX_OUT_OF_RANGE",
            Self::ProofShape { .. } => "MERKLE_PROOF_SHAPE",
            Self::RootMismatch => "MERKLE_ROOT_MISMATCH",
        }
    }
}

/// Domain-separated leaf digest of exact payload bytes.
#[must_use]
pub fn leaf_hash(payload: &[u8]) -> Digest {
    let mut framed = Vec::with_capacity(LEAF_DOMAIN.len() + payload.len() + 16);
    frame(&mut framed, LEAF_DOMAIN);
    frame(&mut framed, payload);
    Digest::of(&framed)
}

/// Domain-separated inner node digest. Order matters.
#[must_use]
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut framed = Vec::with_capacity(NODE_DOMAIN.len() + 72);
    frame(&mut framed, NODE_DOMAIN);
    framed.extend_from_slice(left.as_bytes());
    framed.extend_from_slice(right.as_bytes());
    Digest::of(&framed)
}

/// Proof that one leaf sits at `leaf_index` in a tree of `leaf_count` leaves.
///
/// `siblings` run bottom-up. The side of each sibling is derived from the
/// bits of `leaf_index`, so the proof carries no separate direction flags.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Zero-based position of the proven leaf.
    pub leaf_index: u64,
    /// Committed leaf count; fixes the proof height.
    pub leaf_count: u64,
    /// Sibling digests from the leaf level up to the root's children.
    pub siblings: Vec<Digest>,
}

/// Fully materialized tree. Level zero holds the leaves; the last level holds
/// exactly the root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleTree {
    levels: Vec<Vec<Digest>>,
}

impl MerkleTree {
    /// Build over already-hashed leaves in their exact order.
    ///
    /// # Errors
    ///
    /// `MERKLE_EMPTY` for zero leaves.
    pub fn from_leaves(leaves: &[Digest]) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::Empty);
        }
        let mut levels = vec![leaves.to_vec()];
        while levels.last().map_or(0, Vec::len) > 1 {
            let below = levels.last().expect("non-empty levels");
            let mut above = Vec::with_capacity(below.len().div_ceil(2));
            for pair in below.chunks(2) {
                let right = pair.get(1).unwrap_or(&pair[0]);
                above.push(node_hash(&pair[0], right));
            }
            levels.push(above);
        }
        Ok(Self { levels })
    }

    /// Root over `leaves` without keeping the tree.
    ///
    /// # Errors
    ///
    /// `MERKLE_EMPTY` for zero leaves.
    pub fn root_of(leaves: &[Digest]) -> Result<Digest, MerkleError> {
        Self::from_leaves(leaves).map(|tree| tree.root())
    }

    /// Root digest.
    #[must_use]
    pub fn root(&self) -> Digest {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("a built tree always has a root")
    }

    /// Number of leaves.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Inclusion proof for the leaf at `index`.
    ///
    /// # Errors
    ///
    /// `MERKLE_INDEX_OUT_OF_RANGE` when `index` is not a leaf position.
    pub fn prove(&self, index: usize) -> Result<InclusionProof, MerkleError> {
        let leaf_count = self.leaf_count();
        if index >= leaf_count {
            return Err(MerkleError::IndexOutOfRange {
                index: index as u64,
                leaf_count: leaf_count as u64,
            });
        }
        let mut siblings = Vec::with_capacity(self.levels.len());
        let mut position = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if position % 2 == 0 {
                level.get(position + 1).unwrap_or(&level[position])
            } else {
                &level[position - 1]
            };
            siblings.push(*sibling);
            position /= 2;
        }
        Ok(InclusionProof {
            leaf_index: index as u64,
            leaf_count: leaf_count as u64,
            siblings,
        })
    }
}

/// Recompute the root from `leaf` and `proof` and compare it with `root`.
///
/// # Errors
///
/// `MERKLE_EMPTY` for a zero leaf count, `MERKLE_INDEX_OUT_OF_RANGE` when the
/// index exceeds the count, `MERKLE_PROOF_SHAPE` when the sibling count is not
/// the height implied by `leaf_count`, `MERKLE_ROOT_MISMATCH` otherwise.
pub fn verify_inclusion(
    root: &Digest,
    leaf: &Digest,
    proof: &InclusionProof,
) -> Result<(), MerkleError> {
    if proof.leaf_count == 0 {
        return Err(MerkleError::Empty);
    }
    if proof.leaf_index >= proof.leaf_count {
        return Err(MerkleError::IndexOutOfRange {
            index: proof.leaf_index,
            leaf_count: proof.leaf_count,
        });
    }
    let expected = height(proof.leaf_count);
    if proof.siblings.len() != expected {
        return Err(MerkleError::ProofShape {
            expected,
            found: proof.siblings.len(),
        });
    }
    let mut current = *leaf;
    let mut position = proof.leaf_index;
    for sibling in &proof.siblings {
        current = if position % 2 == 0 {
            node_hash(&current, sibling)
        } else {
            node_hash(sibling, &current)
        };
        position /= 2;
    }
    if &current == root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

/// Number of levels above the leaves for `leaf_count` leaves.
fn height(leaf_count: u64) -> usize {
    let mut width = leaf_count;
    let mut levels = 0;
    while width > 1 {
        width = width.div_ceil(2);
        levels += 1;
    }
    levels
}

pub(super) fn frame(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    target.extend_from_slice(bytes);
}

/// Frame an optional text column: `0x00` for absent, `0x01 || frame(text)`
/// for present, so `None` and `Some("")` never collide.
pub(super) fn frame_text(target: &mut Vec<u8>, text: Option<&str>) {
    match text {
        None => target.push(0),
        Some(text) => {
            target.push(1);
            frame(target, text.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: usize) -> Vec<Digest> {
        (0..count)
            .map(|index| leaf_hash(format!("leaf-{index}").as_bytes()))
            .collect()
    }

    #[test]
    fn empty_tree_is_refused() {
        assert_eq!(
            MerkleTree::from_leaves(&[]).unwrap_err(),
            MerkleError::Empty
        );
        assert_eq!(MerkleError::Empty.reason_code(), "MERKLE_EMPTY");
    }

    #[test]
    fn single_leaf_root_is_the_leaf_and_proof_is_empty() {
        let leaf = leaf_hash(b"only");
        let tree = MerkleTree::from_leaves(&[leaf]).unwrap();
        assert_eq!(tree.root(), leaf);
        let proof = tree.prove(0).unwrap();
        assert!(proof.siblings.is_empty());
        verify_inclusion(&leaf, &leaf, &proof).unwrap();
    }

    #[test]
    fn leaf_and_node_framing_are_domain_separated() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let node = node_hash(&a, &b);
        let mut concatenated = a.as_bytes().to_vec();
        concatenated.extend_from_slice(b.as_bytes());
        assert_ne!(node, leaf_hash(&concatenated));
        assert_ne!(node, Digest::of(&concatenated));
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
        assert_ne!(leaf_hash(b"ab"), Digest::of(b"ab"));
    }

    #[test]
    fn root_matches_hand_built_shape_for_three_leaves() {
        let l = leaves(3);
        let left = node_hash(&l[0], &l[1]);
        let right = node_hash(&l[2], &l[2]);
        let expected = node_hash(&left, &right);
        assert_eq!(MerkleTree::root_of(&l).unwrap(), expected);
    }

    #[test]
    fn duplicate_last_leaf_rule_is_exactly_as_documented() {
        let three = leaves(3);
        let mut four = three.clone();
        four.push(three[2]);
        assert_eq!(
            MerkleTree::root_of(&three).unwrap(),
            MerkleTree::root_of(&four).unwrap()
        );
        assert_eq!(height(3), 2);
        assert_eq!(height(4), 2);
        assert_eq!(height(5), 3);
    }

    #[test]
    fn reordering_any_pair_changes_the_root() {
        let l = leaves(7);
        let root = MerkleTree::root_of(&l).unwrap();
        for i in 0..l.len() {
            for j in (i + 1)..l.len() {
                let mut swapped = l.clone();
                swapped.swap(i, j);
                assert_ne!(MerkleTree::root_of(&swapped).unwrap(), root, "{i}<->{j}");
            }
        }
    }

    #[test]
    fn every_leaf_of_every_small_tree_proves_and_wrong_leaves_fail() {
        for count in 1..=9 {
            let l = leaves(count);
            let tree = MerkleTree::from_leaves(&l).unwrap();
            let root = tree.root();
            for (index, leaf) in l.iter().enumerate() {
                let proof = tree.prove(index).unwrap();
                assert_eq!(proof.siblings.len(), height(count as u64));
                verify_inclusion(&root, leaf, &proof).unwrap();
                let forged = leaf_hash(b"forged");
                assert_eq!(
                    verify_inclusion(&root, &forged, &proof).unwrap_err(),
                    MerkleError::RootMismatch
                );
            }
            assert_eq!(
                tree.prove(count).unwrap_err().reason_code(),
                "MERKLE_INDEX_OUT_OF_RANGE"
            );
        }
    }

    #[test]
    fn proof_shape_and_index_are_pinned_by_leaf_count() {
        let l = leaves(5);
        let tree = MerkleTree::from_leaves(&l).unwrap();
        let root = tree.root();
        let mut proof = tree.prove(4).unwrap();
        proof.siblings.pop();
        assert_eq!(
            verify_inclusion(&root, &l[4], &proof)
                .unwrap_err()
                .reason_code(),
            "MERKLE_PROOF_SHAPE"
        );
        let mut proof = tree.prove(4).unwrap();
        proof.leaf_index = 5;
        assert_eq!(
            verify_inclusion(&root, &l[4], &proof)
                .unwrap_err()
                .reason_code(),
            "MERKLE_INDEX_OUT_OF_RANGE"
        );
        let mut proof = tree.prove(4).unwrap();
        proof.leaf_count = 0;
        assert_eq!(
            verify_inclusion(&root, &l[4], &proof).unwrap_err(),
            MerkleError::Empty
        );
        let mut proof = tree.prove(1).unwrap();
        proof.leaf_index = 0;
        assert_eq!(
            verify_inclusion(&root, &l[1], &proof).unwrap_err(),
            MerkleError::RootMismatch
        );
    }
}
