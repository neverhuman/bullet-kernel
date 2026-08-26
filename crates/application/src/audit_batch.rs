//! Audit batches over ordered ledger events (spec section 43.9; R38, E04).
//!
//! A batch commits a contiguous `first_sequence..=last_sequence` run of
//! [`LedgerEvent`]s to one Merkle root and chains to the prior batch through
//! `previous_root`. The first batch of a ledger chains to
//! [`GENESIS_PREVIOUS_ROOT`]. Everything here is pure and unsigned: the signer
//! slot is typed but uninhabited until the signing wave lands, so no batch can
//! claim a signature this Kernel cannot produce or check, and the verifier
//! refuses any signer or anchor value it does not understand.

pub mod merkle;

use crate::records::LedgerEvent;
use bullet_domain::schema_bundle::AuditBatchV1;
use bullet_domain::Digest;
use merkle::{
    frame, frame_text, leaf_hash, verify_inclusion, InclusionProof, MerkleError, MerkleTree,
};
use thiserror::Error;

/// Schema version written into every batch produced here.
pub const AUDIT_BATCH_SCHEMA_VERSION: &str = "v1alpha1";
/// Wire prefix of `audit_batch_id` (contract pattern `prefix_<64 hex>`).
pub const AUDIT_BATCH_ID_PREFIX: &str = "audit-batch";
/// `previous_root` of the first batch of a ledger: 32 zero bytes.
pub const GENESIS_PREVIOUS_ROOT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// `signer` value of an unsigned batch. The only value this verifier admits.
pub const UNSIGNED_SIGNER: &str = "unsigned";
/// `external_anchor_receipt` of a batch that was never exported.
pub const UNANCHORED_RECEIPT: &str = "unanchored";

const EVENT_LEAF_DOMAIN: &[u8] = b"bullet-kernel.audit-batch.ledger-event.v1";
const BATCH_ID_DOMAIN: &[u8] = b"bullet-kernel.audit-batch.id.v1";

/// Typed signer slot. Uninhabited until the signing wave adds key-bound
/// variants; a builder therefore cannot hold one today.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditSigner {}

/// Fail-closed batch and chain errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum AuditBatchError {
    /// No events or no batches were offered.
    #[error("audit batch is empty")]
    Empty,
    /// Leaf sequences are not strictly increasing.
    #[error("audit leaf {index} carries sequence {found} after {previous}")]
    LeafOrder {
        index: usize,
        previous: u64,
        found: u64,
    },
    /// A sequence number is missing inside a batch or between batches.
    #[error("audit sequence gap: expected {expected}, found {found}")]
    SequenceGap { expected: u64, found: u64 },
    /// Fewer leaves than the committed range.
    #[error("audit batch truncated: {found} of {expected} leaves")]
    Truncated { expected: u64, found: u64 },
    /// Leaves do not cover exactly the committed range.
    #[error("audit leaves {leaf_first}..={leaf_last} do not match {first}..={last}")]
    RangeMismatch {
        first: u64,
        last: u64,
        leaf_first: u64,
        leaf_last: u64,
    },
    /// `first_sequence` exceeds `last_sequence`.
    #[error("audit range {first}..={last} is invalid")]
    RangeInvalid { first: u64, last: u64 },
    /// Unknown schema version.
    #[error("audit schema version {0} is not admitted")]
    SchemaVersion(String),
    /// Signer this verifier cannot check.
    #[error("audit signer {0} is not supported")]
    SignerUnsupported(String),
    /// Anchor receipt this verifier cannot check.
    #[error("audit anchor receipt {0} is not supported")]
    AnchorUnsupported(String),
    /// A root is not 64 lowercase hex characters.
    #[error("audit {0} is not a lowercase 256-bit hex digest")]
    MalformedRoot(&'static str),
    /// Recomputed root differs from the committed root.
    #[error("audit merkle root mismatch: committed {committed}, computed {computed}")]
    RootMismatch { committed: String, computed: String },
    /// Recomputed id differs from the committed id.
    #[error("audit batch id mismatch: committed {committed}, computed {computed}")]
    IdMismatch { committed: String, computed: String },
    /// `previous_root` does not continue the chain.
    #[error("audit batch {index} previous_root {found} does not continue {expected}")]
    PreviousRootMismatch {
        index: usize,
        expected: String,
        found: String,
    },
    /// Batch and leaf-set counts differ.
    #[error("audit chain has {batches} batches but {leaf_sets} leaf sets")]
    ChainShape { batches: usize, leaf_sets: usize },
    /// Merkle-level refusal.
    #[error(transparent)]
    Merkle(#[from] MerkleError),
}

impl AuditBatchError {
    /// Stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Empty => "AUDIT_BATCH_EMPTY",
            Self::LeafOrder { .. } => "AUDIT_LEAF_ORDER",
            Self::SequenceGap { .. } => "AUDIT_SEQUENCE_GAP",
            Self::Truncated { .. } => "AUDIT_BATCH_TRUNCATED",
            Self::RangeMismatch { .. } => "AUDIT_RANGE_MISMATCH",
            Self::RangeInvalid { .. } => "AUDIT_RANGE_INVALID",
            Self::SchemaVersion(_) => "AUDIT_SCHEMA_VERSION",
            Self::SignerUnsupported(_) => "AUDIT_SIGNER_UNSUPPORTED",
            Self::AnchorUnsupported(_) => "AUDIT_ANCHOR_UNSUPPORTED",
            Self::MalformedRoot(_) => "AUDIT_ROOT_MALFORMED",
            Self::RootMismatch { .. } => "AUDIT_ROOT_MISMATCH",
            Self::IdMismatch { .. } => "AUDIT_BATCH_ID_MISMATCH",
            Self::PreviousRootMismatch { .. } => "AUDIT_PREVIOUS_ROOT_MISMATCH",
            Self::ChainShape { .. } => "AUDIT_CHAIN_SHAPE",
            Self::Merkle(inner) => inner.reason_code(),
        }
    }
}

/// Builds one batch that continues a known `previous_root`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditBatchBuilder {
    previous_root: String,
    /// Signing slot. Always `None` until [`AuditSigner`] gains variants.
    pub signer: Option<AuditSigner>,
}

impl AuditBatchBuilder {
    /// Builder for the first batch of a ledger.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            previous_root: GENESIS_PREVIOUS_ROOT.to_owned(),
            signer: None,
        }
    }

    /// Builder for the batch that follows `previous`.
    ///
    /// # Errors
    ///
    /// `AUDIT_ROOT_MALFORMED` when `previous.merkle_root` is not a digest.
    pub fn after(previous: &AuditBatchV1) -> Result<Self, AuditBatchError> {
        Self::with_previous_root(&previous.merkle_root)
    }

    /// Builder continuing an explicit root, for example a restored head.
    ///
    /// # Errors
    ///
    /// `AUDIT_ROOT_MALFORMED` when `previous_root` is not a digest.
    pub fn with_previous_root(previous_root: &str) -> Result<Self, AuditBatchError> {
        validate_root("previous_root", previous_root)?;
        Ok(Self {
            previous_root: previous_root.to_owned(),
            signer: None,
        })
    }

    /// Commit `events`, which must be a contiguous ascending run.
    ///
    /// # Errors
    ///
    /// `AUDIT_BATCH_EMPTY`, `AUDIT_LEAF_ORDER`, or `AUDIT_SEQUENCE_GAP`.
    pub fn build(&self, events: &[LedgerEvent]) -> Result<AuditBatchV1, AuditBatchError> {
        let (first, last) = contiguous_range(events)?;
        let root = MerkleTree::root_of(&event_leaves(events))?.to_hex();
        let signer = match &self.signer {
            None => UNSIGNED_SIGNER.to_owned(),
            Some(signer) => match *signer {},
        };
        Ok(AuditBatchV1 {
            schema_version: AUDIT_BATCH_SCHEMA_VERSION.to_owned(),
            audit_batch_id: batch_id(&self.previous_root, &root, first, last),
            first_sequence: first,
            last_sequence: last,
            previous_root: self.previous_root.clone(),
            merkle_root: root,
            signer,
            external_anchor_receipt: UNANCHORED_RECEIPT.to_owned(),
        })
    }
}

/// Verified head of a chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditChainHead {
    /// Batches verified.
    pub batch_count: usize,
    /// `merkle_root` of the last batch; the next batch's `previous_root`.
    pub head_root: String,
    /// `last_sequence` of the last batch.
    pub last_sequence: u64,
}

/// Domain-separated leaf digest of one event. Every durable column is framed
/// so no field can be altered, dropped, or moved without changing the leaf.
#[must_use]
pub fn event_leaf(event: &LedgerEvent) -> Digest {
    let mut buf = Vec::with_capacity(256 + event.body.len());
    frame(&mut buf, EVENT_LEAF_DOMAIN);
    frame(&mut buf, &event.seq.to_le_bytes());
    frame(&mut buf, event.at.as_bytes());
    frame(&mut buf, event.kind.as_bytes());
    frame(&mut buf, event.body.as_bytes());
    frame_text(&mut buf, event.event_id.as_deref());
    frame_text(&mut buf, event.stream_id.as_deref());
    frame_text(&mut buf, event.sequence.map(|s| s.to_string()).as_deref());
    frame_text(&mut buf, event.causation_id.as_deref());
    frame_text(&mut buf, event.correlation_id.as_deref());
    frame_text(&mut buf, event.authority_token_hash.as_deref());
    leaf_hash(&buf)
}

/// Recompute `batch` from `events` and refuse any divergence.
///
/// # Errors
///
/// Record shape (`AUDIT_SCHEMA_VERSION`, `AUDIT_SIGNER_UNSUPPORTED`, `AUDIT_ANCHOR_UNSUPPORTED`,
/// `AUDIT_ROOT_MALFORMED`, `AUDIT_RANGE_INVALID`), then leaves (`AUDIT_BATCH_EMPTY`, `AUDIT_LEAF_ORDER`,
/// `AUDIT_SEQUENCE_GAP`, `AUDIT_BATCH_TRUNCATED`, `AUDIT_RANGE_MISMATCH`), then content
/// (`AUDIT_ROOT_MISMATCH`, `AUDIT_BATCH_ID_MISMATCH`).
pub fn verify_batch(batch: &AuditBatchV1, events: &[LedgerEvent]) -> Result<(), AuditBatchError> {
    validate_record(batch)?;
    let (leaf_first, leaf_last) = contiguous_range(events)?;
    let expected = batch.last_sequence - batch.first_sequence + 1;
    let found = events.len() as u64;
    if leaf_first == batch.first_sequence && found < expected {
        return Err(AuditBatchError::Truncated { expected, found });
    }
    if leaf_first != batch.first_sequence || leaf_last != batch.last_sequence {
        return Err(AuditBatchError::RangeMismatch {
            first: batch.first_sequence,
            last: batch.last_sequence,
            leaf_first,
            leaf_last,
        });
    }
    let computed = MerkleTree::root_of(&event_leaves(events))?.to_hex();
    if computed != batch.merkle_root {
        return Err(AuditBatchError::RootMismatch {
            committed: batch.merkle_root.clone(),
            computed,
        });
    }
    let id = batch_id(
        &batch.previous_root,
        &batch.merkle_root,
        batch.first_sequence,
        batch.last_sequence,
    );
    if id != batch.audit_batch_id {
        return Err(AuditBatchError::IdMismatch {
            committed: batch.audit_batch_id.clone(),
            computed: id,
        });
    }
    Ok(())
}

/// Verify a whole chain from genesis: every batch, `previous_root` linkage,
/// and sequence contiguity between batches.
///
/// # Errors
///
/// Any [`verify_batch`] error, `AUDIT_CHAIN_SHAPE`, `AUDIT_BATCH_EMPTY` for an
/// empty chain, `AUDIT_PREVIOUS_ROOT_MISMATCH`, `AUDIT_SEQUENCE_GAP`, or
/// `AUDIT_LEAF_ORDER` when a batch overlaps its predecessor.
pub fn verify_chain(
    batches: &[AuditBatchV1],
    leaves_by_batch: &[&[LedgerEvent]],
) -> Result<AuditChainHead, AuditBatchError> {
    verify_chain_from(GENESIS_PREVIOUS_ROOT, batches, leaves_by_batch)
}

/// [`verify_chain`] for a fragment whose first batch continues `head_root`.
///
/// # Errors
///
/// As [`verify_chain`], plus `AUDIT_ROOT_MALFORMED` for a bad `head_root`.
pub fn verify_chain_from(
    head_root: &str,
    batches: &[AuditBatchV1],
    leaves_by_batch: &[&[LedgerEvent]],
) -> Result<AuditChainHead, AuditBatchError> {
    validate_root("head_root", head_root)?;
    if batches.len() != leaves_by_batch.len() {
        return Err(AuditBatchError::ChainShape {
            batches: batches.len(),
            leaf_sets: leaves_by_batch.len(),
        });
    }
    let mut expected_root = head_root.to_owned();
    let mut next_sequence: Option<u64> = None;
    for (index, (batch, leaves)) in batches.iter().zip(leaves_by_batch).enumerate() {
        verify_batch(batch, leaves)?;
        if batch.previous_root != expected_root {
            return Err(AuditBatchError::PreviousRootMismatch {
                index,
                expected: expected_root,
                found: batch.previous_root.clone(),
            });
        }
        if let Some(expected) = next_sequence {
            if batch.first_sequence < expected {
                return Err(AuditBatchError::LeafOrder {
                    index,
                    previous: expected - 1,
                    found: batch.first_sequence,
                });
            }
            if batch.first_sequence > expected {
                return Err(AuditBatchError::SequenceGap {
                    expected,
                    found: batch.first_sequence,
                });
            }
        }
        expected_root.clone_from(&batch.merkle_root);
        next_sequence = Some(batch.last_sequence + 1);
    }
    let last = batches.last().ok_or(AuditBatchError::Empty)?;
    Ok(AuditChainHead {
        batch_count: batches.len(),
        head_root: last.merkle_root.clone(),
        last_sequence: last.last_sequence,
    })
}

/// Inclusion proof for the event with ledger sequence `seq` in a verified
/// batch. The batch is re-verified first; a proof is never issued against an
/// unverified record.
///
/// # Errors
///
/// Any [`verify_batch`] error, or `AUDIT_RANGE_MISMATCH` when `seq` is outside
/// the batch.
pub fn prove_event(
    batch: &AuditBatchV1,
    events: &[LedgerEvent],
    seq: u64,
) -> Result<InclusionProof, AuditBatchError> {
    verify_batch(batch, events)?;
    let index = position(batch, seq)?;
    Ok(MerkleTree::from_leaves(&event_leaves(events))?.prove(index)?)
}

/// Check that `event` is the leaf `proof` claims inside `batch`.
///
/// # Errors
///
/// Record-shape errors of [`verify_batch`], `AUDIT_RANGE_MISMATCH` when the
/// proof does not describe this event's position or the batch's leaf count,
/// or the Merkle reason code of the failed recomputation.
pub fn verify_event_inclusion(
    batch: &AuditBatchV1,
    event: &LedgerEvent,
    proof: &InclusionProof,
) -> Result<(), AuditBatchError> {
    validate_record(batch)?;
    let index = position(batch, event.seq)?;
    let leaf_count = batch.last_sequence - batch.first_sequence + 1;
    if proof.leaf_index != index as u64 || proof.leaf_count != leaf_count {
        return Err(AuditBatchError::RangeMismatch {
            first: batch.first_sequence,
            last: batch.last_sequence,
            leaf_first: batch.first_sequence + proof.leaf_index,
            leaf_last: batch.first_sequence + proof.leaf_count.saturating_sub(1),
        });
    }
    let root = validate_root("merkle_root", &batch.merkle_root)?;
    verify_inclusion(&root, &event_leaf(event), proof)?;
    Ok(())
}

fn validate_record(batch: &AuditBatchV1) -> Result<(), AuditBatchError> {
    if batch.schema_version != AUDIT_BATCH_SCHEMA_VERSION {
        return Err(AuditBatchError::SchemaVersion(batch.schema_version.clone()));
    }
    if batch.signer != UNSIGNED_SIGNER {
        return Err(AuditBatchError::SignerUnsupported(batch.signer.clone()));
    }
    if batch.external_anchor_receipt != UNANCHORED_RECEIPT {
        return Err(AuditBatchError::AnchorUnsupported(
            batch.external_anchor_receipt.clone(),
        ));
    }
    validate_root("previous_root", &batch.previous_root)?;
    validate_root("merkle_root", &batch.merkle_root)?;
    if batch.first_sequence > batch.last_sequence {
        return Err(AuditBatchError::RangeInvalid {
            first: batch.first_sequence,
            last: batch.last_sequence,
        });
    }
    Ok(())
}

fn validate_root(field: &'static str, value: &str) -> Result<Digest, AuditBatchError> {
    let lowercase_hex = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !lowercase_hex {
        return Err(AuditBatchError::MalformedRoot(field));
    }
    Digest::from_hex(value).map_err(|_| AuditBatchError::MalformedRoot(field))
}

/// Order violations anywhere in the slice take precedence over gaps, so a
/// reordered run is reported as `AUDIT_LEAF_ORDER` even when its first
/// irregularity is a forward jump.
fn contiguous_range(events: &[LedgerEvent]) -> Result<(u64, u64), AuditBatchError> {
    let first = events.first().ok_or(AuditBatchError::Empty)?;
    let last = events.last().ok_or(AuditBatchError::Empty)?;
    for (index, pair) in events.windows(2).enumerate() {
        if pair[1].seq <= pair[0].seq {
            return Err(AuditBatchError::LeafOrder {
                index: index + 1,
                previous: pair[0].seq,
                found: pair[1].seq,
            });
        }
    }
    for pair in events.windows(2) {
        if pair[1].seq != pair[0].seq + 1 {
            return Err(AuditBatchError::SequenceGap {
                expected: pair[0].seq + 1,
                found: pair[1].seq,
            });
        }
    }
    Ok((first.seq, last.seq))
}

fn position(batch: &AuditBatchV1, seq: u64) -> Result<usize, AuditBatchError> {
    if seq < batch.first_sequence || seq > batch.last_sequence {
        return Err(AuditBatchError::RangeMismatch {
            first: batch.first_sequence,
            last: batch.last_sequence,
            leaf_first: seq,
            leaf_last: seq,
        });
    }
    usize::try_from(seq - batch.first_sequence).map_err(|_| AuditBatchError::RangeMismatch {
        first: batch.first_sequence,
        last: batch.last_sequence,
        leaf_first: seq,
        leaf_last: seq,
    })
}

fn event_leaves(events: &[LedgerEvent]) -> Vec<Digest> {
    events.iter().map(event_leaf).collect()
}

fn batch_id(previous_root: &str, merkle_root: &str, first: u64, last: u64) -> String {
    let mut buf = Vec::with_capacity(BATCH_ID_DOMAIN.len() + 176);
    frame(&mut buf, BATCH_ID_DOMAIN);
    frame(&mut buf, previous_root.as_bytes());
    frame(&mut buf, merkle_root.as_bytes());
    frame(&mut buf, &first.to_le_bytes());
    frame(&mut buf, &last.to_le_bytes());
    format!("{AUDIT_BATCH_ID_PREFIX}_{}", Digest::of(&buf).to_hex())
}
