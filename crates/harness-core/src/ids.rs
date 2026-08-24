//! Harness-local typed identifiers (spec s18.3 envelope fields) and
//! deterministic uuid synthesis for provider session ids.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! harness_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Wrap a raw identifier string.
            #[must_use]
            pub fn new(raw: impl Into<String>) -> Self {
                Self(raw.into())
            }

            /// Borrow the identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

harness_id!(EventId, "Envelope event identifier.");
harness_id!(AgentSessionId, "Kernel-side agent session identifier.");
harness_id!(InvocationId, "One provider process invocation.");

static UUID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Synthesize an RFC 4122 v4-shaped uuid from a BLAKE3 digest of the seed,
/// wall clock, pid, and a process-wide counter. Unique enough for provider
/// session identifiers; not a cryptographically random uuid.
#[must_use]
pub fn synthetic_uuid(seed: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let count = UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let material = format!("{seed}:{nanos}:{}:{count}", std::process::id());
    let digest = blake3::hash(material.as_bytes());
    let hexed = digest.to_hex();
    let h = hexed.as_str();
    format!(
        "{}-{}-4{}-8{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[17..20],
        &h[20..32]
    )
}

/// Whether `text` is a canonical lowercase RFC 4122 UUID: 8-4-4-4-12 hex
/// digits with dashes at positions 8, 13, 18, 23 and no uppercase.
#[must_use]
pub fn is_canonical_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(idx, byte)| match idx {
        8 | 13 | 18 | 23 => *byte == b'-',
        _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
    })
}

/// Map any caller label to a stable canonical UUID for providers that require
/// a real UUID session id (claude 2.1.241 rejects non-UUIDs). A label that is
/// already a canonical UUID passes through unchanged; every other label maps
/// deterministically to the same v4-shaped UUID on every call, derived from
/// the BLAKE3 digest of the label with the version nibble and RFC 4122 variant
/// bits set. Unlike `synthetic_uuid`, this is a pure function of the label.
#[must_use]
pub fn stable_uuid(label: &str) -> String {
    if is_canonical_uuid(label) {
        return label.to_string();
    }
    let digest = blake3::hash(label.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let h = hex.as_str();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_shape_is_valid_v4() {
        let u = synthetic_uuid("seed");
        assert_eq!(u.len(), 36);
        for idx in [8, 13, 18, 23] {
            assert_eq!(u.as_bytes()[idx], b'-', "dash at {idx}");
        }
        assert_eq!(u.as_bytes()[14], b'4');
        assert_eq!(u.as_bytes()[19], b'8');
    }

    #[test]
    fn uuids_are_unique_per_call() {
        assert_ne!(synthetic_uuid("a"), synthetic_uuid("a"));
    }

    #[test]
    fn ids_round_trip() {
        let id = AgentSessionId::new("abc");
        assert_eq!(id.as_str(), "abc");
        assert_eq!(id.to_string(), "abc");
    }

    #[test]
    fn stable_uuid_is_deterministic_canonical_and_passes_uuids_through() {
        // Deterministic: the same label always yields the same UUID.
        let first = stable_uuid("plan-claude-2");
        assert_eq!(first, stable_uuid("plan-claude-2"));
        // Canonical v4-shaped UUID out of a non-UUID label.
        assert!(is_canonical_uuid(&first), "{first} must be canonical");
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4', "version nibble");
        assert!(
            matches!(first.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "RFC 4122 variant nibble, got {}",
            first.as_bytes()[19] as char
        );
        // The label that broke the 2026-08-24 live run no longer reaches claude.
        assert!(!is_canonical_uuid("plan-claude-2"));
        assert_ne!(stable_uuid("plan-claude-1"), stable_uuid("plan-claude-2"));
        assert_ne!(stable_uuid("atm_02ded31dd58aba625722a55fd35ac97d"), first);
        // A real UUID passes through byte-for-byte unchanged (resume safety).
        let real = "60dace9d-6d37-48c5-b9ce-0e5b703cbe84";
        assert_eq!(stable_uuid(real), real);
        // Uppercase is not canonical; it is re-derived rather than passed.
        let upper = "60DACE9D-6D37-48C5-B9CE-0E5B703CBE84";
        assert!(!is_canonical_uuid(upper));
        assert!(is_canonical_uuid(&stable_uuid(upper)));
    }
}
