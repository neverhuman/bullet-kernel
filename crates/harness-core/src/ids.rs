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
}
