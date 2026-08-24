//! Typed identifiers. Display names, paths, and PIDs are never identifiers.

use crate::digest::Digest;
use crate::error::DomainError;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Typed `", $prefix, "` identifier.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Deterministic id from a seed. Production callers use unique seeds.
            #[must_use]
            pub fn from_seed(seed: &str) -> Self {
                let digest = Digest::of(format!("{}:{}", $prefix, seed).as_bytes());
                Self(format!("{}_{}", $prefix, &digest.to_hex()[..32]))
            }

            /// Parse a prefixed hex id.
            pub fn parse(raw: impl AsRef<str>) -> Result<Self, DomainError> {
                let raw = raw.as_ref();
                let expected = concat!($prefix, "_");
                if !raw.starts_with(expected) || raw.len() != expected.len() + 32 {
                    return Err(DomainError::InvalidId(raw.to_string()));
                }
                let body = &raw[expected.len()..];
                if !body.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(DomainError::InvalidId(raw.to_string()));
                }
                Ok(Self(raw.to_string()))
            }

            /// Borrow the prefixed string.
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

typed_id!(OrganizationId, "org");
typed_id!(RepositoryId, "repo");
typed_id!(MissionId, "mis");
typed_id!(AcceptanceContractId, "acc");
typed_id!(PlanRevisionId, "pln");
typed_id!(WorkPackageId, "wpk");
typed_id!(SelectionGroupId, "sel");
typed_id!(VariantId, "var");
typed_id!(AttemptId, "atm");
typed_id!(RunnerId, "run");
typed_id!(WorkspaceId, "wks");
typed_id!(CandidateId, "can");
typed_id!(EvidenceId, "evd");
typed_id!(EffectId, "eff");
typed_id!(CommandId, "cmd");
typed_id!(CognitiveTaskId, "cog");
typed_id!(ProfileId, "prf");
typed_id!(RequirementId, "req");
