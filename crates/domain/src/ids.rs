//! Typed identifiers. Display names, paths, and PIDs are never identifiers.

use crate::digest::Digest;
use crate::error::DomainError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

/// Persisted identity encoding admitted by this Kernel schema.
pub const IDENTITY_FORMAT_VERSION: &str = "bullet-wire-v1alpha1-blake3-256-lower";

/// Persisted effect-receipt identity encoding admitted by schema 9.
pub const EFFECT_RECEIPT_IDENTITY_FORMAT_VERSION: &str =
    "bullet-wire-v1alpha1-effect-receipt-efr-blake3-256-lower";

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Typed `", $prefix, "` identifier.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Frozen wire prefix without the separator.
            pub const PREFIX: &'static str = $prefix;

            /// Deterministic id from a seed. Production callers use unique seeds.
            #[must_use]
            pub fn from_seed(seed: &str) -> Self {
                let digest = Digest::of(format!("{}:{}", $prefix, seed).as_bytes());
                Self(format!("{}_{}", $prefix, digest.to_hex()))
            }

            /// Parse an exact full-width lowercase BLAKE3 subject.
            pub fn parse(raw: impl AsRef<str>) -> Result<Self, DomainError> {
                let raw = raw.as_ref();
                let expected = concat!($prefix, "_");
                let Some(body) = raw.strip_prefix(expected) else {
                    return Err(DomainError::InvalidId(raw.to_string()));
                };
                if body.len() != 64
                    || !body
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
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

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(raw: &str) -> Result<Self, Self::Err> {
                Self::parse(raw)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(de::Error::custom)
            }
        }
    };
}

typed_id!(OrganizationId, "org");
typed_id!(RepositoryId, "rep");
typed_id!(MissionId, "mis");
typed_id!(AcceptanceContractId, "acc");
typed_id!(PlanRevisionId, "pln");
typed_id!(WorkPackageId, "wpk");
typed_id!(SelectionGroupId, "sel");
typed_id!(VariantId, "var");
typed_id!(AttemptId, "atm");
typed_id!(RunnerId, "run");
typed_id!(WorkspaceId, "wsp");
typed_id!(CandidateId, "can");
typed_id!(EvidenceId, "evd");
typed_id!(EffectId, "efi");
typed_id!(EffectReceiptId, "efr");
typed_id!(CommandId, "cmd");
typed_id!(CognitiveTaskId, "cog");
typed_id!(ContextCapsuleId, "ctx");
typed_id!(ProfileId, "prf");
typed_id!(RequirementId, "req");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_authored_id_uses_its_frozen_full_width_prefix() {
        let subjects = [
            (OrganizationId::from_seed("subject").to_string(), "org"),
            (RepositoryId::from_seed("subject").to_string(), "rep"),
            (MissionId::from_seed("subject").to_string(), "mis"),
            (
                AcceptanceContractId::from_seed("subject").to_string(),
                "acc",
            ),
            (PlanRevisionId::from_seed("subject").to_string(), "pln"),
            (WorkPackageId::from_seed("subject").to_string(), "wpk"),
            (SelectionGroupId::from_seed("subject").to_string(), "sel"),
            (VariantId::from_seed("subject").to_string(), "var"),
            (AttemptId::from_seed("subject").to_string(), "atm"),
            (RunnerId::from_seed("subject").to_string(), "run"),
            (WorkspaceId::from_seed("subject").to_string(), "wsp"),
            (CandidateId::from_seed("subject").to_string(), "can"),
            (EvidenceId::from_seed("subject").to_string(), "evd"),
            (EffectId::from_seed("subject").to_string(), "efi"),
            (EffectReceiptId::from_seed("subject").to_string(), "efr"),
            (CommandId::from_seed("subject").to_string(), "cmd"),
            (CognitiveTaskId::from_seed("subject").to_string(), "cog"),
            (ContextCapsuleId::from_seed("subject").to_string(), "ctx"),
            (ProfileId::from_seed("subject").to_string(), "prf"),
            (RequirementId::from_seed("subject").to_string(), "req"),
        ];

        for (subject, prefix) in subjects {
            let body = subject
                .strip_prefix(&format!("{prefix}_"))
                .expect("frozen prefix");
            assert_eq!(body.len(), 64);
            assert!(body
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        }
    }

    #[test]
    fn generation_is_deterministic_and_seed_sensitive() {
        assert_eq!(MissionId::from_seed("same"), MissionId::from_seed("same"));
        assert_ne!(
            MissionId::from_seed("same"),
            MissionId::from_seed("different")
        );
    }

    #[test]
    fn parser_and_serde_reject_legacy_or_malformed_subjects() {
        let valid = MissionId::from_seed("valid");
        assert_eq!(MissionId::parse(valid.as_str()).expect("parse"), valid);
        let encoded = serde_json::to_string(&valid).expect("serialize");
        assert_eq!(
            serde_json::from_str::<MissionId>(&encoded).expect("deserialize"),
            valid
        );

        let invalid = [
            format!("mis_{}", "a".repeat(32)),
            format!("mis_{}", "A".repeat(64)),
            format!("mis_../{}", "a".repeat(61)),
            format!("mis_{}", "a".repeat(63)),
            format!("mis_{}", "a".repeat(65)),
            format!("wrong_{}", "a".repeat(64)),
            format!("mis_{}\0", "a".repeat(63)),
        ];
        for raw in invalid {
            assert!(MissionId::parse(&raw).is_err(), "admitted {raw:?}");
            assert!(serde_json::from_value::<MissionId>(serde_json::Value::String(raw)).is_err());
        }

        assert!(RepositoryId::parse(format!("repo_{}", "a".repeat(64))).is_err());
        assert!(WorkspaceId::parse(format!("wks_{}", "a".repeat(64))).is_err());
        assert!(EffectId::parse(format!("eff_{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn effect_receipt_rejects_legacy_uppercase_and_wrong_prefix_subjects() {
        let valid = EffectReceiptId::from_seed("receipt");
        assert_eq!(
            serde_json::from_str::<EffectReceiptId>(
                &serde_json::to_string(&valid).expect("serialize")
            )
            .expect("deserialize"),
            valid
        );
        for raw in [
            format!("rcp_{}", "a".repeat(32)),
            format!("efr_{}", "a".repeat(32)),
            format!("efr_{}", "A".repeat(64)),
            format!("efi_{}", "a".repeat(64)),
        ] {
            assert!(EffectReceiptId::parse(&raw).is_err(), "admitted {raw}");
            assert!(serde_json::from_value::<EffectReceiptId>(raw.into()).is_err());
        }
    }
}
