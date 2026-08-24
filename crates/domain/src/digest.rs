//! Content-addressed BLAKE3 digest.

use crate::error::DomainError;
use serde::{Deserialize, Serialize};

/// 32-byte BLAKE3 digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "hex_bytes")] [u8; 32]);

impl Digest {
    /// Hash arbitrary bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Hash a compact JSON encoding of `value`.
    pub fn of_json(value: &impl Serialize) -> Result<Self, DomainError> {
        let bytes =
            serde_json::to_vec(value).map_err(|err| DomainError::Encoding(err.to_string()))?;
        Ok(Self::of(&bytes))
    }

    /// Hex encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a 64-character hex digest.
    pub fn from_hex(text: &str) -> Result<Self, DomainError> {
        let raw = hex::decode(text).map_err(|err| DomainError::Encoding(err.to_string()))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| DomainError::Encoding("digest must be 32 bytes".into()))?;
        Ok(Self(bytes))
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(de)?;
        let raw = hex::decode(&text).map_err(serde::de::Error::custom)?;
        let slice: [u8; 32] = raw
            .try_into()
            .map_err(|_| serde::de::Error::custom("digest must be 32 bytes"))?;
        Ok(slice)
    }
}
