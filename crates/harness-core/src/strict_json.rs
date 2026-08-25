//! Strict JSON-to-`serde_json::Value` decoding for raw trust-boundary input.
//!
//! Unlike `serde_json::Value`'s derived map decoding, this recursive visitor
//! observes every object entry and refuses duplicate decoded keys. It preserves
//! ordinary JSON value semantics and rejects trailing data. It does not
//! canonicalize JSON and makes no RFC 8785 claim.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Decode exactly one JSON value while rejecting duplicate object keys at any depth.
///
/// # Errors
///
/// Returns a `serde_json::Error` for malformed JSON, a duplicate decoded key,
/// an unrepresentable number, or any trailing non-whitespace data.
pub fn decode_strict_json(input: &str) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = StrictValueSeed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

#[derive(Clone, Copy)]
struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::with_capacity(entries.size_hint().unwrap_or(0));
        while let Some(key) = entries.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            object.insert(key, entries.next_value_seed(StrictValueSeed)?);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_nested_and_decoded_equivalent_duplicates_are_rejected() {
        for input in [
            r#"{"a":1,"a":2}"#,
            r#"{"outer":{"gate_ids":["bad"],"gate_ids":["good"]}}"#,
            r#"[{"role":"user","role":"assistant"}]"#,
            r#"{"a":1,"\u0061":2}"#,
        ] {
            let error = decode_strict_json(input).expect_err(input);
            assert!(error.to_string().contains("duplicate JSON object key"));
        }
    }

    #[test]
    fn arrays_objects_scalars_and_numbers_match_ordinary_value_semantics() {
        for input in [
            "null",
            "true",
            "false",
            "0",
            "-9223372036854775808",
            "18446744073709551615",
            "1.25e7",
            r#""text""#,
            r#"[null,true,-1,2.5,"x",{"nested":[1,2]}]"#,
            r#"{"z":0,"a":[false,{"n":3}]}"#,
        ] {
            let strict = decode_strict_json(input).expect(input);
            let ordinary: Value = serde_json::from_str(input).expect(input);
            assert_eq!(strict, ordinary, "{input}");
        }
    }

    #[test]
    fn malformed_and_trailing_data_are_rejected_but_whitespace_is_allowed() {
        assert_eq!(
            decode_strict_json(" \n {\"ok\":true}\t ").unwrap()["ok"],
            true
        );
        for input in ["", "{", "[1,]", "true false", "{}x", r#"{"a":1}[]"#] {
            assert!(decode_strict_json(input).is_err(), "{input}");
        }
    }
}
