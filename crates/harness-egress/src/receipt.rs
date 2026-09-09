//! The egress isolation receipt: every fact the sandbox proved, digested so
//! admission can bind to it. `EgressEvidence` carries exactly the four fields
//! harness-core admission consumes.

use crate::allowlist::AllowlistMode;
use crate::error::{EgressCode, EgressError};
use crate::probes::{ContainmentProbe, ProbeOutcome, ProbeRecord};
use crate::tools::ToolRecord;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Receipt schema identifier.
pub const SCHEMA_VERSION: &str = "bullet.egress-receipt.v1";

/// Complete isolation receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressReceipt {
    /// Always [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// Policy provider label.
    pub provider: String,
    /// Strict or extended allowlist.
    pub allowlist_mode: AllowlistMode,
    /// Namespace backend (`unshare`).
    pub namespace_backend: String,
    /// Host address as seen from inside the namespace.
    pub gateway: String,
    /// Host proxy port; the only admitted destination.
    pub proxy_port: u16,
    /// Sorted admitted hosts.
    pub allowlist: Vec<String>,
    /// Sorted admitted ports.
    pub allowed_ports: Vec<u16>,
    /// BLAKE3 hex over `{"hosts":[...],"ports":[...]}`.
    pub allowlist_digest: String,
    /// Ruleset text fed to `nft -f -`.
    pub ruleset_text: String,
    /// BLAKE3 hex of `ruleset_text`.
    pub ruleset_digest: String,
    /// `nft list ruleset` as the kernel reported it after installation.
    pub ruleset_listing: String,
    /// Probe results in execution order.
    pub probes: Vec<ProbeRecord>,
    /// RFC 3339 UTC time `prepare` began.
    pub started_at: String,
    /// Resolved tool paths and versions.
    pub tools: BTreeMap<String, ToolRecord>,
    /// BLAKE3 hex over the canonical JSON of every other field.
    pub receipt_digest: String,
}

/// Exactly the fields harness-core admission binds to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressEvidence {
    /// [`EgressReceipt::receipt_digest`].
    pub receipt_digest: String,
    /// [`EgressReceipt::ruleset_digest`].
    pub ruleset_digest: String,
    /// [`EgressReceipt::allowlist_digest`].
    pub allowlist_digest: String,
    /// Containment probes only (`{name, outcome}`), in execution order.
    pub probes: Vec<ContainmentProbe>,
}

impl EgressReceipt {
    /// Compute and store `receipt_digest`.
    ///
    /// # Errors
    ///
    /// `EGRESS_IO_FAILED` if the receipt cannot be serialized.
    pub fn seal(mut self) -> Result<Self, EgressError> {
        self.receipt_digest = self.compute_digest()?;
        Ok(self)
    }

    /// BLAKE3 hex over the canonical JSON with `receipt_digest` removed.
    ///
    /// # Errors
    ///
    /// `EGRESS_IO_FAILED` if the receipt cannot be serialized.
    pub fn compute_digest(&self) -> Result<String, EgressError> {
        let mut value = serde_json::to_value(self).map_err(|err| {
            EgressError::new(EgressCode::IoFailed, format!("serialize receipt: {err}"))
        })?;
        if let Value::Object(map) = &mut value {
            map.remove("receipt_digest");
        }
        Ok(blake3::hash(canonical_json(&value).as_bytes())
            .to_hex()
            .to_string())
    }

    /// Recheck schema, digest, and that every probe passed.
    ///
    /// # Errors
    ///
    /// `EGRESS_ISOLATION_UNPROVEN` naming the first inconsistency.
    pub fn verify(&self) -> Result<(), EgressError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(unproven(format!("schema {:?}", self.schema_version)));
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(unproven("receipt digest mismatch".to_string()));
        }
        if crate::ruleset::ruleset_digest(&self.ruleset_text) != self.ruleset_digest {
            return Err(unproven("ruleset digest mismatch".to_string()));
        }
        if self.probes.is_empty() || !self.all_probes_passed() {
            return Err(unproven("probes did not all pass".to_string()));
        }
        Ok(())
    }

    /// Whether every recorded probe passed.
    #[must_use]
    pub fn all_probes_passed(&self) -> bool {
        self.probes
            .iter()
            .all(|probe| probe.outcome == ProbeOutcome::Pass)
    }

    /// The admission-facing subset.
    #[must_use]
    pub fn evidence(&self) -> EgressEvidence {
        EgressEvidence {
            receipt_digest: self.receipt_digest.clone(),
            ruleset_digest: self.ruleset_digest.clone(),
            allowlist_digest: self.allowlist_digest.clone(),
            probes: self
                .probes
                .iter()
                .filter_map(|probe| {
                    probe.containment.map(|outcome| ContainmentProbe {
                        name: probe.name.clone(),
                        outcome,
                    })
                })
                .collect(),
        }
    }

    /// Canonical (sorted-key, compact) JSON of the whole receipt.
    ///
    /// # Errors
    ///
    /// `EGRESS_IO_FAILED` if the receipt cannot be serialized.
    pub fn canonical_json(&self) -> Result<String, EgressError> {
        let value = serde_json::to_value(self).map_err(|err| {
            EgressError::new(EgressCode::IoFailed, format!("serialize receipt: {err}"))
        })?;
        Ok(canonical_json(&value))
    }
}

fn unproven(detail: String) -> EgressError {
    EgressError::new(EgressCode::IsolationUnproven, detail)
}

/// Compact JSON with object keys sorted at every depth.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&sorted(value)).unwrap_or_default()
}

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let ordered: BTreeMap<&String, Value> =
                map.iter().map(|(k, v)| (k, sorted(v))).collect();
            let mut out = serde_json::Map::new();
            for (k, v) in ordered {
                out.insert(k.clone(), v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::GATEWAY;
    use crate::probes::Containment;
    use crate::ruleset::{ruleset_digest, ruleset_text};

    fn sample() -> EgressReceipt {
        let text = ruleset_text(GATEWAY, 40000);
        EgressReceipt {
            schema_version: SCHEMA_VERSION.into(),
            provider: "claude".into(),
            allowlist_mode: AllowlistMode::Strict,
            namespace_backend: "unshare".into(),
            gateway: GATEWAY.to_string(),
            proxy_port: 40000,
            allowlist: vec!["api.anthropic.com".into()],
            allowed_ports: vec![443],
            allowlist_digest: "a".repeat(64),
            ruleset_digest: ruleset_digest(&text),
            ruleset_text: text,
            ruleset_listing: "table inet bf_egress {}".into(),
            probes: vec![
                ProbeRecord {
                    name: "direct-internet".into(),
                    outcome: ProbeOutcome::Pass,
                    containment: Some(Containment::Refused),
                    expected: "refused".into(),
                    observed: "curl exit 7".into(),
                },
                ProbeRecord {
                    name: "proxy-disallowed".into(),
                    outcome: ProbeOutcome::Pass,
                    containment: None,
                    expected: "403".into(),
                    observed: "403".into(),
                },
            ],
            started_at: "2026-08-25T00:00:00.000Z".into(),
            tools: BTreeMap::from([(
                "nft".to_string(),
                ToolRecord {
                    path: "/usr/sbin/nft".into(),
                    version: "nftables v1.0.9".into(),
                },
            )]),
            receipt_digest: String::new(),
        }
    }

    #[test]
    fn seal_is_stable_and_verify_detects_tampering() {
        let sealed = sample().seal().unwrap();
        assert_eq!(sealed.receipt_digest.len(), 64);
        assert_eq!(
            sealed.receipt_digest,
            sample().seal().unwrap().receipt_digest
        );
        sealed.verify().unwrap();
        let mut tampered = sealed.clone();
        tampered.probes[0].outcome = ProbeOutcome::Fail;
        assert_eq!(
            tampered.verify().unwrap_err().code,
            EgressCode::IsolationUnproven
        );
        let mut resealed = tampered.seal().unwrap();
        assert!(
            resealed.verify().is_err(),
            "failed probe cannot verify even resealed"
        );
        resealed.probes[0].outcome = ProbeOutcome::Pass;
        resealed.ruleset_text.push('\n');
        assert!(
            resealed.seal().unwrap().verify().is_err(),
            "ruleset digest mismatch"
        );
        let mut wrong_schema = sealed.clone();
        wrong_schema.schema_version = "other".into();
        assert!(wrong_schema.seal().unwrap().verify().is_err());
        let evidence = sealed.evidence();
        assert_eq!(evidence.receipt_digest, sealed.receipt_digest);
        assert_eq!(
            evidence.probes,
            vec![ContainmentProbe {
                name: "direct-internet".into(),
                outcome: Containment::Refused
            }]
        );
        assert_eq!(
            serde_json::to_string(&evidence.probes).unwrap(),
            r#"[{"name":"direct-internet","outcome":"Refused"}]"#
        );
    }

    #[test]
    fn digest_covers_the_documented_canonical_form() {
        let sealed = sample().seal().unwrap();
        let mut value = serde_json::to_value(&sealed).unwrap();
        value.as_object_mut().unwrap().remove("receipt_digest");
        let expected = blake3::hash(canonical_json(&value).as_bytes())
            .to_hex()
            .to_string();
        assert_eq!(sealed.receipt_digest, expected);
        let round: EgressReceipt = serde_json::from_str(&sealed.canonical_json().unwrap()).unwrap();
        assert_eq!(round, sealed);
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let value: Value =
            serde_json::from_str(r#"{"z":{"b":1,"a":[{"y":2,"x":1}]},"a":0}"#).unwrap();
        assert_eq!(
            canonical_json(&value),
            r#"{"a":0,"z":{"a":[{"x":1,"y":2}],"b":1}}"#
        );
    }
}
