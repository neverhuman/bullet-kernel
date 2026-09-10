//! Operator bind probe. Does not spawn a provider or write enrollments.

use serde_json::{json, Value};

pub(super) const REQUIRED: &[&str] = &[
    "BULLET_HARNESS_HOME",
    "BULLET_HARNESS_WORK_PACKAGE_ID",
    "BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST",
    "BULLET_HARNESS_CANDIDATE_VERIFICATION_KEY",
    "BULLET_HARNESS_WORKSPACE_ROOT",
    "BULLET_HARNESS_SOURCE_REPO",
    "BULLET_HARNESS_BASE_SHA",
    "BULLET_HARNESS_PRESERVATION",
    "BULLET_HARNESS_OBJECTIVE",
    "BULLET_HARNESS_GATE_ID",
    "BULLET_HARNESS_SCOPE",
    "BULLET_HARNESS_IDEMPOTENCY_KEY",
    "BULLET_HARNESS_LEASE_SOCKET",
    "BULLET_HARNESS_FARMD_UID",
    "BULLET_HARNESS_SOCKET_GID",
    "BULLET_HARNESS_LEASE_RECOVERY",
    "BULLET_HARNESS_EXECUTABLE",
];

const PATH_DEFAULT: &str = "/usr/bin:/bin";

const CLAUDE_EXTRA: &[&str] = &[
    "BULLET_HARNESS_DOGFOOD_DATA_DIR",
    "BULLET_HARNESS_DOGFOOD_POLICY",
    "BULLET_HARNESS_DOGFOOD_BINDING",
    "BULLET_HARNESS_DOGFOOD_ENROLLMENT",
    "BULLET_HARNESS_DOGFOOD_ISSUER",
    "BULLET_HARNESS_DOGFOOD_KEY_ID",
    "BULLET_HARNESS_DOGFOOD_RECEIPT",
    "BULLET_HARNESS_DOGFOOD_MAX_BUDGET_USD",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Report {
    pub(super) outcome: &'static str,
    pub(super) rows: Vec<(String, &'static str)>,
}

impl Report {
    pub(super) fn json(&self) -> Value {
        json!({
            "outcome": self.outcome,
            "worker_unbound_code": "COMMAND_CODING_HARNESS_UNBOUND",
            "path_default": PATH_DEFAULT,
            "bindings": self.rows.iter().map(|(name, state)| json!({
                "name": name,
                "state": state,
            })).collect::<Vec<_>>(),
        })
    }
}

pub(super) fn inspect(vars: &[(&str, Option<String>)]) -> Report {
    let mut rows = Vec::new();
    let mut missing = 0_usize;
    for name in REQUIRED {
        let present = vars
            .iter()
            .find(|(key, _)| *key == *name)
            .and_then(|(_, value)| value.as_deref())
            .is_some_and(|value| !value.is_empty());
        if present {
            rows.push(((*name).to_string(), "PRESENT"));
        } else {
            missing += 1;
            rows.push(((*name).to_string(), "ABSENT"));
        }
    }
    let path = vars
        .iter()
        .find(|(key, _)| *key == "BULLET_HARNESS_PATH")
        .and_then(|(_, value)| value.as_deref())
        .filter(|value| !value.is_empty());
    rows.push((
        "BULLET_HARNESS_PATH".into(),
        if path.is_some() {
            "PRESENT"
        } else {
            "ABSENT_DEFAULTS"
        },
    ));
    for name in CLAUDE_EXTRA {
        let present = vars
            .iter()
            .find(|(key, _)| *key == *name)
            .and_then(|(_, value)| value.as_deref())
            .is_some_and(|value| !value.is_empty());
        rows.push((
            (*name).to_string(),
            if present {
                "PRESENT"
            } else {
                "ABSENT_CLAUDE_ONLY"
            },
        ));
    }
    Report {
        outcome: if missing == 0 { "BOUND" } else { "UNBOUND" },
        rows,
    }
}

pub(super) fn from_env() -> Report {
    let mut pairs = Vec::new();
    for name in REQUIRED
        .iter()
        .copied()
        .chain(std::iter::once("BULLET_HARNESS_PATH"))
        .chain(CLAUDE_EXTRA.iter().copied())
    {
        pairs.push((
            name,
            std::env::var(name).ok().filter(|value| !value.is_empty()),
        ));
    }
    inspect(&pairs)
}
