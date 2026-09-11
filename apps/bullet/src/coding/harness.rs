//! Operator bind probe and ledger-identity producer. Does not spawn a provider
//! or write enrollments.

use bullet_domain::{CommandId, WorkPackageId};
use serde_json::{json, Value};
use std::path::Path;

/// Same seed the command worker uses for v2 `run_coding` work packages.
pub(super) const WORK_PACKAGE_SEED: &str = "bullet.coding-work-package.v1";

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Produced {
    pub(super) work_package_id: String,
    pub(super) candidate_request_digest: String,
    pub(super) idempotency_key: String,
}

impl Produced {
    pub(super) fn json(&self) -> Value {
        json!({
            "outcome": "PRODUCED",
            "work_package_seed": WORK_PACKAGE_SEED,
            "BULLET_HARNESS_WORK_PACKAGE_ID": self.work_package_id,
            "BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST": self.candidate_request_digest,
            "BULLET_HARNESS_IDEMPOTENCY_KEY": self.idempotency_key,
        })
    }

    pub(super) fn export_lines(&self) -> String {
        format!(
            "BULLET_HARNESS_WORK_PACKAGE_ID={}\nBULLET_HARNESS_CANDIDATE_REQUEST_DIGEST={}\nBULLET_HARNESS_IDEMPOTENCY_KEY={}\n",
            self.work_package_id, self.candidate_request_digest, self.idempotency_key
        )
    }
}

pub(super) fn write_env_file(path: &Path, produced: &Produced) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("HARNESS_ENV_FILE_NOT_ABSOLUTE".into());
    }
    if path.is_symlink() {
        return Err("HARNESS_ENV_FILE_SYMLINK".into());
    }
    let mut lines = if path.exists() {
        std::fs::read_to_string(path).map_err(|_| "HARNESS_ENV_FILE_UNREADABLE")?
    } else {
        String::new()
    };
    if lines.contains('\0') {
        return Err("HARNESS_ENV_FILE_INVALID".into());
    }
    for (name, value) in [
        (
            "BULLET_HARNESS_WORK_PACKAGE_ID",
            produced.work_package_id.as_str(),
        ),
        (
            "BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST",
            produced.candidate_request_digest.as_str(),
        ),
        (
            "BULLET_HARNESS_IDEMPOTENCY_KEY",
            produced.idempotency_key.as_str(),
        ),
    ] {
        let prefix = format!("{name}=");
        let replacement = format!("{name}={value}");
        let mut found = false;
        let mut next = String::new();
        for line in lines.lines() {
            if line.starts_with(&prefix) {
                next.push_str(&replacement);
                next.push('\n');
                found = true;
            } else {
                next.push_str(line);
                next.push('\n');
            }
        }
        if !found {
            next.push_str(&replacement);
            next.push('\n');
        }
        lines = next;
    }
    let tmp = path.with_extension("env.tmp");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| "HARNESS_ENV_FILE_UNWRITABLE")?;
        use std::io::Write;
        file.write_all(lines.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| "HARNESS_ENV_FILE_UNWRITABLE")?;
    }
    std::fs::rename(&tmp, path).map_err(|_| "HARNESS_ENV_FILE_UNWRITABLE")?;
    Ok(())
}

pub(super) fn produce(
    command_id: &str,
    request_digest: &str,
    idempotency_key: &str,
) -> Result<Produced, String> {
    let command_id = CommandId::parse(command_id).map_err(|_| "COMMAND_ID_INVALID")?;
    if request_digest.len() != 64
        || !request_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("REQUEST_DIGEST_INVALID: expected 64 lowercase hex".into());
    }
    if idempotency_key.is_empty() || idempotency_key.contains('\n') {
        return Err("IDEMPOTENCY_KEY_INVALID: single-line key required".into());
    }
    let seed = format!("{WORK_PACKAGE_SEED}\0{command_id}");
    Ok(Produced {
        work_package_id: WorkPackageId::from_seed(&seed).to_string(),
        candidate_request_digest: request_digest.to_string(),
        idempotency_key: idempotency_key.to_string(),
    })
}

pub(super) fn from_env() -> Report {
    inspect(&env_pairs(None))
}

pub(super) fn from_env_with_produced(produced: &Produced) -> Report {
    inspect(&env_pairs(Some(produced)))
}

fn env_pairs(produced: Option<&Produced>) -> Vec<(&'static str, Option<String>)> {
    let mut pairs = Vec::new();
    for name in REQUIRED
        .iter()
        .copied()
        .chain(std::iter::once("BULLET_HARNESS_PATH"))
        .chain(CLAUDE_EXTRA.iter().copied())
    {
        let overlay = produced.and_then(|produced| match name {
            "BULLET_HARNESS_WORK_PACKAGE_ID" => Some(produced.work_package_id.clone()),
            "BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST" => {
                Some(produced.candidate_request_digest.clone())
            }
            "BULLET_HARNESS_IDEMPOTENCY_KEY" => Some(produced.idempotency_key.clone()),
            _ => None,
        });
        pairs.push((
            name,
            overlay.or_else(|| std::env::var(name).ok().filter(|value| !value.is_empty())),
        ));
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::CommandId;

    #[test]
    fn produce_matches_worker_seed() {
        let command_id = CommandId::from_seed("harness-bind");
        let digest = "ab".repeat(32);
        let produced = produce(command_id.as_str(), &digest, "bind-key").expect("produce");
        let expected =
            WorkPackageId::from_seed(&format!("{WORK_PACKAGE_SEED}\0{command_id}")).to_string();
        assert_eq!(produced.work_package_id, expected);
        assert_eq!(produced.candidate_request_digest, digest);
        assert_eq!(produced.idempotency_key, "bind-key");
        assert!(produced.json()["outcome"] == "PRODUCED");
        assert!(produced
            .export_lines()
            .contains(&format!("BULLET_HARNESS_WORK_PACKAGE_ID={expected}")));
        let dir = std::env::temp_dir().join(format!("bullet-harness-bind-{}", command_id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let env_file = dir.join("harness.env");
        std::fs::write(&env_file, "BULLET_HARNESS_HOME=/tmp/home\n").expect("seed");
        write_env_file(&env_file, &produced).expect("merge");
        let merged = std::fs::read_to_string(&env_file).expect("read");
        assert!(merged.contains("BULLET_HARNESS_HOME=/tmp/home"));
        assert!(merged.contains(&format!("BULLET_HARNESS_WORK_PACKAGE_ID={expected}")));
        assert!(
            write_env_file(std::path::Path::new("relative.env"), &produced)
                .unwrap_err()
                .contains("HARNESS_ENV_FILE_NOT_ABSOLUTE")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn produce_refuses_invalid_inputs() {
        assert_eq!(
            produce("cmd_nope", &"ab".repeat(32), "k").unwrap_err(),
            "COMMAND_ID_INVALID"
        );
        let command_id = CommandId::from_seed("x");
        assert!(produce(command_id.as_str(), "ZZ", "k")
            .unwrap_err()
            .starts_with("REQUEST_DIGEST_INVALID"));
        assert!(produce(command_id.as_str(), &"ab".repeat(32), "k\n")
            .unwrap_err()
            .starts_with("IDEMPOTENCY_KEY_INVALID"));
    }

    #[test]
    fn overlay_three_makes_those_rows_present() {
        let command_id = CommandId::from_seed("bound-overlay");
        let produced = produce(command_id.as_str(), &"cd".repeat(32), "overlay-key").unwrap();
        let report = inspect(&env_pairs(Some(&produced)));
        for name in [
            "BULLET_HARNESS_WORK_PACKAGE_ID",
            "BULLET_HARNESS_CANDIDATE_REQUEST_DIGEST",
            "BULLET_HARNESS_IDEMPOTENCY_KEY",
        ] {
            assert!(
                report
                    .rows
                    .iter()
                    .any(|(row, state)| row == name && *state == "PRESENT"),
                "{name} {:?}",
                report.rows
            );
        }
    }
}
