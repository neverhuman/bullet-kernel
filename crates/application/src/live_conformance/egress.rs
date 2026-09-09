//! Test-only no-op egress backend for the non-namespace workspace test run.
//!
//! The genuine namespace + nftables + CONNECT-proxy proof lives in
//! `bullet-harness-egress` and runs only under `ops/ci/egress.sh`. This double
//! supplies well-formed containment evidence and a plain command factory so the
//! orchestration (mint -> verify -> admit_signed -> admit_egress -> dispatch ->
//! receipt) can be exercised without unprivileged namespaces. It is compiled
//! only under `test` or the `test-seams` feature and is never wired into the
//! production CLI, which always uses the real backend.

use bullet_harness_core::{
    EgressBackend, EgressIsolationEvidence, EgressProbe, EgressProbeOutcome, HarnessError,
    PreparedEgress,
};
use std::path::Path;
use std::process::Command;

/// A no-op egress backend that yields refused-probe evidence and plain
/// commands. Test double only.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopEgressBackend;

impl NoopEgressBackend {
    /// Construct the test double.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn digest(label: &str) -> String {
    blake3::hash(format!("bullet-live-conformance-noop-egress/{label}").as_bytes())
        .to_hex()
        .to_string()
}

impl EgressBackend for NoopEgressBackend {
    fn sandbox_manifest_digest(&self, provider: &str) -> Result<String, HarnessError> {
        Ok(digest(&format!("manifest/{provider}")))
    }

    fn prepare(
        &self,
        provider: &str,
        _workdir: &Path,
    ) -> Result<Box<dyn PreparedEgress + '_>, HarnessError> {
        Ok(Box::new(NoopPreparedEgress {
            provider: provider.to_string(),
        }))
    }
}

struct NoopPreparedEgress {
    provider: String,
}

impl PreparedEgress for NoopPreparedEgress {
    fn evidence(&self) -> EgressIsolationEvidence {
        EgressIsolationEvidence {
            receipt_digest: digest(&format!("receipt/{}", self.provider)),
            ruleset_digest: digest(&format!("ruleset/{}", self.provider)),
            allowlist_digest: digest(&format!("allowlist/{}", self.provider)),
            probes: vec![
                EgressProbe {
                    name: "direct-internet".into(),
                    outcome: EgressProbeOutcome::Refused,
                },
                EgressProbe {
                    name: "host-jeryu".into(),
                    outcome: EgressProbeOutcome::Refused,
                },
            ],
        }
    }

    fn command(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(program);
        command.args(args).env_clear();
        for (key, value) in env {
            command.env(key, value);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command
    }
}
