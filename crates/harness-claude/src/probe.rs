//! Contained runtime probe of the exact enrolled Claude executable (execution
//! plan M3 / PROBE-1b). One granted, egress-denied, bounded invocation of
//! `[<executable>, "--version"]` produces a proposal-free
//! [`RuntimeProbeObservation`] from native bytes only.
//!
//! Inputs are explicit ([`ProbeInput`]): the ENROLL-1 record supplies the
//! executable path and the digest it was enrolled with (an input, never
//! evidence), PROBE-GRANT-1's verified [`ProbeGrantEvidence`] authorizes one
//! probe of exactly those bytes, and the prepared egress-denied boundary
//! supplies its containment receipt digest and command factory. Every refusal
//! is typed; the executable identity is re-observed immediately before spawn;
//! the child runs through the frozen argv/env/process-group/deadline discipline
//! of `bullet_harness_core::argv` and `live::dispatch::capture_turn`.
//! `ArgvBuilder::build` quarantines every live-provider basename and
//! `build_with_admission` needs turn admission, so the probe assembles its
//! `PreparedInvocation` directly with the same kill-switch, denied-token, and
//! `filter_env` checks; the verified probe grant is its only authority.
//!
//! The frozen Claude protocol has no prompt-free hello: `system/init` is only
//! emitted in response to a user frame ([`crate::ClaudeStreamTranscript`]).
//! The probe therefore records `HandshakeRefused` and makes no second
//! invocation rather than inventing a handshake.
//!
//! Seam for ADMIT-1: the `LiveDispatcher::observe_runtime_probe` port carries
//! only the grant, so it keeps refusing `RUNTIME_PROBE_UNAVAILABLE`;
//! [`probe_claude`] is the real entry and must be called with a `ProbeInput`
//! assembled from the enrollment record, `verify_probe_grant`, and
//! `EgressBackend::prepare`.

use crate::PROVIDER;
use bullet_harness_core::argv::{denied_token, kill_switch_active, KILL_SWITCH_VAR};
use bullet_harness_core::launch_grant::is_lower_hex_64;
use bullet_harness_core::live::{
    native_text, ContainmentClass, ExecutableIdentity, ProbeExit, ProbeFacts, ProbeGrantEvidence,
    ProtocolHandshake, RuntimeProbeError, RuntimeProbeObservation,
};
use bullet_harness_core::{
    capture_turn, filter_env, CanarySecrets, CommandFactory, HarnessError, PreparedInvocation,
};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// The single argument the probe passes; the frozen protocol admits no other.
pub const PROBE_ARGUMENT: &str = "--version";
/// Hard cap on the probe wall deadline; the effective deadline is the smaller
/// of this and the grant's remaining validity (grant TTL is at most 15 s).
pub const MAX_PROBE_DEADLINE_MS: u64 = 10_000;
/// Containment the Claude probe requires; any other grant class is a mismatch.
pub const REQUIRED_CONTAINMENT: ContainmentClass = ContainmentClass::EgressDenied;
/// Recorded handshake reason: the frozen protocol defines no prompt-free hello.
pub const NO_PROMPT_FREE_HELLO: &str = "no prompt-free hello in frozen protocol";

/// The prepared egress-denied boundary the probe runs inside.
pub struct ProbeContainment<'a> {
    /// `EgressIsolationEvidence::receipt_digest` of the prepared boundary.
    pub receipt_blake3: String,
    /// Commands built by the boundary (`PreparedEgress::command`).
    pub command: &'a CommandFactory<'a>,
}

/// Explicit inputs of one contained probe. None of them is evidence by itself.
pub struct ProbeInput<'a> {
    /// Absolute path of the enrolled executable.
    pub executable: PathBuf,
    /// BLAKE3 the enrollment record claims for the executable bytes.
    pub expected_blake3: String,
    /// Evidence from a verified, single-use probe grant.
    pub grant: ProbeGrantEvidence,
    /// The prepared boundary; the probe refuses to run without one.
    pub containment: Option<ProbeContainment<'a>>,
    /// Host canaries scanned on every captured surface.
    pub canaries: CanarySecrets,
    /// Child working directory (a read-only fixture directory).
    pub workdir: PathBuf,
    /// Caller clock at probe start; also the recorded spawn instant.
    pub now_unix_ms: u64,
}

/// Typed probe refusal. Every variant carries a stable reason code; `UNKNOWN`
/// is never one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeRefusal {
    /// A refusal from the frozen probe contract (grant, output, executable).
    Probe(RuntimeProbeError),
    /// A refusal from the frozen argv/spawn discipline (kill switch, denied
    /// token, spawn, pipe, canary).
    Harness(HarnessError),
    /// No usable egress-denied boundary was supplied.
    ContainmentMissing { reason: &'static str },
    /// The bytes at the executable path differ from the enrollment record.
    ExecutableDrift { expected: String, observed: String },
    /// The wall deadline fired; the process group was killed.
    Deadline { deadline_ms: u64 },
    /// The child ended without an exit code before the deadline (signal);
    /// the capture path does not expose the signal, so nothing is invented.
    ExitUnavailable,
}

impl ProbeRefusal {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Probe(error) => error.reason_code(),
            Self::Harness(error) => error.reason_code(),
            Self::ContainmentMissing { .. } => "RUNTIME_PROBE_CONTAINMENT_MISSING",
            Self::ExecutableDrift { .. } => "RUNTIME_PROBE_EXECUTABLE_DRIFT",
            Self::Deadline { .. } => "RUNTIME_PROBE_DEADLINE",
            Self::ExitUnavailable => "RUNTIME_PROBE_EXIT_UNAVAILABLE",
        }
    }
}

impl fmt::Display for ProbeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.reason_code();
        match self {
            Self::Probe(error) => write!(f, "{code}: {error}"),
            Self::Harness(error) => write!(f, "{code}: {error}"),
            Self::ContainmentMissing { reason } => write!(f, "{code}: {reason}"),
            Self::ExecutableDrift { expected, observed } => {
                write!(f, "{code}: enrolled {expected}, observed {observed}")
            }
            Self::Deadline { deadline_ms } => {
                write!(
                    f,
                    "{code}: probe exceeded {deadline_ms} ms; process group killed"
                )
            }
            Self::ExitUnavailable => write!(f, "{code}: child ended without an exit code"),
        }
    }
}

impl std::error::Error for ProbeRefusal {}

impl From<RuntimeProbeError> for ProbeRefusal {
    fn from(error: RuntimeProbeError) -> Self {
        Self::Probe(error)
    }
}

impl From<HarnessError> for ProbeRefusal {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

/// The port refusal: the `LiveDispatcher` signature carries only the grant and
/// cannot reach the enrollment, boundary, canaries, or clock, so it never
/// spawns. Callers must use [`probe_claude`].
#[must_use]
pub fn port_refusal(_grant: &ProbeGrantEvidence) -> RuntimeProbeError {
    RuntimeProbeError::Unavailable {
        provider: PROVIDER.to_string(),
    }
}

/// The wall deadline for a probe started at `now` under a grant expiring at
/// `expires_at`: `min(MAX_PROBE_DEADLINE_MS, remaining)`, never zero.
///
/// # Errors
///
/// `RUNTIME_PROBE_GRANT_EXPIRED` when no validity remains.
pub fn probe_deadline_ms(expires_at_unix_ms: u64, now_unix_ms: u64) -> Result<u64, ProbeRefusal> {
    let remaining = expires_at_unix_ms.saturating_sub(now_unix_ms);
    if remaining == 0 {
        return Err(RuntimeProbeError::GrantExpired { expires_at_unix_ms }.into());
    }
    Ok(remaining.min(MAX_PROBE_DEADLINE_MS))
}

/// Run one contained `--version` probe of the enrolled Claude executable and
/// seal the native facts into a grant-bound [`RuntimeProbeObservation`].
///
/// Order, every step before the spawn refusing without a process: grant
/// structure and expiry; grant subject (provider `claude`, egress-denied
/// containment); containment handle present with a 64-hex receipt digest;
/// kill switch; deadline; then, immediately before spawn,
/// [`ExecutableIdentity::observe`] must equal both the grant and the
/// enrollment digest. The child runs through `capture_turn` under the
/// boundary's factory with the `filter_env` allowlist, argv exactly
/// `[<path>, "--version"]`, and the deadline; its stdout is bounded by
/// `MAX_PROBE_STDOUT_BYTES` via [`native_text`]; the observation is bound at
/// `now + wall_ms`, so a run that outlives the grant is refused as expired.
///
/// # Errors
///
/// A [`ProbeRefusal`] naming the exact step; see its variants.
pub fn probe_claude(input: &ProbeInput<'_>) -> Result<RuntimeProbeObservation, ProbeRefusal> {
    let grant = &input.grant;
    grant.verify(input.now_unix_ms)?;
    require_grant_subject(grant)?;
    let containment = require_containment(input.containment.as_ref())?;
    if kill_switch_active(std::env::var(KILL_SWITCH_VAR).ok().as_deref()) {
        return Err(HarnessError::KillSwitch.into());
    }
    let deadline_ms = probe_deadline_ms(grant.expires_at_unix_ms, input.now_unix_ms)?;
    let args = vec![PROBE_ARGUMENT.to_string()];
    for arg in &args {
        if denied_token(arg).is_some() {
            return Err(HarnessError::WorktreeFlagDenied { token: arg.clone() }.into());
        }
    }

    // Immediately before spawn: the bytes about to execute must be exactly
    // the bytes the grant authorizes and the enrollment record names.
    let identity = ExecutableIdentity::observe(&input.executable)?;
    if identity.blake3 != grant.executable_blake3 {
        return Err(RuntimeProbeError::GrantMismatch {
            field: "executable_blake3",
        }
        .into());
    }
    if identity.blake3 != input.expected_blake3 {
        return Err(ProbeRefusal::ExecutableDrift {
            expected: input.expected_blake3.clone(),
            observed: identity.blake3,
        });
    }
    let invocation = PreparedInvocation {
        program: identity.path.clone(),
        args,
        cwd: input.workdir.clone(),
        timeout: Duration::from_millis(deadline_ms),
        env: filter_env(std::env::vars()),
    };
    let capture = capture_turn(containment.command, &invocation, &input.canaries)?;
    if capture.timed_out {
        return Err(ProbeRefusal::Deadline { deadline_ms });
    }
    let exit = capture
        .exit_code
        .map(|code| ProbeExit::Code { code })
        .ok_or(ProbeRefusal::ExitUnavailable)?;
    let native_stdout = native_text(capture.stdout().as_bytes())?;

    let mut argv = Vec::with_capacity(invocation.args.len() + 1);
    argv.push(invocation.program.clone());
    argv.extend(invocation.args.iter().cloned());
    let facts = ProbeFacts {
        provider: PROVIDER.to_string(),
        executable: identity,
        argv,
        native_stdout,
        handshake: ProtocolHandshake::HandshakeRefused {
            reason: NO_PROMPT_FREE_HELLO.to_string(),
        },
        // `--version` output evidences no capability; none is claimed.
        capabilities: Vec::new(),
        exit,
        wall_ms: capture.wall_ms,
        observed_at_unix_ms: input.now_unix_ms,
        containment_receipt_blake3: containment.receipt_blake3.clone(),
    };
    let completed_unix_ms = input.now_unix_ms.saturating_add(capture.wall_ms);
    Ok(RuntimeProbeObservation::from_native(
        facts,
        grant,
        completed_unix_ms,
    )?)
}

fn require_grant_subject(grant: &ProbeGrantEvidence) -> Result<(), ProbeRefusal> {
    if grant.provider != PROVIDER {
        return Err(RuntimeProbeError::GrantMismatch { field: "provider" }.into());
    }
    if grant.containment != REQUIRED_CONTAINMENT {
        return Err(RuntimeProbeError::GrantMismatch {
            field: "containment",
        }
        .into());
    }
    Ok(())
}

fn require_containment<'a, 'b>(
    containment: Option<&'a ProbeContainment<'b>>,
) -> Result<&'a ProbeContainment<'b>, ProbeRefusal> {
    let containment = containment.ok_or(ProbeRefusal::ContainmentMissing {
        reason: "no prepared egress-denied boundary was supplied",
    })?;
    if !is_lower_hex_64(&containment.receipt_blake3) {
        return Err(ProbeRefusal::ContainmentMissing {
            reason: "containment receipt digest must be 64 lowercase hex",
        });
    }
    Ok(containment)
}
