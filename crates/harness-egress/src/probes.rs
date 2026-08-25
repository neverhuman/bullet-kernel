//! In-namespace isolation probes executed with `curl` before any child runs.
//! Every probe has a fixed expectation; any mismatch is
//! `EGRESS_ISOLATION_UNPROVEN` and the sandbox is torn down unused.

use crate::allowlist::EgressPolicy;
use crate::decisions::{Decision, DecisionLog};
use crate::error::{EgressCode, EgressError};
use crate::namespace::{Captured, Namespace, GATEWAY, GUEST_DNS};
use crate::ruleset::{parse_counters, CounterSnapshot, COUNTER_DNS, COUNTER_OTHER, TABLE};
use crate::tools::Tooling;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Host port of the local Jeryu that must be unreachable from inside.
pub const JERYU_PORT: u16 = 8787;
/// curl exit codes accepted as "could not reach": 7 = failed to connect, 28 = timed out.
const UNREACHABLE_EXITS: [i32; 2] = [7, 28];
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// Whether a probe matched its expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeOutcome {
    /// Observed exactly the expected refusal/acceptance.
    Pass,
    /// Observed something else; isolation is unproven.
    Fail,
}

/// What a containment probe's destination did, in the vocabulary admission
/// binds to. Only `Refused` and `Unreachable` ever clear the egress blocker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Containment {
    /// Actively refused, attributed to the ruleset by its counter delta.
    Refused,
    /// No answer inside the bound, attributed to the ruleset by its counter delta.
    Unreachable,
    /// The destination answered; containment failed.
    Reached,
    /// Could not decide (killed at deadline, or a failure not attributable to the ruleset).
    Unknown,
}

/// One probe result as recorded in the receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRecord {
    /// Stable probe name.
    pub name: String,
    /// Pass or fail against this probe's expectation.
    pub outcome: ProbeOutcome,
    /// Containment verdict for destination probes; `None` for proxy-decision probes.
    pub containment: Option<Containment>,
    /// Human-readable expectation.
    pub expected: String,
    /// Human-readable observation.
    pub observed: String,
}

/// `{name, outcome}` pair for one containment probe (admission evidence shape).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentProbe {
    /// Stable probe name.
    pub name: String,
    /// Containment verdict.
    pub outcome: Containment,
}

/// Which named counter a refusal probe must increment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Counter {
    Dns,
    Other,
}

impl Counter {
    const fn name(self) -> &'static str {
        match self {
            Self::Dns => COUNTER_DNS,
            Self::Other => COUNTER_OTHER,
        }
    }

    const fn read(self, snapshot: CounterSnapshot) -> u64 {
        match self {
            Self::Dns => snapshot.dns,
            Self::Other => snapshot.other,
        }
    }
}

/// Everything the probes need.
pub struct ProbeContext<'a> {
    /// Live namespace to enter.
    pub namespace: &'a Namespace,
    /// Resolved tool paths.
    pub tools: &'a Tooling,
    /// Policy under test.
    pub policy: &'a EgressPolicy,
    /// Proxy decision log (checked for the expected decision).
    pub log: &'a DecisionLog,
    /// Host proxy port (the only admitted destination).
    pub proxy_port: u16,
    /// Host port of a listener the sandbox itself opened; must be unreachable.
    pub decoy_port: u16,
}

/// Run every probe in order. Errors are infrastructure failures (cannot run
/// curl or read counters), never a failed expectation.
///
/// # Errors
///
/// `EGRESS_IO_FAILED` or `EGRESS_RULESET_FAILED` when a probe cannot execute.
pub fn run_probes(ctx: &ProbeContext<'_>) -> Result<Vec<ProbeRecord>, EgressError> {
    let proxy = format!("http://{GATEWAY}:{}", ctx.proxy_port);
    let host = ctx
        .policy
        .allowlist()
        .into_iter()
        .next()
        .unwrap_or_default();
    let port = ctx.policy.ports().into_iter().next().unwrap_or(443);
    let allowed_url = format!("https://{host}:{port}/");
    Ok(vec![
        refusal_probe(ctx, "direct-internet", "https://1.1.1.1/", Counter::Other)?,
        refusal_probe(
            ctx,
            "host-jeryu",
            &format!("http://{GATEWAY}:{JERYU_PORT}/"),
            Counter::Other,
        )?,
        refusal_probe(
            ctx,
            "host-decoy",
            &format!("http://{GATEWAY}:{}/", ctx.decoy_port),
            Counter::Other,
        )?,
        refusal_probe(
            ctx,
            "dns-blocked-tcp",
            &format!("http://{GUEST_DNS}:53/"),
            Counter::Dns,
        )?,
        udp_dns_probe(ctx)?,
        proxy_probe(
            ctx,
            "proxy-reachable",
            &["-w", "%{http_code}", &format!("{proxy}/")],
            "405",
            ("", Decision::Malformed, "method-not-allowed:GET"),
        )?,
        proxy_probe(
            ctx,
            "proxy-disallowed",
            &[
                "-p",
                "-x",
                &proxy,
                "-w",
                "%{http_connect}",
                "https://example.com/",
            ],
            "403",
            ("example.com:443", Decision::Deny, "host-not-allowlisted"),
        )?,
        proxy_probe(
            ctx,
            "proxy-allowed-path",
            &["-p", "-x", &proxy, "-w", "%{http_connect}", &allowed_url],
            "503",
            (&format!("{host}:{port}"), Decision::Allow, "disarmed"),
        )?,
    ])
}

/// Fail closed unless every probe passed.
///
/// # Errors
///
/// `EGRESS_ISOLATION_UNPROVEN` listing each failed probe.
pub fn require_all_pass(records: &[ProbeRecord]) -> Result<(), EgressError> {
    let failed: Vec<String> = records
        .iter()
        .filter(|r| r.outcome == ProbeOutcome::Fail)
        .map(|r| {
            format!(
                "{} (expected {}; observed {})",
                r.name, r.expected, r.observed
            )
        })
        .collect();
    if records.is_empty() {
        return Err(EgressError::new(
            EgressCode::IsolationUnproven,
            "no probes were executed",
        ));
    }
    if failed.is_empty() {
        return Ok(());
    }
    Err(EgressError::new(
        EgressCode::IsolationUnproven,
        format!("{} probe(s) failed: {}", failed.len(), failed.join("; ")),
    ))
}

fn curl(ctx: &ProbeContext<'_>, args: &[&str]) -> Result<Captured, EgressError> {
    let mut argv = vec!["-q", "-s", "-o", "/dev/null"];
    argv.extend_from_slice(args);
    ctx.namespace
        .run_captured(&ctx.tools.curl.path, &argv, None, PROBE_TIMEOUT)
}

fn counters(ctx: &ProbeContext<'_>) -> Result<CounterSnapshot, EgressError> {
    let out = ctx.namespace.run_captured(
        &ctx.tools.nft.path,
        &["-j", "list", "counters", "table", "inet", TABLE],
        None,
        PROBE_TIMEOUT,
    )?;
    if out.code != Some(0) {
        return Err(EgressError::new(
            EgressCode::RulesetFailed,
            format!(
                "nft list counters exit {:?}: {}",
                out.code,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    parse_counters(&String::from_utf8_lossy(&out.stdout))
}

fn refusal_probe(
    ctx: &ProbeContext<'_>,
    name: &str,
    url: &str,
    counter: Counter,
) -> Result<ProbeRecord, EgressError> {
    let before = counter.read(counters(ctx)?);
    let out = curl(ctx, &["-m", "3", url])?;
    let delta = counter.read(counters(ctx)?).saturating_sub(before);
    Ok(evaluate_refusal(
        name,
        url,
        counter.name(),
        &out,
        delta,
        &UNREACHABLE_EXITS,
    ))
}

fn udp_dns_probe(ctx: &ProbeContext<'_>) -> Result<ProbeRecord, EgressError> {
    let url = format!("tftp://{GUEST_DNS}:53/probe");
    let before = counters(ctx)?.dns;
    let out = curl(ctx, &["-m", "1", &url])?;
    let delta = counters(ctx)?.dns.saturating_sub(before);
    Ok(evaluate_refusal(
        "dns-blocked-udp",
        &url,
        COUNTER_DNS,
        &out,
        delta,
        &UNREACHABLE_EXITS,
    ))
}

fn evaluate_refusal(
    name: &str,
    url: &str,
    counter: &str,
    out: &Captured,
    delta: u64,
    accepted_exits: &[i32],
) -> ProbeRecord {
    let containment = match out.code {
        _ if out.timed_out => Containment::Unknown,
        Some(0) => Containment::Reached,
        Some(7) if delta >= 1 => Containment::Refused,
        Some(28) if delta >= 1 => Containment::Unreachable,
        _ => Containment::Unknown,
    };
    let refused = !out.timed_out && out.code.is_some_and(|c| accepted_exits.contains(&c));
    let outcome = if refused && delta >= 1 {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Fail
    };
    ProbeRecord {
        name: name.to_string(),
        outcome,
        containment: Some(containment),
        expected: format!("{url}: curl exit in {accepted_exits:?}, {counter} +>=1"),
        observed: match (out.timed_out, out.code) {
            (true, _) => format!("curl killed at deadline, {counter} +{delta}"),
            (false, Some(code)) => format!("curl exit {code}, {counter} +{delta}"),
            (false, None) => format!("curl exit signal, {counter} +{delta}"),
        },
    }
}

fn proxy_probe(
    ctx: &ProbeContext<'_>,
    name: &str,
    args: &[&str],
    expected_code: &str,
    expected_log: (&str, Decision, &str),
) -> Result<ProbeRecord, EgressError> {
    let mut argv = vec!["-m", "5"];
    argv.extend_from_slice(args);
    let out = curl(ctx, &argv)?;
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let (target, decision, reason) = expected_log;
    let logged = ctx
        .log
        .recent()
        .into_iter()
        .rev()
        .find(|r| r.target == target)
        .map(|r| (r.decision, r.reason))
        .unwrap_or((Decision::Malformed, "<none>".to_string()));
    Ok(evaluate_proxy(
        name,
        expected_code,
        (target, decision, reason),
        &code,
        &logged,
    ))
}

fn evaluate_proxy(
    name: &str,
    expected_code: &str,
    expected_log: (&str, Decision, &str),
    observed_code: &str,
    observed_log: &(Decision, String),
) -> ProbeRecord {
    let (target, decision, reason) = expected_log;
    let pass =
        observed_code == expected_code && observed_log.0 == decision && observed_log.1 == reason;
    ProbeRecord {
        name: name.to_string(),
        outcome: if pass {
            ProbeOutcome::Pass
        } else {
            ProbeOutcome::Fail
        },
        containment: None,
        expected: format!("http {expected_code}; log {target:?} {decision:?} {reason}"),
        observed: format!(
            "http {observed_code:?}; log {target:?} {:?} {}",
            observed_log.0, observed_log.1
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(code: Option<i32>, timed_out: bool) -> Captured {
        Captured {
            code,
            timed_out,
            ..Captured::default()
        }
    }

    #[test]
    fn refusal_needs_both_exit_code_and_counter_delta() {
        let ok = evaluate_refusal(
            "p",
            "u",
            COUNTER_OTHER,
            &captured(Some(7), false),
            1,
            &[7, 28],
        );
        assert_eq!(ok.outcome, ProbeOutcome::Pass);
        let reached = evaluate_refusal(
            "p",
            "u",
            COUNTER_OTHER,
            &captured(Some(0), false),
            0,
            &[7, 28],
        );
        assert_eq!(reached.outcome, ProbeOutcome::Fail);
        assert_eq!(reached.containment, Some(Containment::Reached));
        let no_counter = evaluate_refusal(
            "p",
            "u",
            COUNTER_OTHER,
            &captured(Some(7), false),
            0,
            &[7, 28],
        );
        assert_eq!(no_counter.outcome, ProbeOutcome::Fail);
        assert_eq!(no_counter.containment, Some(Containment::Unknown));
        let killed = evaluate_refusal("p", "u", COUNTER_OTHER, &captured(None, true), 1, &[7, 28]);
        assert_eq!(killed.outcome, ProbeOutcome::Fail);
        assert_eq!(killed.containment, Some(Containment::Unknown));
        assert!(killed.observed.contains("deadline"));
    }

    #[test]
    fn proxy_probe_needs_status_and_logged_decision() {
        let expected = ("example.com:443", Decision::Deny, "host-not-allowlisted");
        let logged = (Decision::Deny, "host-not-allowlisted".to_string());
        let ok = evaluate_proxy("p", "403", expected, "403", &logged);
        assert_eq!((ok.outcome, ok.containment), (ProbeOutcome::Pass, None));
        assert_eq!(
            evaluate_proxy("p", "403", expected, "200", &logged).outcome,
            ProbeOutcome::Fail
        );
        let wrong = (Decision::Allow, "tunnel".to_string());
        assert_eq!(
            evaluate_proxy("p", "403", expected, "403", &wrong).outcome,
            ProbeOutcome::Fail
        );
    }

    #[test]
    fn require_all_pass_is_typed_and_names_failures() {
        let pass = ProbeRecord {
            name: "a".into(),
            outcome: ProbeOutcome::Pass,
            containment: Some(Containment::Refused),
            expected: "x".into(),
            observed: "x".into(),
        };
        let fail = ProbeRecord {
            name: "direct-internet".into(),
            outcome: ProbeOutcome::Fail,
            containment: Some(Containment::Reached),
            expected: "refused".into(),
            observed: "curl exit 0".into(),
        };
        require_all_pass(std::slice::from_ref(&pass)).unwrap();
        let err = require_all_pass(&[pass, fail]).unwrap_err();
        assert_eq!(err.code, EgressCode::IsolationUnproven);
        assert!(err.detail.contains("direct-internet"));
        assert!(err.detail.contains("curl exit 0"));
        assert_eq!(
            require_all_pass(&[]).unwrap_err().code,
            EgressCode::IsolationUnproven
        );
    }
}
