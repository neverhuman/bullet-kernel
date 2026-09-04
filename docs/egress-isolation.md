# Provider egress isolation

Status: committed Linux boundary; `COMPONENT_PROOF` on a capable host
Owner: Bullet Farm maintainers
Last reviewed: 2026-08-26 against HEAD `3fb9d8e`
Source of truth: `crates/harness-egress/src/{lib,allowlist,decisions,error,namespace,probes,proxy,receipt,request,ruleset,sandbox,tools,tunnel}.rs`;
consumer: `crates/harness-core/src/admission/signed.rs`
<!-- bullet-doc-review:v1 subject=f8aa2b087a2fff064669ee136d25eb64ffad594e max_distance=25 paths=crates/harness-egress/src/lib.rs,crates/harness-egress/src/sandbox.rs,crates/harness-core/src/admission/signed.rs -->

`bullet-harness-egress` launches a provider CLI inside a fresh Linux user +
network namespace whose only route out is a `slirp4netns` uplink to a
host-side, allow-listing HTTP `CONNECT` proxy. It is driven entirely through
host binaries (no `unsafe`), proves itself with in-namespace probes before any
child runs, and seals the result into an `EgressReceipt` that admission binds.
It never depends on `harness-core`.

## Boundary, in order (`EgressSandbox::prepare_with`)

1. **Tools** (`tools.rs`): `unshare`, `nsenter`, `slirp4netns`, `nft`,
   `curl`, `cat`, `kill` are resolved once on `PATH` plus
   `/usr/sbin:/sbin:/usr/bin:/bin`; absolute path and `--version` line go into
   the receipt. A missing tool is `EGRESS_TOOL_MISSING`.
2. **Decision log** (`decisions.rs`): append-only JSONL
   `<workdir>/egress-decisions.jsonl` with a 256-entry in-memory tail; each
   line is `{ts, provider, target, decision, reason, status}` with
   `decision ∈ {allow, deny, malformed, limit}`.
3. **Proxy** (`proxy.rs`, `tunnel.rs`): binds `127.0.0.1:<ephemeral>` and
   starts **disarmed** — admitted targets answer `503` (logged `allow`
   / `disarmed`) so no probe ever opens a real upstream connection.
4. **Namespace holder** (`namespace.rs`): `unshare --user --map-root-user
   --net -- cat` in its own process group, reading a pipe held by this
   process, so the holder dies with the parent even on SIGKILL. Creation
   waits until `/proc/<pid>/ns/net` differs from ours (`EGRESS_NAMESPACE_FAILED`
   after 5 s). Commands enter with `nsenter --preserve-credentials --user
   --net --target <pid>` in the same process group.
5. **Uplink**: `slirp4netns --configure --mtu 65520 --ready-fd 1 --exit-fd 0
   <pid> tap0`; the host is `GATEWAY = 10.0.2.2`, the slirp DNS forwarder is
   `10.0.2.3`. Readiness is the single byte `1` within 10 s
   (`EGRESS_UPLINK_FAILED`).
6. **Ruleset** (`ruleset.rs`): `nft -f -` inside the namespace installs table
   `inet bf_egress` with chain `output` (`type filter hook output priority
   filter; policy drop`), two named counters, and exactly two accepts:

   ```text
   oif "lo" accept
   ip daddr 10.0.2.2 tcp dport <proxy_port> accept
   udp dport 53 counter name "dns_rejected" reject
   tcp dport 53 counter name "dns_rejected" reject with tcp reset
   meta l4proto tcp counter name "other_rejected" reject with tcp reset
   counter name "other_rejected" reject with icmpx type admin-prohibited
   ```

   Counted `reject` rules exist so a sandboxed CLI fails immediately
   (ECONNREFUSED/EPERM) instead of hanging on silent drops, and so the receipt
   can show counter deltas. `verify_listing` re-reads `nft list ruleset` from
   the kernel and refuses (`EGRESS_RULESET_FAILED`) unless the table, policy
   drop, both counters, exactly 2 accept rules, no `policy accept`, and exactly
   one table are present.
7. **Decoy**: the sandbox opens its own host listener on `127.0.0.1:<ephemeral>`
   so the probes can show that even a port the sandbox itself owns is
   unreachable from inside.
8. **Probes** (`probes.rs`): all eight run with `curl` inside the namespace;
   any mismatch is `EGRESS_ISOLATION_UNPROVEN` and the sandbox is torn down
   unused. `require_all_pass` also refuses an empty probe set.
9. **Receipt** (`receipt.rs`): sealed, written fsync'd to
   `<workdir>/egress-receipt.json`, then the proxy is **armed** and
   `PreparedSandbox` is returned.

## Allowlists (`allowlist.rs`)

Reviewed policy data, not discovery. Every entry carries a rationale; nothing
is admitted by suffix, wildcard, IP literal, or any port other than the policy
port set (443 for provider tables). `Strict` (default) admits only model-API
hosts; `Extended` adds login/feature-flag hosts. Provider label `antigravity`
is used here where admission and grants use `agy`.

| Provider | Strict | Extended only |
| --- | --- | --- |
| `claude` | `api.anthropic.com` | `claude.ai`, `console.anthropic.com`, `statsig.anthropic.com` (`sentry.io` is deliberately absent) |
| `codex` | `api.openai.com` | `chatgpt.com`, `auth.openai.com` |
| `cursor` | `api2.cursor.sh`, `api3.cursor.sh` | `repo42.cursor.sh`, `authenticator.cursor.sh`, `cursor.com` |
| `antigravity` | `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com` | `oauth2.googleapis.com`, `accounts.google.com` |

`EgressPolicy::custom(label, hosts, ports)` exists for tests and operator
experiments; its provider label is recorded as `custom:<label>` so a receipt
can never be mistaken for a provider table. `allowlist_digest` is BLAKE3 over
canonical `{"hosts":[...sorted],"ports":[...sorted]}`. `decide` is an exact
host match then an exact port-set match (`host-not-allowlisted`,
`port-not-allowed`).

## Proxy contract (`proxy.rs`, `request.rs`, `tunnel.rs`)

- Accepts only `CONNECT host:port HTTP/1.1|1.0`; any other method answers
  `405` with `Allow: CONNECT` (logged `malformed` / `method-not-allowed:<M>`).
- Head bounds: request line ≤ 4096 bytes, head ≤ 16 KiB, ≤ 64 header lines
  (`431`, logged `oversized:<what>`); NUL/non-ASCII/control bytes, bad shape,
  bad version, or EOF before the head are `400` (`malformed:<what>`); a client
  that sends nothing within `header_timeout` is `400` (`io:<kind>`).
- Target validation (`parse_connect_target` / `normalize_host`) happens
  **before any name resolution**: refuses empty, oversized, non-ASCII,
  whitespace/control, userinfo (`@`), path/query/fragment, IPv6 literal
  (`[`/`]`), percent-encoding, multiple colons, missing/empty/non-digit/
  leading-zero/zero/out-of-range port, leading or trailing dot, empty or >63
  byte labels, non-LDH characters, hyphen-edged labels, and an all-digit last
  label (IPv4 literal). Every refusal is `403` logged `deny` /
  `target:<reason>`; hosts are lower-cased before the allowlist decision.
- Allowlist denial is `403` logged `deny` / `<reason>`.
- Disarmed: admitted target answers `503` with
  `X-Bullet-Egress: allowlist-accepted; upstream-disarmed`, logged `allow` /
  `disarmed`.
- Armed: `ProxyLimits` (defaults: `max_tunnels = 32`, `header_timeout = 10 s`,
  `connect_timeout = 10 s`, `idle_timeout = 300 s`). Over the tunnel limit is
  `503` logged `limit` / `tunnel-limit`. Upstream resolution and dial happen
  only now, strictly after the allow decision; failure is `502` logged
  `allow` / `upstream-resolve:…` or `upstream-connect:…`. Success is
  `200 Connection established`, logged `allow` / `tunnel`, then a byte relay
  that closes on EOF or idle timeout.
- Dropping the `Proxy` stops the acceptor; open tunnels finish on EOF or idle.

## The eight probes and their expected outcomes

Refusal probes pass only when **both** the curl exit code is 7 (refused) or
28 (timed out) **and** the named counter incremented; the containment verdict
recorded is `Refused` (exit 7), `Unreachable` (exit 28), `Reached` (exit 0),
or `Unknown` (killed at deadline, or a failure not attributable to the
ruleset). Proxy-decision probes pass only when the observed HTTP code and the
most recent logged decision for that target both match.

| # | Name | Command inside the namespace | Expected |
| --- | --- | --- | --- |
| 1 | `direct-internet` | `curl -m 3 https://1.1.1.1/` | exit 7/28, `other_rejected` +≥1 |
| 2 | `host-jeryu` | `curl -m 3 http://10.0.2.2:8787/` | exit 7/28, `other_rejected` +≥1 |
| 3 | `host-decoy` | `curl -m 3 http://10.0.2.2:<decoy>/` | exit 7/28, `other_rejected` +≥1 |
| 4 | `dns-blocked-tcp` | `curl -m 3 http://10.0.2.3:53/` | exit 7/28, `dns_rejected` +≥1 |
| 5 | `dns-blocked-udp` | `curl -m 1 tftp://10.0.2.3:53/probe` | exit 7/28, `dns_rejected` +≥1 |
| 6 | `proxy-reachable` | `curl -w %{http_code} http://10.0.2.2:<proxy>/` | `405`; log `""` `malformed` `method-not-allowed:GET` |
| 7 | `proxy-disallowed` | `curl -p -x <proxy> -w %{http_connect} https://example.com/` | `403`; log `example.com:443` `deny` `host-not-allowlisted` |
| 8 | `proxy-allowed-path` | `curl -p -x <proxy> -w %{http_connect} https://<first allowlisted host>:<first port>/` | `503`; log `<host>:<port>` `allow` `disarmed` |

Probes 1–5 carry a containment verdict and are the only ones exported to
admission; 6–8 have `containment: None`.

## Receipt and evidence (`receipt.rs`)

`EgressReceipt` (`schema_version = "bullet.egress-receipt.v1"`): `provider`,
`allowlist_mode`, `namespace_backend = "unshare"`, `gateway`, `proxy_port`,
sorted `allowlist` and `allowed_ports`, `allowlist_digest`, `ruleset_text`,
`ruleset_digest` (BLAKE3 of the text), `ruleset_listing` (the kernel's own
view after installation), `probes` in execution order (each
`{name, outcome: pass|fail, containment, expected, observed}`), `started_at`,
`tools`, and `receipt_digest` = BLAKE3 over the canonical (sorted-key,
compact) JSON of every other field. `verify()` rechecks schema, receipt
digest, ruleset digest, and that probes are non-empty and all passed
(`EGRESS_ISOLATION_UNPROVEN` otherwise); a failed probe cannot verify even if
resealed.

`EgressEvidence` is exactly the four fields admission consumes:
`receipt_digest`, `ruleset_digest`, `allowlist_digest`, and the containment
`probes` as `{name, outcome}` with outcome serialized as the bare variant
(`Refused`, `Unreachable`, `Reached`, `Unknown`).

## How admission consumes it

`apps/bullet/src/provider.rs` (`RealEgressBackend`) maps `EgressEvidence` to
`bullet_harness_core::EgressIsolationEvidence`, and
`EvaluatedAdmission::admit_egress` (`crates/harness-core/src/admission/signed.rs`)
clears exactly `EGRESS_ISOLATION_UNAVAILABLE` when: all three digests are 64
lowercase hex; there are 1..=32 probes with unique lowercase-label names
including every entry of `REQUIRED_EGRESS_PROBES = ["direct-internet",
"host-jeryu"]`; and **every** probe's outcome is `Refused` or `Unreachable`
(`Reached` or `Unknown` refuse with `ADMISSION_REFUSED`). The receipt is
re-verified first and a second `admit_egress` is refused. The three digests
are then carried into the `LiveConformanceReceipt`
(`egress_receipt_digest`, `egress_ruleset_digest`, `egress_allowlist_digest`).

## Child commands (`PreparedSandbox::command`)

Every command enters the namespace via `nsenter` in the holder's process
group with `env_clear()` plus exactly the caller's `env` and `HTTPS_PROXY`,
`HTTP_PROXY`, `https_proxy`, `http_proxy` = `http://10.0.2.2:<proxy_port>`,
and `NO_PROXY` / `no_proxy` = empty. A bare program name is resolved against
the caller's `PATH` (or this process's) before entering.

## Teardown guarantees (`namespace.rs`, `sandbox.rs`)

Dropping `PreparedSandbox` (or `Namespace`) closes the holder and slirp stdin
pipes (EOF), sends `TERM` to the whole process group, waits up to 2 s for the
holder and uplink to exit, then sends `KILL` to the group and reaps both
children; the proxy acceptor is shut down; the decision log and receipt are
fsync'd. The lane test `teardown_kills_holder_uplink_proxy_and_group_children`
asserts that the holder, `slirp4netns`, and a `sleep 300` group child are gone,
the proxy port no longer accepts, and the on-disk receipt still verifies.

## Boundary and non-claims

- **Linux only.** The crate is `cfg(unix)` in practice and requires the seven
  tools and unprivileged user namespaces. There is no other platform backend;
  every other packaged platform must fail closed until one passes.
- **Same UID.** The namespace is unprivileged and root-mapped to the calling
  user. A process running as the same UID outside the namespace is not
  constrained by it; this is provider containment, not host hardening.
- **No provider identity.** A passing receipt proves the boundary shape and
  the eight refusals/decisions on this host at `started_at`; it says nothing
  about which provider account, model, or credential later runs inside it.
- **No DNS policy beyond refusal.** UDP/TCP 53 are rejected and counted;
  names are resolved only by the host proxy, only after an allow decision, and
  the proxy applies no resolver policy of its own.
- **No transport inspection.** The proxy tunnels bytes after `CONNECT`; it
  does not terminate TLS or inspect the payload.
- **Not authority.** An egress receipt clears one blocker in one local
  admission; it cannot authorize dispatch alone and is never `LIVE_PROOF`.

## Proof

```bash
just egress            # = bash scripts/ci-local.sh egress = bash ops/ci/egress.sh
```

`ops/ci/egress.sh` exits 78 (neutral) when any of
`unshare nsenter slirp4netns nft curl cat kill` is missing or
`unshare --user --map-root-user --net true` fails; otherwise it runs
`cargo nextest run --locked --workspace --features
bullet-verifier/fixture-executor --run-ignored all --no-tests fail -E
"$EGRESS_FILTER"`, where the inventory binds the filter to exactly the three
host-dependent proofs (`claude_strict_sandbox_proves_every_probe_and_blocks_real_commands`,
`custom_policy_tunnels_only_to_the_allowlisted_host_and_port`,
`teardown_kills_holder_uplink_proxy_and_group_children`). The first asserts
exactly the eight probe names above, all passing, seven tool records, five
containment probes in the evidence, and that a real `curl` from inside the
sandbox reaches neither `1.1.1.1` nor `10.0.2.2:8787` directly. It is
`COMPONENT_PROOF` for this host only. Unit tests for allowlist, request
parsing, proxy decisions, ruleset text/listing/counters, and receipt sealing
run in the plain workspace lanes without namespaces.
