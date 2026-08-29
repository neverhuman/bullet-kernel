# `bullet` CLI reference

Status: committed surface at HEAD `3fb9d8e`
Owner: Bullet Farm maintainers
Last reviewed: 2026-08-26
Source of truth: `apps/bullet/src/{main,transaction,authority,provider,maintenance,contracts}.rs`,
`apps/bullet/src/authority/mint.rs`, and the process-bin `main.rs` files below.
<!-- bullet-doc-review:v1 subject=3fb9d8e450f59bf3e35531320381050357116cf2 max_distance=25 paths=apps/bullet/src/main.rs,apps/bullet/src/transaction.rs,apps/bullet/src/authority.rs,apps/bullet/src/provider.rs,apps/bullet/src/maintenance.rs,apps/bullet/src/contracts.rs,apps/bullet-farmd/src/main.rs,apps/bullet-runner/src/main.rs,apps/bullet-effects/src/main.rs -->

Every command is offline except the guarded `provider live-conformance` path.
Every current production adapter refuses at runtime observation before it can
read the operator key, mutate graph/lease/nonce authority, prepare egress, or
spawn a provider. Nothing here produces `LIVE_PROOF` or `RELEASE_PROOF`.

## Environment

| Variable | Used by | Meaning |
| --- | --- | --- |
| `BULLET_DATA_DIR` | `farm init`, `demo`, `demo-synthetic` | data directory; default `./target/demo` |
| `BULLET_POLICY_PATH` | `authority mint-launch-grant`, `provider live-conformance` | absolute path overriding `<data-dir>/policy/policy.json` |
| `BULLET_PROVIDER_KILL=1` | every provider argv build | kill switch; refuses every spawn (`PROVIDER_KILL_ACTIVE`) |

## Commands

| Command | Effect |
| --- | --- |
| `farm init` | on Linux, admit/create a self-owned non-symlink 0700 `<data-dir>`, create `ledger.sqlite`, and run migrations; other platforms refuse |
| `farm backup --database <existing> --output <absent> --receipt <absent>` | SQLite online-backup snapshot with schema/foreign-key/integrity checks, then a separate unsigned BLAKE3 receipt; a receipt failure can leave an unusable orphan snapshot |
| `farm reap --database <existing>` | reclaim every writer lease already expired in the offline database; running farmd performs the same maintenance on its own tick |
| `farm restore --backup <snapshot> --receipt <receipt> --destination <absent>` | verify the exact receipt-bound bytes, advance the restore epoch, publish to an absent destination; the result stays quarantined (normal open refuses) |
| `demo` | deterministic ledger simulation; writes `<data-dir>/receipts.json`; fails on its own safety checks and unless Candidate/Evidence/Effect all remain unproduced |
| `demo-synthetic [--target <origin repo>]` | simulator-only integration scaffold; while production authority is unavailable it exits failed with a typed refusal and no Candidate |
| `transaction --json` | emit the typed `transaction_proof: "ABSENT"`, `transaction_gate_eligible: false` receipt and exit 2; omitting `--json` also refuses |
| `contracts generate` | regenerate `contracts/generated/api.ts` from `contracts/openapi.yaml` |
| `contracts check` | fail when the generated TypeScript is stale (gates the fast lane) |
| `authority keygen` | create the operator launch-grant signing key; see below |
| `authority mint-launch-grant` | mint one signed launch grant from the durable active lease; see below |
| `provider live-conformance` | run the guarded 13-step live path for one provider; see below |

## `authority keygen`

| Flag | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--data-dir <abs>` | yes | — | absolute Kernel data directory |
| `--issuer <label>` | no | `bullet-kernel` | issuer label recorded in policy and every grant |
| `--key-id <label>` | no | `launch-grant-alpha` | key label recorded in policy and every grant |

Creates `<data-dir>/authority/launch-grant.key` (directory 0700, file 0600,
64 raw PASETO v4.public secret bytes, `create_new`, never overwritten) and
prints `key_file`, `public_key_hex`, and an `issuer_key_v1` JSON object
(`key_purpose: authority-signing`, `algorithm: paseto-v4.public`,
`audiences: ["provider-runner"]`, active now, expiring in 365 days, retained
24 h beyond expiry) for the operator to ratify into a new policy generation.
Stderr reminds that a v1alpha1 policy keeps live admission disabled regardless.
Errors carry `LAUNCH_GRANT_INVALID` (relative path, existing key, custody
violation). Unix only.

## `authority mint-launch-grant`

Lease facts are read from the ledger, never from the operator. No process is
spawned. Stdout is the `SignedLaunchGrant` JSON (`schema_version`, `issuer`,
`key_id`, `paseto`); diagnostics go to stderr.

| Flag | Required | Default | Constraint |
| --- | --- | --- | --- |
| `--data-dir <abs>` | yes | — | holds `ledger.sqlite`, `authority/launch-grant.key`, `policy/policy.json` |
| `--attempt <id>` | yes | — | `atm_` + 64 hex; must hold the durable active lease |
| `--receipt <abs>` | yes | — | `ProviderConformanceReceipt` JSON; regular file, no symlink, ≤ 64 KiB, digest must verify |
| `--provider <name>` | yes | — | must equal the receipt provider |
| `--executable <abs>` | yes | — | must equal the receipt path; bytes are re-digested and must equal `executable_blake3` |
| `--profile <id>` | yes | — | `prf_` + 64 hex; must equal the receipt profile |
| `--model <label>` | yes | — | bounded printable identifier |
| `--adapter <label>` | no | `<provider>-adapter` | bounded printable identifier |
| `--credential-generation <u64>` | no | `1` | ≤ 2^53−1 |
| `--sandbox-manifest-digest <hex64>` | yes | — | digest of the sandbox manifest the child runs under (`EgressPolicy::allowlist_digest` for the real backend) |
| `--environment-digest <hex64>` | yes | — | `environment_digest` of the admission's staged child environment |
| `--budget-invocations <u64>` | yes | — | ≥ 1 |
| `--budget-wall-ms <u64>` | yes | — | ≥ 1 |
| `--budget-cost-micro-usd <u64>` | yes | — | — |
| `--gate-id <id>` | yes, repeatable | — | `gat_` + 64 hex; 1..=16 unique values |
| `--ttl-ms <u64>` | no | `15000` | clamped to the lease remainder and to 15 000 |
| `--issuer <label>` | no | `bullet-kernel` | operator key issuer label |
| `--key-id <label>` | no | `launch-grant-alpha` | operator key label |

Check order and stable error prefixes:

1. `--data-dir`, `--receipt`, `--executable` absolute.
2. Policy load (`BULLET_POLICY_PATH` or `<data-dir>/policy/policy.json`):
   `POLICY_UNAVAILABLE` (missing, relative, symlink, non-regular) or
   `POLICY_INVALID` (oversize, non-canonical, `UNSUPPORTED_POLICY_SCHEMA`,
   `INVALID_POLICY_WINDOW`, key lifecycle codes, `UNSAFE_POLICY`,
   `LIVE_ADMISSION_REQUIRES_GENERATION`, `LIVE_ADMISSION_REQUIRES_RUNNER_KEY`).
   Accepted `schema_version` values are `v1alpha1` and `v1alpha2` (ADR 0012).
3. Operator key custody: 0600, self-owned, regular, exactly 64 bytes
   (`LAUNCH_GRANT_INVALID`).
4. `authority_key_at(issuer, key_id, "provider-runner", now)`: policy window
   (`POLICY_NOT_ACTIVE`), registered active unrevoked
   `authority-signing`/`paseto-v4.public` key for that audience
   (`LAUNCH_GRANT_KEY_UNKNOWN`); the file's public half must equal the policy's.
5. Receipt load and `verify()`; `--provider`/`--executable`/`--profile` must
   equal the receipt; executable bytes must match (`ADMISSION_REFUSED`).
6. `--attempt` parse (`INVALID_ID`).
7. `LedgerLaunchGrantIssuer::mint`: durable active lease read inside the
   coherent lease check, nonce persisted, claims signed. Ledger or issuer
   refusals surface with their own reason codes.
8. Stdout: the grant. Stderr, when the policy keeps
   `sandbox_policy.live_admission_enabled = false`: a note that the grant will
   be refused as `POLICY_LIVE_ADMISSION_DISABLED` at admission. Under the
   checked-in v1alpha1 policy that is always the case.

Committed at `0d848f6`: immediately after the policy loads, stderr reports
`bullet: policy schema_version=<v1alpha1|v1alpha2> generation=<n>
live_admission_enabled=<bool> digest=<hex>` and `validate_at(now)` runs
(`POLICY_NOT_ACTIVE` outside the window; `LIVE_ADMISSION_REQUIRES_RUNNER_KEY`
when a v1alpha2 policy enables live admission without an active
`provider-runner` key at `now`). The committed policy fixture is v1alpha1,
generation 1, live admission disabled.

## `provider live-conformance`

| Flag | Required | Default | Constraint |
| --- | --- | --- | --- |
| `--data-dir <abs>` | yes | — | ledger, key, policy, receipts |
| `--provider <name>` | yes | — | one of `claude`, `codex`, `cursor`, `agy` |
| `--executable <abs>` | no | PATH lookup of `claude` / `codex` / `cursor-agent` / `agy` | canonicalized before use |
| `--max-cost-micro-usd <u64>` | no | `50000` | tightest cost cap |

Fixed inputs: wall timeout 180 s, grant TTL 15 000 ms, issuer `bullet-kernel`,
key `launch-grant-alpha`, profile email `operator@bullet.farm`, adapter
`<provider>-adapter`, model `<provider>-default`, credential generation 1,
seed `live-conformance-<provider>`, one random 64-hex canary. The real
`bullet-harness-egress` backend is always used; `agy` maps to the
`antigravity` allowlist.

Exit codes: `0` outcome `PONG`; `78` outcome `REFUSED` (neutral). The checked-in
v1alpha1 policy returns `POLICY_LIVE_ADMISSION_DISABLED` at `POLICY`. A valid,
active v1alpha2 policy reaches `RUNTIME_PROBE_UNAVAILABLE` at `ADMISSION` for
all four production adapters, before operator-key read, graph/Mission or lease/
nonce writes, egress preparation, or provider spawn. An invalid or inactive
v1alpha2 policy fails at `POLICY`; `1` also covers outcome
`FAILED` or a pre-run error (relative
`--data-dir`, unknown provider, executable not found, policy or ledger open
failure). Stdout first prints `policy: schema_version=… generation=…
live_admission_enabled=… digest=…`, and every run prints `receipt: <path>`;
receipts are sealed and fsync'd
to `<data-dir>/live/<provider>-<utc>.json` on every outcome. The 13 steps and
the receipt fields are listed in
[`architecture.md`](architecture.md#live-conformance-path).

The v1alpha1 receipt has `POLICY=REFUSED` and 12 `NOT_RUN` records. The valid
v1alpha2 product receipt has `POLICY=PASS`, `ADMISSION=REFUSED`, and all other
11 records—including `OPERATOR_KEY` and `LEASE`—`NOT_RUN`; the observation is
checked early but mapped to the existing `ADMISSION` slot. The CLI opens its
SQLite ledger before orchestration, but the refusal creates no Mission, graph,
lease, or nonce row.

## Daemons and process bins

| Binary | Flags | Notes |
| --- | --- | --- |
| `bullet-farmd` | `--data-dir` (default `./target/demo`), `--bind` (default `127.0.0.1:7420`; non-loopback refused), `--portal-origin <exact loopback origin>`, `--worker-token-file <protected file>`, `--reap-interval-ms <1..=500>`, `--lease-transport-socket <abs>` with durable `--lease-peer-registry` + `--lease-transport-key` (0700 parent, 0600 key); debug builds also expose `--fixture-lease-peer-registration <runner:epoch>` | routes in [`README.md`](../README.md#farmd-routes); the internal reconciler is inert without the worker token; the socket refuses without durable local registry/key (or the debug-only fixture) |
| `bullet-runner` | `--lease-socket`, `--farmd-uid`, `--socket-gid`, `--lease-recovery` admit `SignedLeaseRpcClient::new_admitted`; missing any input returns typed `LEASE_TRANSPORT_ADMISSION_UNAVAILABLE` | HTTP `/v1/leases/*` stays unmounted; `HttpLeaseClient` remains unreachable |
| `bullet-verifier` | arguments are ignored | always refuses before reading stdin with `VERIFICATION_INTENT_ADMISSION_UNAVAILABLE`; emits no evidence |
| `bullet-verifier-fixture` | non-default `fixture-executor` feature; `--stdin` fixture JSON | credential-free component-test executor; output is explicitly `COMPONENT_PROOF`, `UNSIGNED_FIXTURE`, and ineligible for independent Evidence |
| `bullet-effects` | no arguments, or `serve <durable-queue-dir>` | no arguments run a component `LocalBareForge` loss/reconciliation demo; `serve` processes at most one UNKNOWN job to `QUARANTINED` and reports `live_forge_success:false` |
