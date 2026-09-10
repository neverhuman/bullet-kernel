# `bullet` CLI reference

Status: current source components; not an installed or release-qualified operator workflow
Owner: Bullet Farm maintainers
Last reviewed: 2026-09-10
Source of truth: `apps/bullet/src/{main,auth,client,coding,tui,transaction,authority,provider,maintenance,contracts}.rs`,
their supporting modules, `apps/bullet/src/authority/mint.rs`, and the process-bin sources below.
<!-- bullet-doc-review:v1 subject=b9d39619dcbc9f19ef2017eff57a55d19b1bfea5 max_distance=25 paths=apps/bullet/src/main.rs,apps/bullet/src/auth.rs,apps/bullet/src/auth/input.rs,apps/bullet/src/auth/session.rs,apps/bullet/src/auth/store.rs,apps/bullet/src/client.rs,apps/bullet/src/client/coherence.rs,apps/bullet/src/coding.rs,apps/bullet/src/coding/journal.rs,apps/bullet/src/coding/discovery.rs,apps/bullet/src/tui.rs,apps/bullet/src/tui/model.rs,apps/bullet/src/tui/ui.rs,apps/bullet/src/transaction.rs,apps/bullet/src/authority.rs,apps/bullet/src/provider.rs,apps/bullet/src/maintenance.rs,apps/bullet/src/contracts.rs,apps/bullet-farmd/src/main.rs,apps/bullet-farmd/src/main/bootstrap.rs,apps/bullet-runner/src/main.rs,apps/bullet-effects/src/main.rs,crates/adapters/src/sqlite/backup/create.rs,crates/adapters/src/sqlite/backup/restore.rs,crates/adapters/src/sqlite/open.rs,apps/bullet-farmd/src/main/launch.rs,crates/runner/src/signed_lease_rpc/recovery.rs -->

`auth`, `coding` and `tui` consume the loopback daemon. The local ledger helpers
and guarded provider qualification paths remain separate. The operator controls
below have component proofs; they do not establish installed provider execution,
independent verification, integration or release acceptance. Operating HOLD
continues until its actual predecessor admission and operator checkpoint.

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
| `farm backup --database <existing> --output <absent> --receipt <absent>` | private recovered SQLite snapshot with authentic schema-22/23/24/25, foreign-key and integrity checks, then a separate unsigned BLAKE3 receipt; a receipt failure can leave an unusable orphan snapshot |
| `farm reap --database <existing>` | reclaim every writer lease already expired in the offline database; running farmd performs the same maintenance on its own tick |
| `farm restore --backup <snapshot> --receipt <receipt> --destination <absent>` | verify exact receipt-bound schema-22/23/24/25 bytes, preserve schema/authority, advance the restore epoch, publish to an absent destination and read back; the result stays quarantined (normal open refuses) |
| `demo` | deterministic ledger simulation; writes `<data-dir>/receipts.json`; fails on its own safety checks and unless Candidate/Evidence/Effect all remain unproduced |
| `demo-synthetic [--target <origin repo>]` | simulator-only integration scaffold; while production authority is unavailable it exits failed with a typed refusal and no Candidate |
| `transaction --json` | emit the typed `transaction_proof: "ABSENT"`, `transaction_gate_eligible: false` receipt and exit 2; omitting `--json` also refuses |
| `contracts generate` | regenerate TypeScript, Rust models and JSON Schema together from `contracts/openapi.yaml` |
| `contracts check` | fail when any generated TypeScript, Rust or JSON Schema output is stale |
| `authority keygen` | create the operator launch-grant signing key; see below |
| `authority mint-launch-grant` | mint one signed launch grant from the durable active lease; see below |
| `provider live-conformance` | run the guarded 13-step live path for one provider; see below |
| `mission materialize` / `mission status` | materialize one plan revision into the local ledger (same seed + input replays the same ids; same seed + different input refuses) / print the stored graph for one mission |
| `run show` / `run print-preimages` | verify and render one run receipt (recomputes the body digest; follows the embedded selection-receipt chain link) / emit BLAKE3 preimages for paths at an exact base commit; see below |
| `dogfood read-only` | one contained read-only dogfood compose under ADR 0015; not a release profile, not live-conformance; see below |
| `auth login` | exchange one-time bootstrap using hidden input, or `--stdin`; save private credentials for the selected loopback `--farmd` and exact allowed `--origin` |
| `auth status` | check the saved session against the daemon and show nonsecret operator/session IDs and expiry |
| `auth revoke` / `auth logout` | revoke the current server session; remove local credentials only after a matching acknowledgement |
| `auth forget` | remove only the local credential copy; does not revoke server authority or remove request journals |
| `tui` | read authenticated atomic operator snapshots, navigate missions/tasks/Attempts/Candidates/events/context, and detach with an exact reconnect subject |
| `coding submit` | journal the exact `run_coding` envelope before POST using saved credentials. Requires `--account`, `--provider` ∈ `claude\|codex\|cursor\|antigravity`, and `--model`; optional `--idempotency-key` reuses the original journal on exact retry. Secret-bearing argument flags are retired. |
| `coding list` | discover this operator's durable command IDs and current phases after journal loss; `--after` resumes the returned cursor and `--limit` bounds each page to 1–100 commands |
| `coding status <id>` | GET the same command subject using saved credentials; correlate kind and payload digest with its local journal when present |
| `coding board` | fleet, sessions and outbox from one authenticated `/api/v1/operator-snapshot`; separate public health and optional `--command` observations. Empty fleet is zero lease rows. `--json` emits the observed projection objects. |
| `coding watch` | poll the same board; `--interval-ms` must be ≥ 1 (`WATCH_INTERVAL_INVALID` otherwise). Not a coordinator fleet. |
| `coding harness-check` | report `BULLET_HARNESS_*` PRESENT/ABSENT without spawning a provider. Exit 2 when unbound (`COMMAND_CODING_HARNESS_UNBOUND`). |
| `coding stop` | typed `STOP_UNIMPLEMENTED` and exit 2; does not SIGKILL a provider |

## Operator client custody and recovery

Run `bullet auth login` and `bullet tui` through SSH on xbabe2. Browser access
uses an SSH forward to the packaged Portal once installation is qualified.
Current source functionality does not establish that installation. Authentication
defaults to `http://127.0.0.1:7420`; the selected Origin must equal the daemon's
allowed Origin. HTTP destinations must be explicit numeric loopback addresses.

The default private directory is `$XDG_STATE_HOME/bullet/operator`, falling back
to `$HOME/.local/state/bullet/operator`. `--state-dir` selects another absolute
private directory for auth, coding and TUI commands. Its owner-only credentials
are serialized with a file lock, validated through directory descriptors and
fsynced before acknowledgement. Do not obtain bootstrap credentials from logs or
pass them as command arguments. Existing, corrupt, linked or displaced files
produce explicit refusal instead of being overwritten.

Submission prints a nonsecret journaled command ID before sending. After response
loss, run `bullet coding status <id>` with the same state directory, or retry the
exact input and idempotency key. Preserve the journal when the outcome is unknown.
After local journal loss, `bullet coding list` discovers the current operator's
durable commands. Follow `next_after` with `--after`, using the same authenticated
state directory. Each page has its own atomic snapshot watermark; pages do not
form one cross-page snapshot. Historical commands without a recorded operator
owner are not adopted. Discovery performs GETs and does not resubmit work.

The journal contains the request and destination, not session credentials. A
different input or endpoint for an existing key is a conflict. Human output
separates the server phase from independently unchecked receipt verification;
terminal control sequences in untrusted data are escaped. Explicit JSON output
preserves its value while escaping unsafe terminal characters.

The TUI uses Ctrl+K for navigation, Tab for panes, arrows or j/k for selection,
Enter for details, Escape for back, `?` for help, and `r` for refresh. Ctrl+C
detaches and prints a reconnect command; it does not cancel work. Selection stays
bound to a subject across updates. Failed or regressing snapshots retain previous
data with STALE/UNKNOWN. `NO_COLOR` preserves text labels without color;
`--once`, redirected output and `TERM=dumb` use a plain snapshot. Current TUI
updates are polled GETs. Native controls, exact queue blockers and approval
mutations remain separate unfinished backend/UI obligations.

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

## `run`

`run show <receipt>` verifies before it renders: it recomputes the receipt's
body digest over the canonical body bytes for the receipt's schema, and for an
effect-chain receipt it decodes the embedded selection receipt and requires
`selection_binding.receipt_body_digest` to equal that receipt's own
`body_digest`. A flipped byte refuses with `RECEIPT_BODY_DIGEST_MISMATCH`; an
unknown `schema_version` refuses without printing any body field; every render
carries `eligibility 0/9 — NOT a release receipt`.

`run print-preimages --repo <abs> --base-sha <sha> <path>...` prints one JSON
line per path: `{"kind":"digest","digest":"<blake3 of git show base:path>"}`,
or `{"kind":"absent"}` when the path does not exist at that commit. Digests
match `b3sum --no-names` exactly.

## `dogfood read-only`

One contained read-only dogfood turn (ADR 0015). Clears no release gate; the
receipt is a purpose-separated operational observation with every eligibility
flag false, and the release registry refuses it as evidence.

| Flag | Required | Default | Constraint |
| --- | --- | --- | --- |
| `--provider <name>` | no | `claude` | one of `claude`, `codex`, `cursor`, `antigravity`; only `claude` has a wired dispatch — the rest refuse `DOGFOOD_PROVIDER_UNIMPLEMENTED` before any staging |
| `--data-dir <abs>` | yes | — | self-owned 0700 runtime directory |
| `--policy <abs>` | yes | — | 0600 v1alpha2 policy, `policy_generation >= 2`, `live_admission_enabled` **false** (`true` is refused twice) |
| `--binding <abs>` | yes | — | `DogfoodBindingV1` JSON: audience `dogfood-runner`, operation `read-only-propose` |
| `--enrollment <abs>` | yes | — | must equal `<data-dir>/policy/enrollments/<provider>.json`; executable path and BLAKE3 must match it |
| `--issuer <label>` / `--key-id <label>` | yes | — | fixture labels refused (`launch-grant-alpha` etc.) |
| `--executable <abs>` | yes | — | re-hashed at the argv chokepoint; drift from the enrollment refuses |
| `--credential source,target,blake3` | no | — | repeatable exact staged grants |
| `--workdir <abs>` | yes | — | owner-private 0700 snapshot of the subject; the live family root is denylisted |
| `--prompt <text>` | yes for a turn | — | absent is designed-neutral 78 |
| `--max-budget-usd <f64>` | no | enrollment max | the enrollment cap still wins |
| `--receipt <abs>` | yes | — | create-once 0600; overwrite refused |

Exit codes: `0` a receipt was written; `78` designed-neutral (missing input,
namespaces unavailable, containment unavailable); `1` typed refusal (live
admission enabled, binding/enrollment mismatch, fixture key, argv drift).

## `coding submit` / `list` / `status` / `board` / `watch` / `harness-check` / `stop`

Loopback farmd ingress for a durable `run_coding` command. This is not
`dogfood read-only` (that compose still bypasses farmd and is Claude-only).
It is not session steer, interrupt, or a coordinator fleet: Operating HOLD
and farmd T4a remain open, and `coding stop` is `STOP_UNIMPLEMENTED`.
`board` and `watch` read the existing farmd GET projections and print saturated
status colors **plus** textual labels (`HOLD`, `LIVE`, `EXPIRED`, `UNKNOWN`).
`NO_COLOR` or a non-TTY stdout disables ANSI. Reads other than `/health` need
the `bullet_session` cookie (`SESSION_REQUIRED` without it).

The worker executes `run_coding` by spawning `bullet-runner` with
operator-bound `BULLET_HARNESS_*` environment (workspace, lease socket,
signed-in executable or Claude dogfood paths, `HOME`). Missing binding is
`COMMAND_CODING_HARNESS_UNBOUND` and does not fall back to `SimAdapter` or
`transaction_offline`. A finished coding child retains a
`CODING_HARNESS_OBSERVATION` (`cost: UNPRICED`), not `COMPONENT_PROOF` and
not Evidence.

## Daemons and process bins

`bullet-farmd --provision-bootstrap-token <absolute-path>`
creates a bootstrap token in an absent file and exits. Its existing parent must
be owned by the current user with mode 0700; the created file has mode 0600.
Provisioning cannot be combined with startup flags. It refuses symlinks and
existing files and never prints the token.
Normal startup accepts that file with `--bootstrap-token-file <absolute-path>`;
it requires an owned, single-link, mode-0600 regular file below an admitted
private parent. Without this flag, new bootstrap exchanges are disabled while
existing durable sessions remain usable. Deliver the token privately to
`bullet auth login`; it is consumed once and is never recovered from logs.

| Binary | Flags | Notes |
| --- | --- | --- |
| `bullet-farmd` | `--data-dir` (default `./target/demo`), `--bind` (default `127.0.0.1:7420`; non-loopback refused), `--portal-origin <exact loopback origin>`, `--worker-token-file <protected file>`, `--reap-interval-ms <1..=500>`, `--lease-transport-socket <abs>` with durable `--lease-peer-registry` + `--lease-transport-key` (0700 parent, 0600 key); debug builds also expose `--fixture-lease-peer-registration <runner:epoch>` | routes in [`README.md`](../README.md#farmd-routes); the internal reconciler is inert without the worker token; the socket refuses without durable local registry/key (or the debug-only fixture) |
| `bullet-runner` | `--lease-socket`, `--farmd-uid`, `--socket-gid`, `--lease-recovery` admit `SignedLeaseRpcClient::new_admitted`; missing any lease input returns typed `LEASE_TRANSPORT_ADMISSION_UNAVAILABLE`; explicit Candidate request/key, workspace/preservation, source/base, identity, scope/gates and idempotency inputs are also required; `--provider` accepts `sim`, `claude`, `codex`, `cursor`, `agy`, and `antigravity`. `claude` still requires the `--dogfood-*` admission inputs and a positive `--dogfood-max-budget-usd`. `codex`/`cursor`/`agy`/`antigravity` require `--signed-in-executable` and `--model` and never construct `SimAdapter`. Incomplete admission is `PROVIDER_ADMISSION_INCOMPLETE` | HTTP `/v1/leases/*` stays unmounted; `HttpLeaseClient` remains unreachable |
| `bullet-verifier` | arguments are ignored | always refuses before reading stdin with `VERIFICATION_INTENT_ADMISSION_UNAVAILABLE`; emits no evidence |
| `bullet-verifier-fixture` | non-default `fixture-executor` feature; `--stdin` fixture JSON | credential-free component-test executor; output is explicitly `COMPONENT_PROOF`, `UNSIGNED_FIXTURE`, and ineligible for independent Evidence |
| `bullet-effects` | no arguments, or `serve <durable-queue-dir>` | no arguments run a component `LocalBareForge` loss/reconciliation demo; `serve` processes at most one UNKNOWN job to `QUARANTINED` and reports `live_forge_success:false` |
