# bullet-kernel

Control-plane modular monolith for Bullet Farm. Agents start at [`AGENTS.md`](AGENTS.md).
Product-surface claims were last reviewed 2026-08-25 against `c797d51`; the CI
lane and test-inventory section was reviewed against product subject `107c5cd`.
<!-- bullet-doc-review:v1 subject=c797d51d75f80eb167f6ac5eb094755aca577688 max_distance=25 paths=apps/bullet/src/main.rs,apps/bullet-farmd/src/main.rs,crates/runner/src/lib.rs,crates/verifier/src/lib.rs -->
Evidence classes follow
`bullet-farm/docs/release.md`; nothing in this repository is `LIVE_PROOF` or
`RELEASE_PROOF`, and every receipt named here is a component receipt.

## Layout

| Path | Role |
| --- | --- |
| `crates/domain` | IDs, tokens, state machines, taxonomy; no I/O |
| `crates/application` | commands, materializer, leases/fences, pure simulators, `bullet demo`; policy loader (`policy_snapshot`, v1alpha1 + v1alpha2), launch-grant issuer and durable nonce store (`launch_grant`), signed lease-transport service (`lease_transport`), live-conformance orchestration (`live_conformance`) |
| `crates/adapters` | SQLite WAL ledger, checksummed migrations, and offline receipt-bound backup/quarantined restore |
| `crates/adapters-postgres` | configuration scaffold; implements no `Ledger` and never connects in required CI |
| `crates/harness-core`, `crates/harness-sim` | adapter trait, provider admission with two evidence-cleared blockers (`admission/`), PASETO v4.public launch-grant verifier (`launch_grant/`), lease-transport permit contract (`lease_transport.rs`), live-turn dispatch ports (`live/`), checkpoint-bound `PatchProposal` (`proposal.rs`), event envelope, argv/supervision gate, deterministic simulator |
| `crates/harness-egress` | Linux user+net namespace, `slirp4netns` uplink, in-namespace nftables default-drop, host CONNECT proxy, sealed `EgressReceipt`; see [`docs/egress-isolation.md`](docs/egress-isolation.md) |
| `crates/harness-{claude,codex,cursor,antigravity}` | fail-closed provider contract crates with bounded offline transcript/result subsets and one `LiveDispatcher` each |
| `crates/runner` | component-testable attempt loop; the product CLI refuses before dispatch because no workload lease transport is admitted (see [`docs/architecture.md`](docs/architecture.md#runner--farmd-lease-admission-refusal)) |
| `crates/verifier` | clean-room reconstruction and typed gate outcomes |
| `crates/effects` | effect broker and state machine over `LocalBareForge`; the Jeryu adapter is a typed quarantine |
| `crates/router`, `fusion`, `behavior`, `projections` | non-authoritative scaffolds: routing fallback, fusion, behaviour catalog, spec §25 `View`/`Surface` types; the served §25 projections live in `apps/bullet-farmd/src/projections/` |
| `crates/mcp-mock`, `crates/test-simulation` | in-process mocks and harness tapes for the contract lane |
| `apps/bullet-farmd` | loopback-only HTTP + SSE daemon; routes in the table below |
| `apps/bullet-mcpd` | official-SDK stdio MCP adapter for fixed read-only farmd projections; no command or authority surface; see [`docs/mcp.md`](docs/mcp.md) |
| `apps/bullet` | CLI: `farm init\|backup\|restore`, `demo`, `demo-synthetic`, `contracts generate\|check`, `authority keygen\|mint-launch-grant`, `provider live-conformance`; every flag is in [`docs/cli.md`](docs/cli.md) |
| `apps/bullet-runner` | fail-closed attempt runner; returns `LEASE_TRANSPORT_ADMISSION_UNAVAILABLE` before farmd, filesystem, provider, or gitd activity |
| `apps/bullet-verifier` | verifier process boundary; refuses the writer identity, reads its job as `--stdin` JSON |
| `apps/bullet-effects` | effect broker process boundary; drives `LocalBareForge` through loss and reconciliation |

## farmd routes

Source of truth: `build_router` in `apps/bullet-farmd/src/api.rs`. Every route
below is mounted there and every mounted route is below; anything else answers
the router fallback `NOT_FOUND`. `contracts/openapi.yaml` documents all of them
except the internal reconciler, and `bullet contracts check` gates the
generated client against that YAML.

| Method | Path | In `openapi.yaml` | Meaning |
| --- | --- | --- | --- |
| GET | `/health` | yes | liveness `{"status":"ok"}` |
| GET | `/openapi.yaml` | yes | the embedded contract bytes |
| GET | `/api/v1/missions` | yes | mission list snapshot |
| GET | `/api/v1/missions/{id}` | yes | one mission; `X-Bullet-As-Of-Sequence` watermark |
| GET | `/api/v1/demo` | yes | demo receipt re-derived from ledger rows |
| POST | `/api/v1/demo/run` | yes | `410 MUTATION_ENDPOINT_REMOVED`; submit a `run_demo` command instead |
| POST | `/api/v1/auth/bootstrap` | yes | one-time local-browser session bootstrap (600 s token, 8 h session, CSRF header) |
| POST | `/api/v1/commands` | yes | authenticated command submission; records `PENDING` |
| GET | `/api/v1/commands/{id}` | yes | command status |
| POST | `/internal/v1/commands/{id}/reconcile` | no | worker-bearer reconciler; inert without `--worker-token-file`; settles `UNKNOWN` or `FAILED` only |
| GET | `/api/v1/outbox` | yes | outbox snapshot |
| GET | `/api/v1/events` | yes | SSE ledger events with bounded replay (64 per batch, 1024 max) |
| GET | `/api/v1/ready` | yes | next ready work package; `X-Bullet-As-Of-Sequence` watermark |
| GET | `/api/v1/fleet` | yes | §25 projection; one atomic ledger snapshot |
| GET | `/api/v1/sessions` | yes | §25 projection; one atomic ledger snapshot |
| GET | `/api/v1/merge-rail` | yes | §25 projection; one atomic ledger snapshot |
| GET | `/api/v1/quality-lab` | yes | §25 projection; one atomic ledger snapshot |
| GET | `/api/v1/audit` | yes | §25 projection; one atomic ledger snapshot |

No `/api/v1/leases/*` or `/api/v1/attempts/advance` route is mounted. Runner mutation
RPC stays off the browser API until a signed lease transport is exposed; the
committed `SignedLeaseService` is in-process only.

## Quick start

```bash
just setup
just fast
BULLET_DATA_DIR=./target/demo cargo run -p bullet --bin bullet -- demo
```

The demo receipt is re-derived from ledger rows on every run and proves the
permanent fence advanced (fence 1, then fence 2 on the same variant), that a
stale heartbeat and stale token are refused, and that a lost SCM response is
recorded as an unknown outcome rather than a success.

The portal is a projection of this API. It is never an authority source.

## Offline maintenance

```bash
cargo run -p bullet --bin bullet -- farm backup \
  --database ./target/demo/ledger.sqlite \
  --output ./backup.sqlite \
  --receipt ./backup.receipt.json
cargo run -p bullet --bin bullet -- farm restore \
  --backup ./backup.sqlite \
  --receipt ./backup.receipt.json \
  --destination ./restored.sqlite
```

Backup uses SQLite's online backup API and checks the exact schema, foreign
keys, and SQLite integrity before publishing an absent output; the thin CLI then
creates its separate no-clobber receipt. The receipt binds physical bytes and
integrity with BLAKE3; it is not signed and does not prove authenticity. A
receipt-write failure can leave an unusable orphan snapshot. Restore verifies
those exact bytes, advances the restore epoch, and publishes only to an absent
destination. The result remains quarantined: normal Kernel open refuses it
because no production authority admission operation exists. A directory-sync
failure after publication is an unknown outcome with a complete destination
possibly present. These are offline operator commands, not a live backup service
or an authority recovery procedure.

## Lanes

Every lane is one script under `ops/ci/`, reachable as `just <lane>` or
`bash scripts/ci-local.sh <lane>`.

The exact 569-test inventory is disjoint: 523 standalone, three host-dependent
egress, 34 contract, and nine family identities.

| Lane | Command | Contents | Evidence class |
| --- | --- | --- | --- |
| fast | `just fast` | digest-bound 523-test standalone partition with all 523 executed and zero skipped; a checked nonexistent daemon sentinel prevents sibling fallback | `COMPONENT_PROOF` |
| lint | `just lint` | fmt, Clippy, actionlint 1.7.8, ShellCheck 0.10.0, and inventory/workflow/observation/nightly meta-tests | hygiene gate; no evidence class |
| contract | `just contract` | exactly 34 offline provider-protocol and simulation tests, executed once; no sibling daemon | `COMPONENT_PROOF` / `SYNTHETIC_PROOF` |
| security | `just security` | gitleaks (no-git); `cargo deny fetch db` plus a lane-side freshness proof of the RustSec advisory database (refuses at 14 days); `cargo deny --locked check licenses advisories bans sources` against the committed `deny.toml`; `zizmor .`; a missing tool, a missing `deny.toml`, or an absent/stale advisory database fails | hygiene gate; no evidence class |
| docs | `just docs` | generated-contract drift, workspace rustdoc, and repository-relative Markdown links | hygiene gate; no evidence class |
| required | `just check` | fast, lint, contract, security, and docs sequentially, exactly once | unsigned component observation only |
| family | `BULLET_GITD_BIN=/canonical/absolute/bullet-gitd BULLET_GITD_SHA256=<lowercase-sha256> just family` | exactly nine connected family tests: five transaction-demo identities, three runner identities, and `synthetic_e2e`; missing, relative, non-canonical, non-executable, or digest-mismatched daemon subjects fail | family observation only; not registered until immutable family provisioning exists |
| audit | `just audit` | Jankurai audit against the committed ratchet floor (`AUDIT_FLOOR=57`, may only rise); artifacts under `.jankurai/`; a missing auditor fails | hygiene gate; no evidence class |
| egress | `just egress` | exactly three host-dependent live proofs, kept outside standalone by the inventory ratchet, cover namespace, uplink, nftables, CONNECT proxy, receipt, and teardown; exits 78 (neutral) when any of `unshare nsenter slirp4netns nft curl cat kill` or unprivileged user namespaces is missing; never green unless all three capability-admitted probes run | `COMPONENT_PROOF` on a Linux host |
| nightly | `just nightly` | per selected provider: exact live-feature refusal test plus positive live-conformance half. All PONG is 0; any policy refusal without a hard failure is neutral 78; any test, execution, or spawn failure is 1. Default mode uses marker executables and the checked-in policy, never a real provider | default: `COMPONENT_PROOF` of refusal without spawn; not `LIVE_PROOF` |
| toolchain-msrv | `just toolchain-msrv` | release-schema observation under Rust 1.95.0; separate from standalone required CI and still family-bound while its frozen receipt argv tests all targets | `COMPONENT_PROOF`; unsigned input to a future release receipt only |

`.github/workflows/ci.yml` scans source and lockfiles before dependency work,
then runs the five atomic lanes in parallel and converges on exact context
`CI / required`. Scheduled diagnostics cover external links, advisories,
coverage, full-history secrets, and macOS/Windows compile plus typed refusal.
All hosted observations are unsigned `DIAGNOSTIC_ONLY`, not Evidence or release
receipts. See [CI and test inventory](docs/testing.md).

## Readiness

| Surface | Current meaning |
| --- | --- |
| Component tests | Lease, ledger, harness, runner, verifier, effects, and protocol primitives |
| `bullet demo` | Deterministic ledger simulation only |
| `bullet demo-synthetic` | Offline non-gating scaffold; while production authority is unavailable, it exits failed with a typed refusal and no Candidate |
| `bullet farm backup\|restore` | Offline integrity/subject maintenance; restored truth remains quarantined |
| Internal command worker | Authenticated invoked reconciliation; demo work settles only `UNKNOWN`, unsupported kinds only `FAILED` |
| Provider contracts | Four bounded offline transcript/result subsets plus one common policy-gated live-conformance path; under the checked-in v1alpha1 policy every provider refuses (exit 78) before any spawn; no provider has a live receipt |
| Policy loader | v1alpha1 and v1alpha2 (ADR 0012 mirror); live admission is legal only at generation ≥ 2 with an active `provider-runner` key; the committed fixture is v1alpha1, generation 1, live disabled |
| Launch-grant authority | Offline operator keygen and mint from the durable lease; the verifier binds lease, admission, policy, and a single-use nonce; a constant authority epoch and zero freeze generation until durable counters exist |
| Egress isolation | Linux-only namespace/nftables/CONNECT-proxy boundary with a sealed receipt; `just egress` on a capable host, else neutral 78 |
| farmd projections | Five read-only §25 routes, each one atomic ledger snapshot with a sequence watermark; consumed by the Portal; never authority |
| Runner ↔ farmd leases | Refused: product CLI does not construct the dormant unsigned `HttpLeaseClient`; the experimental UDS transport lacks `SO_PEERCRED` identity binding and is not admitted |
| Exact five-plane transaction | Not implemented or proven |
| Production | Not eligible; operator-ratified live policy, signed lease transport, durable authority epoch and budgets, online BulletGit authority, freeze, and restore admission are incomplete |

The product scaffold never selects Runner's private `#[cfg(test)]` workspace
simulator. That simulator covers repair-loop mechanics only and cannot produce
transaction, live, or release evidence. Until signed BulletGit authority is
available, the product receipt must preserve `AUTHORITY_CONTRACT_UNAVAILABLE`
and show no Candidate, Evidence, or effect.

The harness has one non-spawning `ProviderAdmission` evaluator. It requires an
absolute canonical executable and exact complete descriptor/version/capability/
profile/protocol probe; stages only digest-bound, individually allowlisted OAuth
files in a unique 0700 HOME as 0400 files; builds the child environment from a
positive allowlist; and checks canaries across environment, stdout, stderr,
events, and the accepted gate-ID-only proposal. Its deterministic receipt binds
those facts but is not authority. Every fresh receipt carries
`SIGNED_ADMISSION_UNAVAILABLE` and `EGRESS_ISOLATION_UNAVAILABLE`; only
`admit_signed` (a `VerifiedLaunchGrant` whose provider facts equal the receipt)
and `admit_egress` (egress evidence whose every probe observed refusal or
unreachability, including `direct-internet` and `host-jeryu`) clear them, and
`build_with_admission` calls `require_dispatch`, which refuses while any
blocker remains. A deserialized receipt never dispatches (`UNSIGNED_RECEIPT`).
Codex App Server JSONL, Cursor ACP, Antigravity structured headless with
1.1.19's flags-before-prompt-last-`-p=` ordering, and Claude stream JSON are the
frozen protocol requirements; runtime probes, not provider names, determine
conformance. No provider has an admitted live runtime: the checked-in v1alpha1
policy makes `verify_launch_grant` refuse with `POLICY_LIVE_ADMISSION_DISABLED`
before any spawn.

The four committed provider machines accept only bounded offline protocol
subsets: Claude stream messages, Codex App Server JSONL, Cursor ACP, and
Antigravity's one-shot structured result. Exact structured terminal output may
become a locally validated, unverified `PatchProposal` (schema 1: content-
addressed `proposal_id`, `producing_attempt_id`, exact `base_checkpoint_id` and
digest, preimage-bound whole-file operations, admitted `gate_ids`); free text
cannot become a proposal, narrative fields are never serialized to the writer,
and no proposal is Evidence or `VERIFIED` truth. Their `--features live` tests
are non-ignored refusal contracts that prove public runtime methods do not spawn
or create artifacts. Fixed installed-version or schema observations are test
inputs, not live runtime conformance.

The ordinary harness argv gate also refuses every known live provider executable
by default (`LIVE_ADMISSION_UNAVAILABLE`). Its bounded supervision and process-
group cleanup are component-level mechanics, not a provider dispatch path or
network containment. The authenticated internal worker likewise has no admitted
runner, verifier, or effect adapter: it can durably reconcile only to `UNKNOWN`
or `FAILED`, never `APPLIED` or `VERIFIED`. There is no admitted live provider
dispatch, online BulletGit call, independent Evidence flow, or
runner-to-verifier-to-effect transaction. The Jeryu adapter performs no
credential lookup or network call. No component test or synthetic receipt
establishes Transaction-ready or production-ready status.
