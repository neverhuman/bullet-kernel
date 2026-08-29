# bullet-kernel

Control-plane modular monolith for Bullet Farm. Agents start at [`AGENTS.md`](AGENTS.md).
Product-surface claims and the CI inventory were last reviewed 2026-08-26
against product subject `3fb9d8e`.
<!-- bullet-doc-review:v1 subject=3fb9d8e450f59bf3e35531320381050357116cf2 max_distance=25 paths=apps/bullet/src/main.rs,apps/bullet-farmd/src/main.rs,apps/bullet-farmd/src/lease_transport_rpc.rs,crates/runner/src/lib.rs,crates/runner/src/signed_lease_rpc.rs,crates/verifier/src/lib.rs -->
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
| `crates/effects` | effect broker and state machine over `LocalBareForge`, plus a bounded durable `PENDING` → `OUTCOME_UNKNOWN` → `QUARANTINED` queue; the Jeryu adapter is a typed quarantine |
| `crates/router`, `fusion`, `behavior`, `projections` | non-authoritative scaffolds: routing fallback, fusion, behaviour catalog, spec §25 `View`/`Surface` types; the served §25 projections live in `apps/bullet-farmd/src/projections/` |
| `crates/mcp-mock`, `crates/test-simulation` | in-process mocks and harness tapes for the contract lane |
| `apps/bullet-farmd` | loopback-only HTTP + SSE daemon; routes in the table below |
| `apps/bullet-mcpd` | official-SDK stdio MCP adapter for fixed read-only farmd projections; no command or authority surface; see [`docs/mcp.md`](docs/mcp.md) |
| `apps/bullet` | CLI: `farm init\|backup\|reap\|restore`, `demo`, `demo-synthetic`, `transaction --json`, `contracts generate\|check`, `authority keygen\|mint-launch-grant`, `provider live-conformance`; every flag is in [`docs/cli.md`](docs/cli.md) |
| `apps/bullet-runner` | fail-closed attempt runner; returns `LEASE_TRANSPORT_ADMISSION_UNAVAILABLE` before farmd, filesystem, provider, or gitd activity |
| `apps/bullet-verifier` | product verifier boundary; always returns the typed `VERIFICATION_INTENT_ADMISSION_UNAVAILABLE` refusal without reading a job. The default-off `bullet-verifier-fixture` accepts unsigned fixture JSON only with `fixture-executor`; every fixture outcome is component-only, unsigned, non-independent, and transaction-gate-ineligible |
| `apps/bullet-effects` | no-argument component demo over `LocalBareForge`; `serve <durable-queue-dir>` processes one UNKNOWN job only to `QUARANTINED`, never fabricated forge success |

## farmd routes

Source of truth: the closed method-token catalogs in
`apps/bullet-farmd/src/api/routes.rs` and `api/portal.rs`. Each catalog token
generates both its Axum mount and the marked projection below; the docs lane
compares that projection and its explicit OpenAPI membership exactly. Anything
else answers the router fallback `NOT_FOUND`. `bullet contracts check` also
gates the generated client against the complete OpenAPI document.

<!-- bullet-farmd-route-table:v1:start -->
| Method | Path | In `openapi.yaml` | Meaning |
| --- | --- | --- | --- |
| GET | `/health` | yes | liveness `{"status":"ok"}` |
| GET | `/openapi.yaml` | yes | the embedded contract bytes |
| GET | `/api/v1/missions` | yes | mission list snapshot |
| GET | `/api/v1/missions/{id}` | yes | one mission with its sequence watermark |
| GET | `/api/v1/demo` | yes | demo receipt re-derived from ledger rows |
| POST | `/api/v1/demo/run` | yes | retired direct mutation; submit a `run_demo` command |
| POST | `/api/v1/auth/bootstrap` | yes | one-time local-browser session bootstrap |
| POST | `/api/v1/commands` | yes | authenticated command submission records `PENDING` |
| GET | `/api/v1/commands/{id}` | yes | command status |
| POST | `/internal/v1/commands/{id}/reconcile` | no | worker-bearer reconciler, outside the public contract |
| GET | `/api/v1/outbox` | yes | outbox snapshot |
| GET | `/api/v1/events` | yes | SSE ledger events with bounded replay |
| GET | `/api/v1/ready` | yes | next ready work package with its sequence watermark |
| GET | `/api/v1/fleet` | yes | fleet projection from one atomic ledger snapshot |
| GET | `/api/v1/sessions` | yes | sessions projection from one atomic ledger snapshot |
| GET | `/api/v1/context-lineage` | yes | context-lineage projection from one atomic ledger snapshot |
| GET | `/api/v1/merge-rail` | yes | merge-rail projection from one atomic ledger snapshot |
| GET | `/api/v1/quality-lab` | yes | quality-lab projection from one atomic ledger snapshot |
| GET | `/api/v1/audit` | yes | audit projection from one atomic ledger snapshot |
| ANY | `/v1` | no | retired operator API root; always `410 API_VERSION_RETIRED` |
| ANY | `/v1/{*path}` | no | retired operator API subtree; always `410 API_VERSION_RETIRED` |
| GET | `/` | no | embedded-portal entry point; absent without the feature |
| GET | `/index.html` | no | embedded-portal entry point alias; absent without the feature |
| GET | `/assets/{file}` | no | content-hashed embedded-portal asset; absent without the feature |
<!-- bullet-farmd-route-table:v1:end -->

No `/api/v1/leases/*` or `/api/v1/attempts/advance` route is mounted. Runner mutation
RPC stays off the browser API. A signed UDS transport exists only behind farmd's
debug-only fixture peer registration; the product `bullet-runner` still refuses
with `LEASE_TRANSPORT_ADMISSION_UNAVAILABLE` before farmd, workspace, provider,
or Gitd activity because no durable workload peer registry is admitted.

## Quick start

```bash
just fast
BULLET_DATA_DIR=./target/demo cargo run -p bullet --bin bullet -- demo
```

Run `just setup` only if this checkout has not yet been prepared (toolchain
and repo-side dependencies).

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

The exact 793-test inventory is disjoint: 747 standalone, three host-dependent
egress, 34 contract, and nine family identities.

| Lane | Command | Contents | Evidence class |
| --- | --- | --- | --- |
| fast | `just fast` | digest-bound 747-test standalone partition with all 747 executed and zero skipped, including explicitly feature-enabled verifier fixture tests; both Gitd binary variables are unset so product resolution fails closed | `COMPONENT_PROOF` |
| lint | `just lint` | fmt, Clippy, actionlint 1.7.8, ShellCheck 0.10.0, and inventory/workflow/observation/nightly meta-tests | hygiene gate; no evidence class |
| contract | `just contract` | exactly 34 offline provider-protocol and simulation tests, executed once; no sibling daemon | `COMPONENT_PROOF` / `SYNTHETIC_PROOF` |
| security | `just security` | gitleaks (no-git); `cargo deny fetch db` plus a lane-side freshness proof of the RustSec advisory database (refuses at 14 days); `cargo deny --locked check licenses advisories bans sources` against the committed `deny.toml`; `zizmor --offline --no-ignores --strict-collection .`; a missing tool, a missing `deny.toml`, or an absent/stale advisory database fails | hygiene gate; no evidence class |
| docs | `just docs` | generated-contract drift, workspace rustdoc, and repository-relative Markdown links | hygiene gate; no evidence class |
| required | `just check` | fast, lint, contract, security, and docs sequentially, exactly once | unsigned component observation only |
| family | `BULLET_GITD_BIN=/canonical/absolute/bullet-gitd BULLET_GITD_SHA256=<lowercase-sha256> just family` | exactly nine connected family tests: five transaction-demo identities, three runner identities, and `synthetic_e2e`; missing, relative, non-canonical, non-executable, or digest-mismatched daemon subjects fail | family observation only; not registered until immutable family provisioning exists |
| offline transaction component | `BULLET_GITD_BIN=/canonical/absolute/bullet-gitd BULLET_GITD_SHA256=<lowercase-sha256> just proof-transaction-offline` | builds locked Kernel subjects offline, runs durable scope and Candidate authority through product Runner/production Gitd, fixture verification, exact Candidate delivery/read-back, stale-fence refusal, and `OUTCOME_UNKNOWN` reconciliation, then retains strict JSON | unsigned `COMPONENT_PROOF`; fixture verifier; explicitly ineligible for transaction/release admission |
| audit | `just audit` | Jankurai audit against the committed ratchet floor (`AUDIT_FLOOR=57`, may only rise); artifacts under `.jankurai/`; a missing auditor fails | hygiene gate; no evidence class |
| egress | `just egress` | exactly three host-dependent live proofs, kept outside standalone by the inventory ratchet, cover namespace, uplink, nftables, CONNECT proxy, receipt, and teardown; exits 78 (neutral) when any of `unshare nsenter slirp4netns nft curl cat kill` or unprivileged user namespaces is missing; never green unless all three capability-admitted probes run | `COMPONENT_PROOF` on a Linux host |
| nightly | `just nightly` | per selected provider: exact live-feature refusal test plus guarded live-conformance half. All PONG is 0; any typed policy or runtime-observation refusal without a hard failure is neutral 78; any test, execution, or spawn failure is 1. Default mode uses marker executables and the checked-in policy, never a real provider | default: `COMPONENT_PROOF` of refusal without spawn; not `LIVE_PROOF` |
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
| Provider contracts | Four bounded offline transcript/result subsets plus one common policy-gated live-conformance path; the checked-in v1alpha1 policy refuses at `POLICY`, while a valid v1alpha2 policy reaches the production adapters' typed `RUNTIME_PROBE_UNAVAILABLE` refusal at `ADMISSION`; both exit 78 before any provider spawn, and no provider has a live receipt |
| Policy loader | v1alpha1 and v1alpha2 (ADR 0012 mirror); live admission is legal only at generation ≥ 2 with an active `provider-runner` key; the committed fixture is v1alpha1, generation 1, live disabled |
| Launch-grant authority | Offline operator keygen and mint from the durable lease; the verifier binds lease, admission, policy, a single-use nonce, and the ledger's durable authority epoch/freeze generation; no admitted online operation advances those revisions |
| Egress isolation | Linux-only namespace/nftables/CONNECT-proxy boundary with a sealed receipt; `just egress` on a capable host, else neutral 78 |
| farmd projections | Five read-only §25 routes, each one atomic ledger snapshot with a sequence watermark; consumed by the Portal; never authority |
| Runner ↔ farmd leases | Refused: product CLI constructs neither component client; the UDS predecessor binds both peers with `SO_PEERCRED` and socket identity, but registration is debug-fixture-only and acquire read-back metadata remains process-local |
| Exact five-plane transaction | A family-only component fixture exercises the roles; the product `bullet transaction --json` returns typed `ABSENT` with exit 2, and no `TRANSACTION_PROOF` exists |
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
conformance. No production adapter can yet produce the owned runtime and
conformance observation. Its default port returns `RUNTIME_PROBE_UNAVAILABLE`
immediately after a valid policy check and before operator-key read, Mission/
graph materialization, lease or nonce writes, egress, or spawn. The checked-in
v1alpha1 policy refuses even earlier with `POLICY_LIVE_ADMISSION_DISABLED`.
Only a strict `cfg(test)` application wrapper constructs positive observed
fixture data, so its PONG paths remain component mechanics, never live proof.

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
