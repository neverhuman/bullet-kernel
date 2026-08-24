# bullet-kernel

Control-plane modular monolith for Bullet Farm. Agents start at [`AGENTS.md`](AGENTS.md).

## Layout

| Path | Role |
| --- | --- |
| `crates/domain` | IDs, tokens, state machines, taxonomy; no I/O |
| `crates/application` | commands, materializer, leases/fences, pure simulators, `bullet demo` |
| `crates/adapters` | SQLite WAL ledger with `schema_version` migrations (`db/migrations`) |
| `crates/adapters-postgres` | configuration scaffold; implements no `Ledger` and never connects in required CI |
| `crates/harness-core`, `crates/harness-sim` | adapter trait, capability matrix, event envelope, argv gate, deterministic simulator |
| `crates/harness-{claude,codex,cursor,antigravity}` | provider adapters: offline parsers and argv guardrails, plus an opt-in live smoke test (see Lanes) |
| `crates/runner` | attempt loop, scope check, heartbeat self-fence, `bullet-gitd` supervision |
| `crates/verifier` | clean-room reconstruction and typed gate outcomes |
| `crates/effects` | effect broker and state machine over `LocalBareForge`; the Jeryu adapter is a typed quarantine |
| `crates/router`, `fusion`, `behavior`, `projections` | non-authoritative scaffolds: routing fallback, fusion, behaviour catalog, spec §25 surfaces |
| `crates/mcp-mock`, `crates/test-simulation` | in-process mocks and harness tapes for the contract lane |
| `apps/bullet-farmd` | HTTP + SSE daemon: `/health`, `/openapi.yaml`, `/v1/missions[/{id}]`, `/v1/demo[/run]`, `/v1/outbox`, `/v1/events`, `/v1/leases/{acquire,heartbeat,release}`, `/v1/attempts/advance`, `/v1/ready` |
| `apps/bullet` | CLI: `farm init`, `demo`, `demo-synthetic`, `contracts generate`, `contracts check` |
| `apps/bullet-runner` | attempt runner process; accepts only the `sim` provider |
| `apps/bullet-verifier` | verifier process boundary; refuses the writer identity, reads its job as `--stdin` JSON |
| `apps/bullet-effects` | effect broker process boundary; drives `LocalBareForge` through loss and reconciliation |

## Quick start

```bash
just setup
just fast
BULLET_DATA_DIR=./target/demo cargo run -p bullet -- demo
```

The demo receipt is re-derived from ledger rows on every run and proves the
permanent fence advanced (fence 1, then fence 2 on the same variant), that a
stale heartbeat and stale token are refused, and that a lost SCM response is
recorded as an unknown outcome rather than a success.

The portal is a projection of this API. It is never an authority source.

## Lanes

| Lane | Command | Contents |
| --- | --- | --- |
| fast | `just fast` | fmt check, nextest `fast` profile, `contracts check` |
| required | `just check` | fast plus clippy `-D warnings` |
| contract | `just contract` | nextest `contract` profile plus harness tapes and simulators; offline |
| security | `just security` | gitleaks (no-git) plus `cargo deny check bans`; a missing tool fails |
| audit | `bash ops/ci/audit.sh` | Jankurai audit against a committed ratchet floor; artifacts under `.jankurai/` |
| nightly | `bash ops/ci/nightly.sh` | registered live-adapter lane; neutral unless `BULLET_LIVE_PROVIDERS` names providers |

`.github/workflows` runs exactly these scripts. Runners must provide
`cargo-nextest`, `gitleaks`, `cargo-deny`, and `jankurai`.

## Readiness

| Surface | Current meaning |
| --- | --- |
| Component tests | Lease, ledger, harness, runner, verifier, effects, and protocol primitives |
| `bullet demo` | Deterministic ledger simulation only |
| `bullet demo-synthetic` | Offline non-gating scaffold; while production authority is unavailable, it exits failed with a typed refusal and no Candidate |
| Exact five-plane transaction | Not implemented or proven |
| Production | Not eligible; signed authority, sandbox, budgets, freeze, audit, and restore gates are incomplete |

The product scaffold never selects Runner's private `#[cfg(test)]` workspace
simulator. That simulator covers repair-loop mechanics only and cannot produce
transaction, live, or release evidence. Until signed BulletGit authority is
available, the product receipt must preserve `AUTHORITY_CONTRACT_UNAVAILABLE`
and show no Candidate, Evidence, or effect.

Every provider spawn passes through the harness argv gate, which refuses by
default (`LIVE_ADMISSION_UNAVAILABLE`). The `--features live` smoke tests in
`crates/harness-*/tests/live.rs` are `#[ignore]`, run only from the nightly lane
with `BULLET_LIVE_PROVIDERS`, and fail closed rather than skip when the gate
refuses. The Jeryu adapter performs no credential lookup or network call. No
component test or synthetic receipt establishes Transaction-ready or
production-ready status.
