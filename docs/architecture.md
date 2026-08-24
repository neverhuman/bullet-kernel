# Kernel architecture

## Ledger core

`crates/domain` is pure: ids, Authority Tokens, and the spec section 24
state machines. `crates/application` owns transitions, the `Ledger` port
(single-transaction lease acquisition, six-column heartbeat, expiry,
outbox), the pure simulators (`simulators.rs`; `crates/adapters` only
re-exports them), and the demo. `crates/adapters` owns SQLite (WAL,
`schema_version` migrations under `db/migrations`, typed authority tables).
`MemoryLedger` and `SqliteLedger` pass one shared conformance suite.
`crates/adapters-postgres` is a configuration scaffold: it implements no
`Ledger`, runs no conformance, and reports `NotConfigured` without
`DATABASE_URL`.

## Edge and contracts

`apps/bullet-farmd` is the HTTP + SSE edge; errors are typed problem
details with stable reason codes, and `/v1/missions/{id}` and `/v1/ready`
carry an `X-Bullet-As-Of-Sequence` watermark. `contracts/openapi.yaml` is
the contract source of truth; `bullet contracts generate` emits
`contracts/generated/api.ts` and `bullet contracts check` gates CI.

## Provider harness

`crates/harness-core` defines the adapter trait, capability matrix, event
envelope, and the argv gate every spawn passes through (kill switch,
worktree-flag deny list, default refusal of live provider executables).
`crates/harness-sim` is the deterministic simulator; the four provider
crates parse real CLI output offline and keep one `#[ignore]` live smoke
test each behind `--features live`.

## Process boundaries

`crates/runner` (`apps/bullet-runner`) runs the attempt loop: scope check,
heartbeat self-fence, checkpoint journal, and `bullet-gitd` supervision; the
binary accepts only the `sim` provider. `crates/verifier`
(`apps/bullet-verifier`) reconstructs the candidate in a clean room and
returns typed gate outcomes. `crates/effects` (`apps/bullet-effects`) is the
effect broker and state machine over `LocalBareForge`; ambiguous loss stays
`unknown` until reconciled, and the Jeryu adapter is a typed quarantine.

## Scaffolds

`crates/router`, `crates/fusion`, `crates/behavior`, and
`crates/projections` are non-authoritative and non-gating. `crates/mcp-mock`
and `crates/test-simulation` exist for the contract lane only.

Content-addressed artifact storage is not implemented.
