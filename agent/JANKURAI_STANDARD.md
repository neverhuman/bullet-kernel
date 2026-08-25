# Jankurai Standard Binding

Standard version: `0.9.0`. Target stack: Rust control plane, generated
contracts, SQLite adapters. The machine-readable half of this binding is
`agent/standard-version.toml`, `agent/owner-map.json`, `agent/test-map.json`,
`agent/proof-lanes.toml`, `agent/generated-zones.toml`, `agent/boundaries.toml`,
`agent/security-policy.toml`, `agent/tool-adoption.toml`,
`agent/audit-policy.toml` and `db/migrations/meta.toml`.

## Hard rules

- `crates/domain` is pure: no filesystem, env, process, network, SQL or mutating
  clock. The exact forbidden import list is `agent/boundaries.toml`.
- SQL lives in `crates/adapters` and `db/migrations`.
- Public HTTP shapes are generated from `contracts/openapi.yaml`.
- No Python product truth. No writable Git worktrees.
- Split files before 500 LOC; prefer under 300.
- `AUDIT_FLOOR` in `ops/ci/audit.sh` is an upward-only ratchet.
- Never skip-green: a missing tool, a skipped case or an `UNKNOWN` result is
  never success (`ops/AGENTS.md`).

## Generated zones

Do not hand-edit a `generator_only` zone. `crates/domain/src/schema_bundle.rs`
and `crates/adapters/tests/fixtures/formal/` are hub-synced;
`contracts/generated/` is emitted from `contracts/openapi.yaml`. Repair them
from the source with the `command` recorded next to the zone in
`agent/generated-zones.toml`, never by editing the output.
`contracts/schemas/patch-proposal.json` is deliberately absent from that
manifest: it is hand-written, it has no generator, and declaring it would claim
one. Its agreement with the authoritative Rust struct is proved instead by
`schema_and_authoritative_struct_agree` in `crates/harness-core/src/proposal.rs`,
which embeds the exact bytes through `schema_source()`.

## Repair receipts and the agent-friendly exception surface

Every failure in this repository is a typed value with a stable machine reason
code, so the next agent can route a repair without reading a log. The contract
each error type satisfies:

- **purpose** — say which boundary refused, in the caller's vocabulary.
- **reason** — a stable `SCREAMING_SNAKE` reason code returned by
  `reason_code()`. It is a wire contract: `bullet-git`, the runner, the daemon
  and the portal all match on it, so it is renamed only with a contract change,
  never for tidiness. `crates/domain/tests/invariants.rs::reason_codes_are_stable`,
  `crates/harness-core/src/error.rs::reason_codes_are_stable` and
  `crates/runner/src/error.rs::reason_codes_are_stable` pin the exact strings.
- **common fixes** — the typed variant names the recoverable action.
  `STALE_AUTHORITY` means refetch the authority token and retry with the current
  fence. `INVALID_LEASE_TTL` means the requested TTL is outside the admitted
  1..=15 second range. `IDEMPOTENCY_CONFLICT` means the same command id was
  replayed with a different payload; read the recorded response instead of
  re-sending. `RESTORE_ADMISSION_REQUIRED` means the database was physically
  restored and is quarantined; it is not a retryable error.
  `LIVE_ADMISSION_UNAVAILABLE` means no live provider is admitted; the offline
  contract lane is the supported path.
- **repair_hint** — the lane that reproduces the failure locally. Every error
  category maps to one command: domain and application failures to
  `bash scripts/ci-local.sh fast`, adapter and migration failures to
  `bash scripts/ci-local.sh required`, provider protocol failures to
  `bash scripts/ci-local.sh contract`, supply-chain failures to
  `bash scripts/ci-local.sh security`, and score regressions to
  `bash scripts/ci-local.sh audit`.
- **docs_url** — `docs/architecture.md` for the boundary that refused,
  `docs/cli.md` for operator-facing surfaces, `docs/egress-isolation.md` for
  containment refusals, and this file for the standard binding itself.

The rerun command and the artifact it writes are the repair receipt: the audit
lane leaves `.jankurai/repo-score.json`, `.jankurai/repo-score.md` and
`.jankurai/repair-queue.jsonl`, and a rerun of the named lane is the evidence
that a repair landed. An `UNKNOWN` outcome is reported as `UNKNOWN`; it is never
reconciled into success.

## No ZYAL runbooks live here

A ZYAL v1 runbook is a `RUN_FOREVER` daemon envelope. This component has no
run-forever agent loop, so its proof surface is `agent/proof-lanes.toml` and the
`ops/ci/<lane>.sh` scripts instead. The previous `agent/zyal/fast.zyal` was a
three-line stub that was not a ZYAL envelope at all; it was removed rather than
dressed up into a fake envelope to satisfy a checker.

## Accepted audit exceptions

Exceptions are declared where the auditor reads them, never as a silent
suppression: `agent/audit-policy.toml` (`[dead_language] allow_terms`, with the
justification for each term next to it) and inline
`jankurai:allow <detector> reason=… owner=… expires=…` comments. A wire-contract
string is never renamed to satisfy a marker rule.
