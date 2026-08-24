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
envelope, central `ProviderAdmission`, and supervised argv boundary. Admission
compares one absolute canonical executable against its exact BLAKE3 digest and
fresh runtime-probe snapshot (complete `HarnessDescriptor`, verified version and
profile, capability digest, and protocol). It creates a unique 0700 HOME, copies only exact policy-listed OAuth
files after digest and symlink checks as 0400, and constructs a child environment
from locale hints plus HOME/TMPDIR/XDG paths. Host PATH, SCM, cloud, SSH, and API
secrets are not inherited. Canary scanning covers that environment plus complete
stdout, stderr, normalized events, and the validated `PatchProposal`; proposal
text supplies `gate_ids`, never commands.

The local conformance receipt binds the exact probe, environment, credentials,
output/event/proposal digests, and every blocker, and verifies its own
domain-separated digest. It can never authorize dispatch. Signed Kernel
admission validation and audited provider-only network egress are not
implemented, so every receipt contains both blockers. Runtime probes must show
Claude stream JSON, Codex App Server JSONL, Cursor ACP, or Antigravity structured
headless mode with 1.1.19's flags before a prompt-last `-p=`; current legacy
protocol adapters stay nonconformant.
No claim of network containment follows from environment filtering.

The argv boundary additionally enforces the kill switch, worktree/tmux deny
list, exact admitted executable, and default refusal of live provider programs.
Supervision records exit/crash, cancellation, heartbeat loss, or deadline and
kills the POSIX process group before bounded pipe reaping. This is the Linux V1
process-tree mechanism, not a cross-platform sandbox.
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
