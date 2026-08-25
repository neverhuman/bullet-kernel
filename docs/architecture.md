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

SQLite maintenance is an offline boundary. `bullet farm backup` uses SQLite's
online backup API, validates exact schema, foreign keys, and integrity, then
publishes an absent snapshot; the CLI separately writes an absent unsigned
BLAKE3 receipt, so receipt failure may leave an unusable orphan snapshot.
`bullet farm restore` admits the receipt-bound bytes through a bounded no-follow
descriptor, advances the restore epoch, and no-clobber publishes an absent
destination. That proves integrity and exact subject, not authenticity. A late
directory-sync failure has an `UNKNOWN` publication outcome with a complete
destination possibly present. The restored database remains quarantined and
normal ledger open fails until a future production authority operation admits
its restore epoch.

## Edge and contracts

`apps/bullet-farmd` is the HTTP + SSE edge; errors are typed problem
details with stable reason codes, and `/v1/missions/{id}` and `/v1/ready`
carry an `X-Bullet-As-Of-Sequence` watermark. `contracts/openapi.yaml` is
the contract source of truth; `bullet contracts generate` emits
`contracts/generated/api.ts` and `bullet contracts check` gates CI.
Public command submission records `PENDING`. A separately authenticated,
explicitly invoked internal reconciler atomically settles the command, outbox,
and audit event, but has no execution/read-back adapter: known demo work becomes
only `UNKNOWN`, and unsupported kinds only `FAILED`. It cannot emit `APPLIED` or
`VERIFIED`.

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
implemented, so every receipt contains both blockers. Runtime probes must
eventually show Claude stream JSON, Codex App Server JSONL, Cursor ACP, or
Antigravity structured headless mode with 1.1.19's flags before a prompt-last
`-p=`. No claim of network containment follows from environment filtering.

The four provider crates expose pure, bounded offline transcript/result machines
plus blocked public runtime surfaces: Claude stream messages, Codex App Server
JSONL, Cursor ACP, and an Antigravity one-shot structured result. They correlate
protocol subjects and accept a `PatchProposal` only from exact structured
terminal output with ordered admitted `gate_ids`; free text is never authority,
and a proposal is not Evidence. Their feature-gated tests are non-ignored refusal
contracts, not live smokes or runtime conformance. Installed-version and schema
observations only freeze test inputs. All raw provider frames use strict recursive
decoding that rejects decoded-equivalent duplicate object keys and trailing data;
Codex applies it again to its inner proposal text. RFC 8785 byte/numeric-lexeme
identity, signed admission, credential and egress containment, transport
supervision, and live receipts remain absent.

The argv boundary additionally enforces the kill switch, worktree/tmux deny
list, exact admitted executable, and default refusal of live provider programs.
Supervision records exit/crash, cancellation, heartbeat loss, or deadline and
kills the POSIX process group before bounded pipe reaping. This is the Linux V1
process-tree mechanism, not a cross-platform sandbox.
`crates/harness-sim` is the deterministic simulator. Harness-core supervision is
tested as a component, but no provider adapter is authorized to enter that spawn
path.

## Process boundaries

`crates/runner` (`apps/bullet-runner`) runs the attempt loop: scope check,
heartbeat self-fence, checkpoint journal, and `bullet-gitd` supervision; the
binary accepts only the `sim` provider. `crates/verifier`
(`apps/bullet-verifier`) reconstructs the candidate in a clean room and
returns typed gate outcomes. `crates/effects` (`apps/bullet-effects`) is the
effect broker and state machine over `LocalBareForge`; ambiguous loss stays
`unknown` until reconciled, and the Jeryu adapter is a typed quarantine.
These are isolated component boundaries. There is no signed provider dispatch,
online-authorized BulletGit mutation, or connected runner -> BulletGit ->
independent verifier -> effect transaction, so none supplies production Evidence
or integration truth.

## Scaffolds

`crates/router`, `crates/fusion`, `crates/behavior`, and
`crates/projections` are non-authoritative and non-gating. `crates/mcp-mock`
and `crates/test-simulation` exist for the contract lane only.

Content-addressed artifact storage is not implemented.
