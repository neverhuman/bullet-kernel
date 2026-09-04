# Kernel architecture

Last reviewed: 2026-08-26 against HEAD `3fb9d8e`. Every claim names the code
it is read from. Evidence classes follow `bullet-farm/docs/release.md`; nothing
below is `TRANSACTION_PROOF`, `LIVE_PROOF`, or `RELEASE_PROOF`.
<!-- bullet-doc-review:v1 subject=f8aa2b087a2fff064669ee136d25eb64ffad594e max_distance=25 paths=crates/domain/src/lib.rs,crates/application/src/lib.rs,crates/adapters/src/lib.rs,apps/bullet-farmd/src/api.rs,apps/bullet-farmd/src/lease_transport_rpc.rs,crates/runner/src/signed_lease_rpc.rs -->

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

The current `AuthorityToken` is still an unsigned legacy in-process value, never
a mutation capability. Kernel typed ids are prefix plus 64 lowercase hex
(`crates/domain/src/ids.rs`), while the frozen wire authority contract still
requires different prefixes for some subjects. Lease and Attempt rows now persist
durable configuration/policy/routing/provider generations, authority epoch,
and freeze generation through a singleton `authority_revisions` row.
Grants now bind against `Ledger::current_authority()` rather than hard-coded
constants, so durable rows can evolve with policy and provider claims.
The kernel has an admitted PASETO v4.public verifier for launch grants
(`crates/harness-core/src/launch_grant/verify.rs`, below) and a quarantined
lease-transport permit verifier (`crates/harness-core/src/lease_transport.rs`),
but production authority remains an online gate: V1-S1 wire consumption and
normalized durable subject truth still need the remaining release proofs.
Until then, the online active-lease check is an observation only and unsigned
authority stays refused.

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

`apps/bullet-farmd` is the loopback-only HTTP + SSE edge (`--bind` refuses a
non-loopback address). Errors are typed problem details with stable reason
codes; `/api/v1/missions/{id}`, `/api/v1/ready`, and the six projections carry an
`X-Bullet-As-Of-Sequence` watermark. The exact mounted route set is the table
in [`README.md`](../README.md#farmd-routes); the router fallback answers
`NOT_FOUND`. `contracts/openapi.yaml` is the contract source of truth for every
public route (the internal reconciler is deliberately absent from it);
`bullet contracts generate` emits `contracts/generated/api.ts` and
`bullet contracts check` gates CI. Public command submission records
`PENDING`. A separately authenticated, explicitly invoked internal reconciler
(`POST /internal/v1/commands/{id}/reconcile`, inert without
`--worker-token-file`) atomically settles the command, outbox, and audit
event, but has no execution/read-back adapter: known demo work becomes only
`UNKNOWN`, and unsupported kinds only `FAILED`. It cannot emit `APPLIED` or
`VERIFIED`. After worker authentication and identifier validation, an absent
command returns non-retryable RFC 9457 `404 NOT_FOUND`; durable store or
corruption failures remain retryable `500 STORE_FAILURE`.

## Projections

Source: `apps/bullet-farmd/src/projections/{mod,fleet,sessions,context_lineage,merge_rail,quality_lab,audit}.rs`.

`/api/v1/fleet`, `/api/v1/sessions`, `/api/v1/context-lineage`, `/api/v1/merge-rail`,
`/api/v1/quality-lab`, and `/api/v1/audit` are read-only spec §25 surfaces. Each route performs exactly one
atomic ledger snapshot (`read_snapshot`) and returns the standard envelope with
its `as_of_sequence`, so a response never mixes two ledger states. Label
tallies are `LabelCount` rows built by `count_labels` against a complete
catalog: every catalog label is listed with its count, so a zero is explicit
rather than absent, and observed labels outside the catalog are appended
rather than dropped. An empty set is zero rows verified at a sequence, never a
healthy default. The Portal's required lane consumes these five routes against
a real farmd (component receipts Kernel `529bad1`, Portal `95108e3`); they are
projections, never authority, and change no release decision. `crates/
projections` holds only the §25 `View`/`Surface` types (a failed read is
`unknown`, never an empty list) and stays non-gating.

## Provider harness

`crates/harness-core` defines the adapter trait, capability matrix, event
envelope, central `ProviderAdmission`, and supervised argv boundary. Admission
compares one absolute canonical executable against its exact BLAKE3 digest and
fresh runtime-probe snapshot (complete `HarnessDescriptor`, verified version and
profile, capability digest, and protocol). It creates a unique 0700 HOME, copies
only exact policy-listed OAuth files after digest and symlink checks as 0400,
and constructs a child environment from locale hints plus HOME/TMPDIR/XDG paths.
Host PATH, SCM, cloud, SSH, and API secrets are not inherited. Canary scanning
covers that environment plus complete stdout, stderr, normalized events, and the
validated `PatchProposal`; proposal text supplies `gate_ids`, never commands.

The local conformance receipt (`ProviderConformanceReceipt`) binds the exact
probe, environment, credentials, output/event/proposal digests, and every
blocker, and verifies its own domain-separated digest. It can never authorize
dispatch by itself: a deserialized receipt's `require_dispatch` always refuses
(`PROVIDER_ADMISSION_BLOCKED`, or `UNSIGNED_RECEIPT` when no blocker remains).
Only a live `EvaluatedAdmission` that cleared every blocker with its own
evidence (next section) can reach `ArgvBuilder::build_with_admission`, which
also refuses an argv executable that differs from the admitted one. Runtime
probes must show Claude stream JSON, Codex App Server JSONL, Cursor ACP, or
Antigravity structured headless mode with 1.1.19's flags before a prompt-last
`-p=`. No claim of network containment follows from environment filtering; it
follows only from an admitted egress receipt.

The four provider crates expose pure, bounded offline transcript/result machines
plus blocked public runtime surfaces: Claude stream messages, Codex App Server
JSONL, Cursor ACP, and an Antigravity one-shot structured result. They correlate
protocol subjects and accept a `PatchProposal` only from exact structured
terminal output. `PatchProposal` (`crates/harness-core/src/proposal.rs`, schema
1) carries a content-addressed `proposal_id`, `producing_attempt_id`, the exact
`base_checkpoint_id` and `base_checkpoint_digest`, preimage-bound whole-file
`operations` (`Absent` or exact digest; `Write` or `Delete`), and ordered
admitted `gate_ids`; narrative fields are retained for review only and are
never serialized to the writer. Free text is never authority, and a proposal is
not Evidence. Their feature-gated tests are non-ignored refusal contracts, not
live smokes or runtime conformance. Installed-version and schema observations
only freeze test inputs. Their shared `LiveDispatcher` observation port defaults
to `RUNTIME_PROBE_UNAVAILABLE`; no production adapter overrides it. The owned
observation type validates a proposal but is neither signed proof nor authority.
Only the application's strict `cfg(test)` Claude wrapper constructs positive
runtime/profile/event/proposal fixture data. All raw provider frames use strict recursive decoding
that rejects decoded-equivalent duplicate object keys and trailing data; Codex
applies it again to its inner proposal text. RFC 8785 identity is enforced only
on the launch-grant, lease-transport, and policy paths (`launch_grant/canonical.rs`,
vendored and golden-vector-pinned to bullet-wire); transport supervision for
live providers and live receipts remain absent.

The argv boundary additionally enforces the kill switch
(`BULLET_PROVIDER_KILL=1`), worktree/tmux deny list, exact admitted executable,
and default refusal of live provider programs (`LIVE_ADMISSION_UNAVAILABLE`).
Supervision records exit/crash, cancellation, heartbeat loss, or deadline and
kills the POSIX process group before bounded pipe reaping. This is the Linux V1
process-tree mechanism, not a cross-platform sandbox. `crates/harness-sim` is
the deterministic simulator. Harness-core supervision is tested as a component;
the only committed provider spawn path is step 11 of the live-conformance path
below, and it is unreachable under the committed policy.

## Signed launch-grant admission

Source: `crates/harness-core/src/launch_grant/` (claims, keys, key file,
expectation, nonce port, verifier), `crates/application/src/launch_grant/`
(issuer, durable nonce store), `crates/harness-core/src/admission/signed.rs`
(blocker clearing), `crates/application/src/policy_snapshot{.rs,/keys.rs,/live.rs,/load.rs}`
(policy loader).

**Token.** A launch grant is a PASETO v4.public token (`pasetors`) over the RFC
8785 encoding of `LaunchGrantClaims`, with canonical footer
`{schema_version, issuer, key_id, purpose: "launch-grant-signing"}` and implicit
assertion `bullet-farm.launch-grant.v1alpha1`. Audience is `provider-runner`,
operation `launch-provider`, TTL at most 15 000 ms, 1..=16 unique `gat_` gate
ids, every integer at most 2^53−1, every digest 64 lowercase hex, and the
executable path absolute, normalized, and control-free. Shape validity is not
authority.

**Issuer** (`LedgerLaunchGrantIssuer`, `bullet authority mint-launch-grant`,
and step 5 below). Every lease-binding claim is read from the durable active
lease inside the coherent lease check (`durable_lease_binding`: attempt row,
lease row with matching attempt and fence, `check_active_lease`, owning
graph); the caller supplies only the evaluated provider facts, sandbox and
environment digests, gates, and budgets. A single-use nonce is persisted with
its Attempt, fence, and expiry before signing. The operator key lives at
`<data-dir>/authority/launch-grant.key`: 64 raw bytes, 0600, self-owned,
never a symlink, never overwritten, Unix only.

**Verifier** (`verify_launch_grant`), in order: envelope framing and digest;
signature, footer, and implicit assertion under the policy-selected key;
strict canonical claim decode and shape; `LaunchGrantExpectation::check_subject`
comparing 21 string and 6 integer fields for equality with the durable lease
(`mission_id`, `repository_id`, `graph_revision_id`, `work_package_id`,
`variant_id`, `attempt_id`, `runner_id`, `workspace_id`,
`workspace_nonce_digest`, `attempt_fence`, `runner_epoch`, `authority_epoch`,
`freeze_generation`), the evaluated admission (`provider`, `adapter`,
`provider_profile_id`, `model`, `protocol`, `executable_path`,
`executable_digest`, `descriptor_digest`, `capability_digest`,
`sandbox_manifest_digest`, `environment_digest`, `credential_generation`),
and the loaded policy (`policy_snapshot_digest`, `policy_generation`); the
window `not_before <= now < expires_at`; `policy.live_admission_enabled`,
else `POLICY_LIVE_ADMISSION_DISABLED`; and finally the only side effect, nonce
consumption (`Consumed`; `Replayed` is `LAUNCH_GRANT_REPLAYED`; `Expired`;
`Unknown` when never registered for that Attempt). Nothing is consumed unless
every earlier check passed, and the first mismatch is reported by field name
(`LAUNCH_GRANT_SUBJECT_MISMATCH`). `VerifiedLaunchGrant` cannot be cloned,
serialized, or constructed elsewhere.

**Blockers.** `ProviderAdmission::prepare` starts every receipt with
`SIGNED_ADMISSION_UNAVAILABLE` and `EGRESS_ISOLATION_UNAVAILABLE`, adding
`PROTOCOL_NONCONFORMANT` or `CAPABILITY_NONCONFORMANT` when the probe misses
the frozen requirement. Exactly one path clears each:

- `admit_signed(VerifiedLaunchGrant)` clears `SIGNED_ADMISSION_UNAVAILABLE`
  after eight claim fields equal the receipt: `provider`, `executable_path`,
  `executable_digest`, `descriptor_digest`, `capability_digest`,
  `provider_profile_id`, `protocol`, and a freshly recomputed
  `environment_digest` of the staged child environment. The receipt is
  re-verified, a second admission is refused, and the non-secret
  `SignedAuthorityRecord` (grant id, key, issuer, envelope digest, expiry) is
  sealed into the receipt.
- `admit_egress(EgressIsolationEvidence)` clears `EGRESS_ISOLATION_UNAVAILABLE`
  when the three digests are 64 hex, 1..=32 uniquely named lowercase probes are
  present including `REQUIRED_EGRESS_PROBES = ["direct-internet", "host-jeryu"]`,
  and every probe observed `Refused` or `Unreachable` (`Reached` or `Unknown`
  refuse). See [`egress-isolation.md`](egress-isolation.md).

`require_dispatch` re-verifies the receipt digest and refuses while any
blocker remains; it is the single chokepoint before a spawn.

**Policy loader** (committed `0d848f6`, mirroring hub ADR 0012). `load_policy`
admits `BULLET_POLICY_PATH` (absolute) or `<data-dir>/policy/policy.json`: a
regular non-symlink file at most 256 KiB, identity-checked between stat and
open (`POLICY_UNAVAILABLE` otherwise); the bytes must be canonical RFC 8785
(`NON_CANONICAL_POLICY`). `validate_policy` accepts `schema_version`
`v1alpha1` or `v1alpha2` on the snapshot; nested policies and every
`IssuerKeyV1` must be `v1alpha1` (`UNSUPPORTED_POLICY_SCHEMA`). It requires an
ordered window, generation ≥ 1, ≥ 1 issuer key, and 64-hex bundle/registry
hashes (`INVALID_POLICY_WINDOW`); issuer-key lifecycle and key-use rules
(`INVALID_ISSUER_KEY_LIFECYCLE`, `INVALID_AUTHORITY_PUBLIC_KEY`,
`INVALID_RELEASE_PUBLIC_KEY`, `INVALID_KEY_USE`); and the immutable
conservatism set, checked before any live rule so nothing can be traded for it
(`UNSAFE_POLICY`): lease TTL ≤ 15 s, no headroom from unknown quota, no
arbitrary shell gates, author evidence never independent, unknown never
satisfies a gate, R2 requires a sealed holdout, universal incumbent `T0`, no
evolutionary authority. `sandbox_policy.live_admission_enabled = true` is
`UNSAFE_POLICY` under v1alpha1; under v1alpha2 (`policy_snapshot/live.rs`) it
is legal only at `policy_generation >= LIVE_ADMISSION_MIN_GENERATION = 2`
(`LIVE_ADMISSION_REQUIRES_GENERATION`) with an unrevoked `authority-signing` /
`paseto-v4.public` key admitted for `provider-runner` overlapping the window
(`LIVE_ADMISSION_REQUIRES_RUNNER_KEY`). `validate_at(now)` adds the instant
checks (`POLICY_NOT_ACTIVE`; `LIVE_ADMISSION_REQUIRES_RUNNER_KEY` when no
qualifying key is active at `now`), with activation inclusive and expiry and
revocation exclusive. `authority_key_at` resolves `(issuer, key_id)` for an
audience only inside the window and only for an active, unrevoked
authority-signing PASETO key (`LAUNCH_GRANT_KEY_UNKNOWN`). The committed
fixture `crates/application/tests/fixtures/policy-v1alpha1.json` is
generation 1 with live admission disabled, so `require_live_admission` and the
verifier both end in `POLICY_LIVE_ADMISSION_DISABLED` naming the generation and
field; the v1alpha2 fixture is test data, not an operator ratification.
Equivalence with bullet-wire is pinned by `crates/application/tests/policy_v1alpha2.rs`
because the Kernel takes no path dependency on the hub.

## Live-conformance path

Source: `crates/application/src/live_conformance/{mod,steps}.rs`; ports in
`crates/harness-core/src/live/`; CLI entry `bullet provider live-conformance`
(flags in [`cli.md`](cli.md)).

`run_live_conformance` drives 13 ordered steps (`LiveStep::ALL`); each records
`PASS`, `REFUSED`, `FAILED`, or `NOT_RUN`, and a step that never ran is
`NOT_RUN`, never omitted:

1. `POLICY` — `require_live_admission`, then `validate_at(now)`. The committed
   v1alpha1 policy refuses here (`REFUSED`, outcome `REFUSED`, CLI exit 78)
   before any key read, runtime observation, namespace, or spawn; a live-enabled v1alpha2
   policy that is not active with an active `provider-runner` key at `now`
   fails here instead.
   Immediately after this pass, the application requests an independently
   observed runtime/conformance subject. If unavailable, the existing
   `ADMISSION` record becomes `REFUSED` with `RUNTIME_PROBE_UNAVAILABLE`; all
   other 11 records, including schema-earlier `OPERATOR_KEY` and `LEASE`, stay
   `NOT_RUN`. This early safety check preserves the frozen 13-step schema.
2. `OPERATOR_KEY` — load the 0600 key; `authority_key_at` must admit it and
   the public halves must be equal.
3. `LEASE` — materialize a deterministic conformance Mission/graph from the
   seed and acquire a durable lease (TTL 15 s).
4. `ADMISSION` — consume the already obtained owned runtime/conformance
   observation in `ProviderAdmission::prepare`/`finalize`, with fresh canaries
   and an empty credential set. No production adapter can supply that
   observation today. The fixed descriptor/profile/two-event/one-operation
   subject exists only in the strict `cfg(test)` dispatcher wrapper.
5. `MINT` — `LedgerLaunchGrantIssuer::mint` binding the durable lease, the
   receipt's digests, the egress backend's `sandbox_manifest_digest`
   (`EgressPolicy::allowlist_digest` for the real backend), and the staged
   child `environment_digest`.
6. `VERIFY_GRANT` — re-digest the executable, re-read the durable lease
   binding, `verify_launch_grant`, consume the nonce through the ledger.
7. `ADMIT_SIGNED` — clear `SIGNED_ADMISSION_UNAVAILABLE`.
8. `EGRESS_PREPARE` — `EgressBackend::prepare` (the CLI always wires the real
   `bullet-harness-egress` backend; `agy` maps to the `antigravity`
   allowlist); record the three egress digests.
9. `ADMIT_EGRESS` — clear `EGRESS_ISOLATION_UNAVAILABLE`.
10. `REQUIRE_DISPATCH` — the final chokepoint.
11. `DISPATCH` — exactly one read-only turn of `CONFORMANCE_PROMPT`
    (`Reply with the single word PONG and nothing else.`) through the sandbox
    command factory; the only provider spawn on the path.
12. `CANARY_SCAN` — a `SECRET_CANARY_EXPOSURE` from dispatch is attributed
    here.
13. `PONG_MATCH` — the trimmed response equals `PONG`; otherwise
    `PONG_MISMATCH` with outcome `FAILED`.

Receipt (`LiveConformanceReceipt`, schema `bullet.live-conformance.v1`,
sealed by a domain-separated BLAKE3 `receipt_id`): `provider`, `outcome`
(`PONG` | `REFUSED` | `FAILED`), `refusal_reason`, `failed_step`, all 13
`steps`, `executable_path`, `executable_blake3`, `grant_id`,
`grant_envelope_digest`, `egress_receipt_digest`, `egress_ruleset_digest`,
`egress_allowlist_digest`, `policy_snapshot_digest`, `policy_generation`,
`prompt`, `prompt_blake3`, `response_text`, `pong_match`, `cost_micro_usd`,
`duration_ms`, `exit_code`, `native_session_id`, `events`, `stdout_blake3`,
`stderr_blake3`, `events_blake3`, `started_at`, `completed_at`. Fields for
steps that did not run are `null`. It is written fsync'd to
`<data-dir>/live/<provider>-<utc>.json` on every outcome, including refusal
and failure.

Evidence class: the workspace test run drives this path through a fake
provider process, the strict `cfg(test)` observation wrapper, and the no-op
egress double (`live_conformance/egress.rs`, `test-seams` only, never wired
into the CLI); that is `COMPONENT_PROOF`.
`ops/ci/nightly.sh` default mode is `COMPONENT_PROOF` of refusal without spawn.
Every current product adapter refuses at runtime observation under an otherwise
valid v1alpha2 policy. No provider has a real-mode receipt; a future real-mode `PONG` would be
provider-conformance evidence for one read-only turn, not `LIVE_PROOF` of the
exact-subject transaction.

## Process boundaries

`crates/runner` (`apps/bullet-runner`) runs the attempt loop: scope check,
heartbeat self-fence, checkpoint journal, and `bullet-gitd` supervision; the
binary accepts only the `sim` provider. Since `ca380bc` the runner's `Capsule`
carries the producing Attempt and the daemon-issued base checkpoint id and
digest; `pre_apply_refusal` refuses a proposal whose `producing_attempt_id`,
`base_checkpoint_id`, or `base_checkpoint_digest` differs from the active
capsule (`proposal_binding_refused`) before the workspace port is called, and
a successful `apply_proposal` advances the capsule to the daemon's new
checkpoint. `crates/verifier` (`apps/bullet-verifier`) reconstructs the
candidate in a clean room and returns typed gate outcomes. `crates/effects`
(`apps/bullet-effects`) is the effect broker and state machine over
`LocalBareForge`; ambiguous loss stays `unknown` until reconciled. Its bounded
on-disk queue persists `PENDING` and `OUTCOME_UNKNOWN`, and the local daemon can
settle an unknown only as `QUARANTINED`, never as forge success. The Jeryu
adapter is a typed quarantine. These are isolated component boundaries.
There is no admitted live provider dispatch, online-authorized BulletGit
mutation, or connected runner -> BulletGit -> independent verifier -> effect
transaction, so none supplies production Evidence or integration truth.

## Runner ↔ farmd lease admission refusal

`apps/bullet-runner/src/main.rs` returns typed
`LEASE_TRANSPORT_ADMISSION_UNAVAILABLE` before it contacts farmd or touches the
filesystem, provider, or gitd. The dormant unsigned `HttpLeaseClient` uses the
operator `/api/v1` prefix, but its lease and advance routes are deliberately not
mounted and the product CLI never constructs it. This prevents a retired `/v1`
response or a public browser route from being mistaken for workload authority.

The committed predecessor (`419d8a6`, V1-S4) is a quarantined signed
lease-transport contract: `crates/harness-core/src/lease_transport.rs`
defines a PASETO v4.public permit with audience `lease-runner`, footer purpose
`lease-transport-signing`, implicit assertion
`bullet-farm.lease-transport.v1alpha1`, one named operation (`acquire`,
`heartbeat`, `advance`, `release`, `readback`) bound to one request digest;
`crates/application/src/lease_transport.rs` (`SignedLeaseService`) verifies a
permit and then applies one ledger operation or returns the last grant for a
lost acquire response. Its `last_acquire` index is process-local (readback
after a restart is `UNKNOWN`), its nonce ledger is in-memory, permit issuance
exists only under `test-seams` (`issue_permit`), and `crates/runner/src/
signed_lease.rs` (`SignedLeaseClient`, `test-seams` only) co-locates the
signing key with the verifier, which makes it a simulator, never an admission
path. `DirectLeaseClient` remains unsigned and test/embedded-only. A newer
internal UDS predecessor keeps the signing key in farmd, persists grants/nonces,
binds the connected Runner UID and registered Runner ID/epoch with `SO_PEERCRED`,
and makes the client pin the farmd UID plus socket group/device/inode. Its
registry is configurable only through a debug fixture, the client's acquire
read-back metadata is process-local, and `bullet-runner` does not construct it.
No public `/api/v1/leases` route is remounted, no production workload transport
is admitted, and this closes no five-plane gate.

## Scaffolds

`crates/router`, `crates/fusion`, and `crates/behavior` are non-authoritative
and non-gating. `crates/projections` holds the §25 `View`/`Surface` types only;
the served projections are described above under Projections. `crates/mcp-mock`
and `crates/test-simulation` exist for the contract lane only.

Content-addressed artifact storage is not implemented.
