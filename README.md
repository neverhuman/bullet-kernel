# bullet-kernel

Control-plane modular monolith for Bullet Farm. Agents start at [`AGENTS.md`](AGENTS.md).

## Layout

| Path | Role |
| --- | --- |
| `crates/domain` | IDs, tokens, state machines, taxonomy; no I/O |
| `crates/application` | commands, materializer, leases/fences, pure simulators, `bullet demo` |
| `crates/adapters` | SQLite WAL ledger, checksummed migrations, and offline receipt-bound backup/quarantined restore |
| `crates/adapters-postgres` | configuration scaffold; implements no `Ledger` and never connects in required CI |
| `crates/harness-core`, `crates/harness-sim` | adapter trait, probed provider admission, event envelope, argv/supervision gate, deterministic simulator |
| `crates/harness-{claude,codex,cursor,antigravity}` | fail-closed provider contract crates with bounded offline transcript/result subsets |
| `crates/runner` | attempt loop, scope check, heartbeat self-fence, `bullet-gitd` supervision |
| `crates/verifier` | clean-room reconstruction and typed gate outcomes |
| `crates/effects` | effect broker and state machine over `LocalBareForge`; the Jeryu adapter is a typed quarantine |
| `crates/router`, `fusion`, `behavior`, `projections` | non-authoritative scaffolds: routing fallback, fusion, behaviour catalog, spec §25 surfaces |
| `crates/mcp-mock`, `crates/test-simulation` | in-process mocks and harness tapes for the contract lane |
| `apps/bullet-farmd` | HTTP + SSE daemon: `/health`, `/openapi.yaml`, `/v1/missions[/{id}]`, `/v1/demo[/run]`, `/v1/outbox`, `/v1/events`, `/v1/leases/{acquire,heartbeat,release}`, `/v1/attempts/advance`, `/v1/ready` |
| `apps/bullet` | CLI: `farm init|backup|restore`, `demo`, `demo-synthetic`, and `contracts generate|check` |
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

## Offline maintenance

```bash
cargo run -p bullet -- farm backup \
  --database ./target/demo/ledger.sqlite \
  --output ./backup.sqlite \
  --receipt ./backup.receipt.json
cargo run -p bullet -- farm restore \
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

| Lane | Command | Contents |
| --- | --- | --- |
| fast | `just fast` | fmt check, nextest `fast` profile, `contracts check` |
| required | `just check` | fast plus clippy `-D warnings` |
| contract | `just contract` | nextest `contract` profile plus harness tapes and simulators; offline |
| security | `just security` | gitleaks (no-git) plus `cargo deny check bans`; a missing tool fails |
| audit | `bash ops/ci/audit.sh` | Jankurai audit against a committed ratchet floor; artifacts under `.jankurai/` |
| nightly | `bash ops/ci/nightly.sh` | unregistered legacy live wrapper; unset exits 78 and no result is release evidence |

`.github/workflows` runs exactly these scripts. Runners must provide
`cargo-nextest`, `gitleaks`, `cargo-deny`, and `jankurai`.

## Readiness

| Surface | Current meaning |
| --- | --- |
| Component tests | Lease, ledger, harness, runner, verifier, effects, and protocol primitives |
| `bullet demo` | Deterministic ledger simulation only |
| `bullet demo-synthetic` | Offline non-gating scaffold; while production authority is unavailable, it exits failed with a typed refusal and no Candidate |
| `bullet farm backup|restore` | Offline integrity/subject maintenance; restored truth remains quarantined |
| Internal command worker | Authenticated invoked reconciliation; demo work settles only `UNKNOWN`, unsupported kinds only `FAILED` |
| Provider contracts | Four bounded offline transcript/result subsets; public runtime operations remain blocked |
| Exact five-plane transaction | Not implemented or proven |
| Production | Not eligible; signed dispatch, online BulletGit authority, containment, budgets, freeze, and restore admission are incomplete |

The product scaffold never selects Runner's private `#[cfg(test)]` workspace
simulator. That simulator covers repair-loop mechanics only and cannot produce
transaction, live, or release evidence. Until signed BulletGit authority is
available, the product receipt must preserve `AUTHORITY_CONTRACT_UNAVAILABLE`
and show no Candidate, Evidence, or effect.

The harness has one non-spawning `ProviderAdmission` evaluator. It requires an
absolute canonical executable and exact complete descriptor/version/capability/
profile/protocol probe; stages only digest-bound, individually allowlisted OAuth files
in a unique 0700 HOME as 0400 files; builds the child environment from a
positive allowlist; and checks canaries across environment, stdout, stderr,
events, and the accepted gate-ID-only proposal. Its deterministic receipt binds
those facts but is not authority: signed admission and audited provider-only
egress are explicit blockers, so `build_with_admission` cannot spawn. Codex App
Server JSONL, Cursor ACP, Antigravity structured headless with 1.1.19's
flags-before-prompt-last-`-p=` ordering, and Claude stream JSON are the frozen
protocol requirements; runtime probes, not provider names, determine
conformance. No provider currently has an admitted live runtime.

The four committed provider machines accept only bounded offline protocol
subsets: Claude stream messages, Codex App Server JSONL, Cursor ACP, and
Antigravity's one-shot structured result. Exact structured terminal output may
become a locally validated, unverified `PatchProposal` with the admitted
`gate_ids`; free text cannot become a proposal, and no proposal is Evidence or
`VERIFIED` truth. Their `--features live` tests are non-ignored refusal contracts
that prove public runtime methods do not spawn or create artifacts. Fixed
installed-version or schema observations are test inputs, not live runtime
conformance.

The ordinary harness argv gate also refuses every known live provider executable
by default (`LIVE_ADMISSION_UNAVAILABLE`). Its bounded supervision and process-
group cleanup are component-level mechanics, not a provider dispatch path or
network containment. The authenticated internal worker likewise has no admitted
runner, verifier, or effect adapter: it can durably reconcile only to `UNKNOWN`
or `FAILED`, never `APPLIED` or `VERIFIED`. There is no signed provider dispatch,
online BulletGit call, independent Evidence flow, or runner-to-verifier-to-effect
transaction. The Jeryu adapter performs no credential lookup or network call.
No component test or synthetic receipt establishes Transaction-ready or
production-ready status.
