# bullet-kernel operations

CI entrypoints live in `ops/ci/` and are exposed by `scripts/ci-local.sh <lane>`
and the `Justfile`. Every lane is one script; hosted CI and local runs execute
the same file.

| Lane | Script | Hosted (`.github/workflows/ci.yml`) | Exit contract |
| --- | --- | --- | --- |
| `fast` | `ops/ci/fast.sh` | yes, atomic | digest-bound 747-test standalone partition, including the explicitly feature-enabled verifier fixture tests, all executed with zero skipped; both Gitd binary variables are unset so product resolution fails closed |
| `lint` | `ops/ci/lint.sh` | yes, atomic | fmt, Clippy, actionlint 1.7.8, ShellCheck 0.10.0, workflow/inventory/observation/nightly meta-tests |
| `contract` | `ops/ci/contract.sh` | yes, atomic | exact 34-test offline provider-contract/simulation partition; never resolves `bullet-gitd` |
| `security` | `ops/ci/security.sh` | yes | gitleaks; `cargo deny fetch db` then a lane-side freshness proof of the RustSec database; `cargo deny --locked check licenses advisories bans sources` against the committed `deny.toml`; `zizmor --offline --no-ignores --strict-collection .github`; a missing tool, a missing `deny.toml`, or an absent/stale advisory database fails |
| `docs` | `ops/ci/docs.sh` | yes, atomic | generated-contract drift, rustdoc, repository-relative links |
| `required` | `ops/ci/required.sh` | local only | fast + lint + contract + security + docs, sequentially and exactly once |
| `family` | `ops/ci/family.sh` | no | exact nine family tests; requires a canonical executable `BULLET_GITD_BIN` and exact `BULLET_GITD_SHA256`; no sibling fallback |
| `faults` | `ops/ci/faults.sh` | no (local) | exact 13-test component sampler under wrapper-owned private Cargo-target custody, including the parent of the six-process SQLite/local-bare recovery matrix; direct ambient-target invocation refuses, and no release fault receipt is emitted |
| `proof-transaction-offline` | `ops/ci/proof-transaction-offline.sh` | no | retained exact-digest production-Gitd component bridge; emits only unsigned fixture-ineligible `COMPONENT_PROOF` and cannot clear a transaction/release gate |
| `proof-synthetic-dogfood` | `ops/ci/proof-synthetic-dogfood.sh` | no | two sequential simulator Candidates -> blinded selection -> sealed winner -> fresh third-Runner successor-fence lease -> fixture-signed verification -> local-bare response-loss reconciliation -> exact-SHA check -> protected integration -> fixture-signed observation -> terminal settlement; final decode replays the exact retained origin receipt and the wrapper independently checks its framed bytes; two create-once unsigned component receipts and 10 named + 5 ordinary-chaos fault cells, including both real post-acquire grant-readback cleanup paths; same-UID cooperative custody only, with no Delivery/Check/Integration grants or distinct service identities; interruption after an unobserved remote mutation is non-resumable `ORPHANED_REMOTE`; every higher eligibility is hard-false |
| `audit` | `ops/ci/audit.sh` | no (local) | Jankurai, ratchet floor `AUDIT_FLOOR`; missing auditor fails |
| `egress` | `ops/ci/egress.sh` | no (local) | exact three-name host-dependent namespace/nft/proxy partition via filtered nextest `--run-ignored all`; 78 neutral when tools or user namespaces are missing, green only after all three run |
| `nightly` | `ops/ci/nightly.sh` | no (local) | per-provider refusal test + positive half; all PONG is 0, any neutral refusal without failure is 78, any failure is 1; real mode needs `BULLET_LIVE_REAL=1` and an absolute `BULLET_POLICY_PATH` |

## Security lane policy

`deny.toml` at the repository root is the committed supply-chain policy and is
the only place a license, advisory, ban, or source exception may be written;
each entry carries the crate that justifies it. The lane runs
`cargo deny --locked check licenses advisories bans sources`, so all four
checks fail closed together.

The advisory database is cloned into `target/advisory-db` (ignored) rather than
into the ambient `CARGO_HOME`, and the lane proves its freshness itself: it
reads the database's newest commit and refuses at 14 days
(`ADVISORY_DB_ABSENT` / `ADVISORY_DB_UNREADABLE` / `ADVISORY_DB_STALE`, exit 1).
That check exists because cargo-deny 0.19.8 fetches through the git CLI and
reads a non-zero `git` exit as success, so a failed fetch alone cannot fail the
check on a host that already has a database, and `maximum-db-staleness` cannot
see it either because a failed `git fetch` still rewrites `FETCH_HEAD`. Never
replace that gate with a `|| true`, a skip, or a wider age limit to get a green
run on an offline host: an unrefreshed database means the scan is not trusted.

`zizmor --offline --no-ignores --strict-collection .github` audits the GitHub
workflow and action bytes without API access or traversal of `.git` runtime
state, refuses configured ignores, and treats collection warnings as failures.
Do not add a token, broaden the input to runtime state, or weaken those flags
in a proof lane.

`ops/ci/inventory.sh` is the single filter/count declaration;
`ops/ci/inventory-test.sh` proves its nonzero, union, disjointness, complete
identity digests, exact family/egress identities, unprovisioned Gitd-variable refusal, and source
inventory. `ops/ci/nightly-test.sh` pins the nightly wrapper's exact
calls and exit precedence. Edits under `ops/` are routed to `just check` by
`agent/test-map.json`. Full lane semantics live in `docs/testing.md`.
