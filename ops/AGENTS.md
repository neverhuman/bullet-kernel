# bullet-kernel operations

CI entrypoints live in `ops/ci/` and are exposed by `scripts/ci-local.sh <lane>`
and the `Justfile`. Every lane is one script; hosted CI and local runs execute
the same file.

| Lane | Script | Hosted (`.github/workflows/ci.yml`) | Exit contract |
| --- | --- | --- | --- |
| `fast` | `ops/ci/fast.sh` | yes | fmt, nextest `fast`, `contracts check` |
| `required` | `ops/ci/required.sh` | yes | fast + `ops/ci/nightly-test.sh` + clippy `-D warnings` |
| `contract` | `ops/ci/contract.sh` | yes | nextest `contract` + `bullet-test-simulation`; offline |
| `security` | `ops/ci/security.sh` | yes | gitleaks; `cargo deny fetch db` then a lane-side freshness proof of the RustSec database; `cargo deny --locked check licenses advisories bans sources` against the committed `deny.toml`; `zizmor .`; a missing tool, a missing `deny.toml`, or an absent/stale advisory database fails |
| `audit` | `ops/ci/audit.sh` | no (local) | Jankurai, ratchet floor `AUDIT_FLOOR`; missing auditor fails |
| `egress` | `ops/ci/egress.sh` | no (local) | live namespace/nft/proxy proofs; 78 neutral when tools or user namespaces are missing |
| `nightly` | `ops/ci/nightly.sh` | no (local) | per-provider refusal test + positive half; 78 when `BULLET_LIVE_PROVIDERS` is unset; real mode needs `BULLET_LIVE_REAL=1` and an absolute `BULLET_POLICY_PATH` |

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

`zizmor .` audits the workflow bytes. Without a GitHub API token it skips its
five online audits (impostor-commit, ref-confusion, known-vulnerable-actions,
stale-action-refs, ref-version-mismatch) and prints that it is doing so; the
offline audits still fail the lane on a finding. Do not add a token to make the
online audits run from a proof lane.

`ops/ci/lib.sh` supplies `log`, `require_tool`, and `run_tests <profile>`;
`ops/ci/nightly-test.sh` is the meta-test that pins the nightly wrapper's exact
`cargo` calls and both modes. Edits under `ops/` are routed to `just check` by
`agent/test-map.json`. Lane semantics are documented in `README.md#lanes`.
