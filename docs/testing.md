# Kernel CI and test inventory

Kernel has five atomic standalone lanes. `bash scripts/ci-local.sh required`
runs them once, sequentially, in this order: `fast`, `lint`, `contract`,
`security`, `docs`. GitHub runs the same scripts in parallel after a
credential-free source-admission scan and converges on the stable
`CI / required` job. A failed, skipped, cancelled, or missing predecessor makes
that aggregator fail.

## Frozen inventory

`ops/ci/inventory.sh` declares the nextest filters and reviewed counts:

| Partition | Selected | Meaning |
| --- | ---: | --- |
| standalone | 496 | all tests except provider-contract/simulation and family tests; 493 execute and three reviewed live-egress tests remain ignored |
| contract | 34 | four offline provider protocol binaries plus `bullet-test-simulation` |
| family | 4 | `heartbeat_stale`, `kill_retry`, `loop_sim`, and `synthetic_e2e` |
| total | 534 | complete nextest inventory, including ignored tests |

`ops/ci/inventory-test.sh` independently lists all four sets, requires every
set to be nonzero, checks pairwise disjointness and exact union, digest-binds
all identities, locks the four family and three ignored test identities, and
scans test sources for every `bullet-gitd` resolution site. A new, removed,
renamed, ignored, or silently reclassified test makes `lint` fail until the
inventory is reviewed.

`fast`, `contract`, and coverage export a checked nonexistent absolute
`BULLET_GITD_BIN` sentinel. That overrides the product's canonical-family
fallback, so accidentally selected or indirect daemon work fails instead of
finding a sibling repository. The family lane is separate and fail-closed:

```bash
BULLET_GITD_BIN=/canonical/absolute/path/to/bullet-gitd \
  bash scripts/ci-local.sh family
```

The path must already be canonical, name a regular executable, and exist. The
lane never falls back to `../bullet-git/target/...`. Family CI remains blocked
until the Hub can provision immutable authenticated repository subjects and
pass the exact daemon path.

## Atomic lanes

| Lane | Scope |
| --- | --- |
| `fast` | standalone nextest partition only |
| `lint` | rustfmt, all-target Clippy, actionlint 1.7.8, ShellCheck 0.10.0, workflow policy, inventory/observation/nightly meta-tests |
| `contract` | exactly 34 offline provider-contract and simulation tests |
| `security` | current-tree gitleaks 8.21.2; full cargo-deny 0.19.8 advisories/bans/licenses/sources with independently proved RustSec freshness; zizmor 1.25.2 |
| `docs` | generated-contract drift, workspace rustdoc, repository-relative Markdown links |

Nextest writes raw JUnit under ignored `target/nextest`; the lane requires that
report and reduces it to allowlisted suite/test/status structure. Captured
stdout/stderr, failure bodies and messages, timestamps, UUIDs, and unknown XML
elements cannot enter `.ci-artifacts/junit/`; a secret-shaped canary proves the
redaction. Hosted CI uploads only that structural report and the unsigned
observation, never raw provider or credential-bearing logs.

## Hosted controls

The required workflow runs on `pull_request`, `push`, and `merge_group` without
path filters. Only superseded pull-request runs are cancelled. Every checkout
uses `contents: read` and `persist-credentials: false`; no cache is configured;
Rust is 1.97.1 and every action/tool is pinned. A dedicated preflight scans the
current source and `Cargo.lock` before any project dependency installation.

The scheduled workflow adds external-link, advisory/supply-chain, standalone
coverage, full-history secret, and `macos-15`/`windows-2025` compile-plus-typed-
refusal jobs. Those platforms are read-only: Linux is the only future
mutation-capable platform, and family mutation is not registered here.

Each hosted lane emits `bullet.ci-observation.v1` through
`scripts/ci-observation.sh`: commit/tree OIDs, checkout cleanliness, exact
command, tool versions, lane outcome, and hashes of sanitized artifacts. It is
always `signed: false` and `DIAGNOSTIC_ONLY`; it is neither Bullet Evidence nor
a release receipt.

`ci.toml` is an inactive Jeryu-native mirror of the same five local commands.
It does not activate a runner, badge, ruleset, release, or protected context.
That activation remains gated on forge/public-mirror ratification and API
read-back.
