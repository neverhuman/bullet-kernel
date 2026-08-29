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
| standalone | 747 | all component tests outside the provider-contract/simulation, egress, and family partitions; every selected identity executes with zero skipped, including the explicitly feature-enabled verifier fixture tests |
| egress | 3 | the exact host-dependent namespace/nftables/CONNECT-proxy identities; only the capability-admitted `egress` lane executes them |
| contract | 34 | four offline provider protocol binaries plus `bullet-test-simulation` |
| family | 9 | five `transaction_demo` identities plus `heartbeat_stale`, `kill_retry`, `loop_sim`, and `synthetic_e2e` |
| total | 793 | exact union of the four disjoint partitions above |

`ops/ci/inventory-test.sh` independently lists all four partitions, requires
every set to be nonzero, checks pairwise disjointness and exact union,
digest-binds all identities, locks the nine family and three egress identities, and
scans test sources for every `bullet-gitd` resolution site. A new, removed,
renamed, ignored, or silently reclassified test makes `lint` fail until the
inventory is reviewed.

Every partition list and execution supplies
`--features bullet-verifier/fixture-executor`. The feature exposes six
component-only fixture process identities that otherwise disappear from Cargo's
default workspace inventory; it does not change the default product verifier,
which remains a constant fail-closed refusal.

`bash scripts/ci-local.sh egress` performs host admission, then runs exactly:

```bash
cargo nextest run --locked --workspace --features bullet-verifier/fixture-executor --run-ignored all --no-tests fail -E "$EGRESS_FILTER"
```

`EGRESS_FILTER` is the three-name expression digest-bound in
`ops/ci/inventory.sh`. Missing tools or unavailable unprivileged namespaces
produce typed neutral 78; green means all three selected probes actually ran.

`fast`, `contract`, and coverage remove both daemon path and digest variables.
Product resolution has no sibling or sentinel fallback and returns typed
`GITD_BINARY_UNPROVISIONED` or
`GITD_BINARY_ADMISSION_REFUSED` before constructing a child command. The
family lane is separate and fail-closed:

```bash
BULLET_GITD_BIN=/canonical/absolute/path/to/bullet-gitd \
BULLET_GITD_SHA256=<lowercase-sha256> \
  bash scripts/ci-local.sh family
```

The path must already be canonical, name a non-symlink regular executable, and
exist. The runner streams the admitted native ELF into a bounded memfd, verifies
its exact SHA-256, seals writes/growth/shrinkage, reads the seals back, and
executes only that immutable Linux procfd; the wrapper separately checks the
source digest immediately before and after the family partition. The path and
digest are caller-declared component self-consistency, not authenticated
provenance or release authority. The lane never falls back to
`../bullet-git/target/...`. Family CI remains blocked
until the Hub can provision immutable authenticated repository subjects and
pass the exact daemon path.

The first self-dogfood loop is an explicit local component lane:

```bash
BULLET_GITD_BIN=/canonical/absolute/path/to/bullet-gitd \
BULLET_GITD_SHA256=<lowercase-sha256> \
  just proof-synthetic-dogfood
```

It builds default-off debug seams from locked offline dependencies, starts
peer-authenticated farmd authority, and runs two sequential fresh simulator
participants against one plan/base. Each author participant has a distinct
logical Runner, Variant, Attempt, workspace, recovery journal, raw transcript,
and reconstructed Candidate. A private selector sees only blinded content
subjects and a frozen non-quality tiebreak. The selected result is sealed back
to the create-once selection receipt, exact winning handle, Candidate row,
repository, author authority, plan graph, package, Variant, base, gates, and
scope before any effect work begins.

The selected component path then executes this exact order:

1. A third logical Runner obtains a fresh synthetic writer lease for the
   selected Variant at successor fence 2; neither terminal author lease is
   reused.
2. Fixture keys sign and reverify the exact verification intent, PASS Evidence,
   and proof bundle after the author-as-verifier path is refused.
3. A local-bare Candidate-ref push deliberately loses its response. The effect
   remains `UNKNOWN` until authoritative ref read-back adopts the exact head.
4. The local forge publishes and reads back a proof-root-bound check at the
   exact Candidate SHA, performs protected integration with the expected old
   OID, emits and reverifies a fixture-signed observation, and matches the
   check, protection, and target again after reopen.
5. The third Attempt settles terminal `Superseded`, and a second create-once
   canonical receipt binds the sealed selection, verification, delivery,
   reconciliation, check, integration, observation, settlement, and their
   durable rows. It retains the exact canonical selection-receipt bytes and
   decode-time replay derives both author grants, blinded views, the exact
   unblinding pair, selection decision, and winning Candidate.

The wrapper rejects credential-bearing environments before Cargo and runs the
subjects under `env -i`. Its fault campaign retains the five original author/
selection cells and adds `effect-grant-changed`,
`effect-grant-readback-error`, `after-delivery-unknown`,
`before-effect-receipt`, and `after-effect-receipt`, for ten named cells total,
plus the applicable ordinary chaos boundaries
`verifier-handoff`, `candidate-delivery`, `check-publication`, `integration`,
and `observation-cleanup`. It checks which of the two receipts may exist at
each boundary, terminal lease/Attempt truth, exact ledger/ref/check/target
subjects, replay immutability, and retained artifact digests. The two grant
read-back faults execute after acquire and prove cleanup leaves three terminal
Attempts, three distinct logical Runners, no active lease, and no premature
effect intent or receipt. The wrapper independently derives the framed
selection artifact/body digests and proves the final receipt's retained hex
decodes byte-for-byte to that exact selection artifact.

Both receipts remain `COMPONENT_PROOF` with `UNSIGNED_FIXTURE` trust. Shell
rehashing and retained-path inspection are cooperative same-UID checks, not
adversarial custody. The three Runners are logical identities in one fixture
security context; verifier, broker/delivery, attestor/check, integrator, and
observer do not have distinct service/OS identities. There is no
`DeliveryGrant`, `CheckGrant`, or `IntegrationGrant`, and the fixture-signed
records are not independently anchored Evidence.

The response-loss case is only reconciled while this process remains alive.
An interruption after the remote ref changes but before read-back has no
durable resumable effect claimant; that state is `ORPHANED_REMOTE`, never an
implicit retry or PASS. Independent-Evidence, transaction, five-plane,
provider-certification, team-recipe, evolution-profile, live, release,
routing-activation, comparative, and restart-recovery eligibility are all
hard-false. This lane accelerates local component dogfood mechanics; it clears
no transaction, release, or profile gate.

The standalone live-conformance tests keep positive PONG mechanics behind a
strict `cfg(test)` observed-subject wrapper. A separate valid-v1alpha2 test
uses the real Claude adapter and proves `RUNTIME_PROBE_UNAVAILABLE` leaves the
operator-key, Mission/graph, lease, nonce, egress, and child-process surfaces
untouched. The product CLI test tables all four selectors against the same
typed `ADMISSION` refusal. These are fail-closed component proofs, not runtime
provider conformance.

## Atomic lanes

| Lane | Scope |
| --- | --- |
| `fast` | exactly 747 standalone nextest identities, all executed with zero skipped |
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
