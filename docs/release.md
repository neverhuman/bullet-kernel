# Release contract

Status: **no release exists; every release gate is BLOCKED**
Owner: bullet-kernel maintainers (`agent/owner-map.json`)
Last reviewed: 2026-08-26
Applies to: bullet-kernel

This page is a fail-closed contract, not a plan of record. Nothing in this
repository has been released, and no lane in `ops/ci/` may publish, tag, mirror,
sign, or otherwise mutate forge state. A green component lane is never a
release, and this page never becomes evidence that one happened.

## Version source

`agent/standard-version.toml` binds the standard, paper, auditor and schema
versions this component claims. Crate versions live in `Cargo.toml` and the
locked graph in `Cargo.lock`; every lane runs `--locked`. The database schema
has its own version source: the checksummed migration set in `db/migrations`,
reduced to `schema_contract_digest()` by
`crates/adapters/src/sqlite/migrations.rs`. There is no published crate, tag or
artifact, so there is no version for anyone to consume yet.

## Change record

`CHANGELOG.md` carries the unreleased change record. It may never gain a
released version heading before the gates below hold with receipts.

## Launch gate inventory

A release gate closes only with an artifact-backed receipt from an independent
checker. Today every gate is BLOCKED. The honest status of each:

| Release gate | Required evidence | Status |
| --- | --- | --- |
| Component proof | `bash scripts/ci-local.sh required` green on the release commit (fast, lint, contract, security, docs) | available locally; a local green is not release evidence on its own |
| Conformance score | `bash ops/ci/audit.sh` at or above the upward-only `AUDIT_FLOOR` ratchet | local gate only: the pinned auditor is a machine-local build and is not registered in hosted CI, so no workflow may claim it ran |
| Secret and dependency scan | `bash scripts/ci-local.sh security`: `gitleaks detect`, `cargo deny --locked check licenses advisories bans sources` against the committed `deny.toml`, `zizmor --offline --no-ignores --strict-collection .`, and an independent freshness proof of the RustSec advisory database | runs and fails closed; it produces no release artifact |
| Integrity and provenance | checksums, signatures and an SBOM for a published artifact | BLOCKED: nothing is built for publication, so nothing is signed. Internally `schema_contract_digest()` is embedded in every backup receipt, which is integrity evidence for the database, not for a release |
| Backup and restore | a restore drill against a real database | implemented and tested offline: `crates/adapters/src/sqlite/backup.rs` takes a receipt-bound copy (`PRAGMA integrity_check` plus the schema digest) and restores it quarantined. BLOCKED as a release gate: no drill has been run against production data, because there is no production |
| Rollback | a rehearsed rollback procedure | there is no down-migration and there deliberately never will be one pre-1.0. Rollback is restore-from-verified-backup; a physically restored database refuses every operation with `RESTORE_ADMISSION_REQUIRED` until admitted, and no production admission path exists in V1. Implemented in code, unproven as a procedure |
| Monitoring | telemetry, dashboards and alerts | BLOCKED: none exist. What exists is typed reason codes on every failure (`reason_code()`, pinned by `reason_codes_are_stable`), the observation projections the daemon serves, and the fail-closed egress receipts in `crates/harness-egress/src/receipt.rs`. That is structured evidence a human can read, not monitoring |
| Abuse and rate limits | a rate-limited, authenticated public surface | no public surface exists to rate limit. What is bounded today: writer leases are capped to 1..=15 seconds (`db/migrations/0005_lease_ttl.sql` plus `DomainError::InvalidLeaseTtl`), fences refuse reuse, provider egress is default-deny through the allowlist and in-namespace nftables ruleset (`crates/harness-egress`, `docs/egress-isolation.md`), and the authority gateway is fail-closed |
| Live provider oracle | a green live-conformance run against real provider binaries | BLOCKED: the checked-in `v1alpha1` policy refuses at `POLICY_LIVE_ADMISSION_DISABLED`; even a valid v1alpha2 policy reaches `RUNTIME_PROBE_UNAVAILABLE` in every production adapter before spawn. `ops/ci/nightly.sh` exits 78 for either typed refusal. Exit 78 is neutral, never green |

## Rules

- Release builds depend on immutable tags, not branches.
- Lanes never publish, mirror, tag, push, or touch Jeryu.
- A skipped, missing, unsupported, flaky or `UNKNOWN` result is never success,
  and exit 78 is not green.
- Never edit an applied migration to make a release build pass; add the next
  numbered one (`db/AGENTS.md`).
