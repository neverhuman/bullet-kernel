# Changelog

All notable changes to bullet-kernel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project is
pre-release: there is no published version, tag or artifact, and no released
heading may be added before the gates in `docs/release.md` hold with receipts.

## [Unreleased]

### Added

- Jankurai control plane for this component: `agent/audit-policy.toml`,
  `agent/boundaries.toml` and `agent/tool-adoption.toml`. The audit report now
  carries a real `policy_fingerprint` instead of `sha256:0000…`.
- `tools/security-lane.sh`, the canonical security-lane wrapper that delegates
  to `ops/ci/security.sh` and names the tools the lane runs.
- `scripts/ci-doctor.sh`, the local environment check that lists and pins every
  tool the `ops/ci` lanes depend on.
- `ops/git-hooks/pre-push`, the mandatory local pre-push gate
  (`git config core.hooksPath ops/git-hooks`).
- `db/migrations/meta.toml`: the ownership, approval, timeout, rollback and
  verification posture of the migration set, declared where the audit lane and
  the next agent read it. No migration byte changed.
- Local `AGENTS.md` guidance for the `domain`, `application`, `adapters`,
  `contracts` and `db` cells.
- `docs/release.md` (fail-closed release contract) and this changelog.

### Changed

- `agent/generated-zones.toml` now declares a reproducible `command` for every
  zone, and records in a comment why `contracts/schemas/patch-proposal.json` is
  deliberately not declared as one: it is hand-written, it has no generator, and
  what keeps it honest is `schema_and_authoritative_struct_agree` in
  `crates/harness-core/src/proposal.rs`.
- `agent/JANKURAI_STANDARD.md` now documents the typed exception surface —
  purpose, stable reason code, common fixes, repair hint and docs route — so a
  failure routes a repair without reading a log.

### Removed

- `agent/zyal/`: a ZYAL v1 runbook is a `RUN_FOREVER` daemon envelope and this
  component has no run-forever agent loop, so the three-line stub was not a
  runbook and was removed rather than faked into one.

[Unreleased]: https://github.com/neverhuman/bulletfarm
