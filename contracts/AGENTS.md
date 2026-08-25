# contracts

Owner `contracts` (`agent/owner-map.json`). The public wire surface.

- `openapi.yaml` is the source of truth for the HTTP API. `generated/` is
  emitted from it and is a `generator_only` zone in
  `agent/generated-zones.toml`: never hand-edit a file under `generated/`,
  regenerate it and prove it with `bash ops/ci/contract.sh`.
- `schemas/patch-proposal.json` is deliberately hand-written and is deliberately
  not declared in `agent/generated-zones.toml`: there is no generator to declare,
  and the auditor is right to report it as a handwritten contract. Its
  authoritative Rust binding is
  `crates/harness-core/src/proposal.rs`, which embeds the exact bytes through
  `schema_source()`; `schema_and_authoritative_struct_agree` proves the two
  still match. Change the schema and the struct together, in one change, with
  that test green.
- Reason codes and other protocol strings are contract, not vocabulary. Renaming
  one breaks bullet-git, the runner, the daemon and the portal.
- Proof lane: `bash scripts/ci-local.sh contract`.
