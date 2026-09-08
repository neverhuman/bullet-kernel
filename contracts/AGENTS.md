# contracts

Owner `contracts` (`agent/owner-map.json`). The public wire surface.

- `openapi.yaml` is the source of truth for the HTTP API. `generated/` is
  emitted from it and is a `generator_only` zone in
  `agent/generated-zones.toml`: never hand-edit a file under `generated/`,
  regenerate with `cargo run --locked -p bullet --bin bullet -- contracts generate` and
  check drift with `cargo run --locked -p bullet --bin bullet -- contracts check`.
- `schemas/patch-proposal.json` is hand-written and declared `reviewed_manual`
  in `agent/generated-zones.toml`. It has no generator and remains authored
  source for audits. Its authoritative Rust binding is
  `crates/harness-core/src/proposal.rs`, which embeds the exact bytes through
  `schema_source()`. The exact mapped test checks required keys, closed
  top-level properties and the operations/gates item limits; it does not prove
  complete semantic equivalence. Change the schema and the struct together,
  with that test green and independent review of the affected constraints.
- Reason codes and other protocol strings are contract, not vocabulary. Renaming
  one breaks bullet-git, the runner, the daemon and the portal.
- The separate protocol proof lane is `bash scripts/ci-local.sh contract`.
