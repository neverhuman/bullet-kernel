# Jankurai Standard Binding

Standard version: `0.9.0`
Target stack: Rust control plane, generated contracts, SQLite adapters.

- `crates/domain` is pure: no filesystem, env, DB, HTTP, or clocks that mutate.
- SQL lives in `crates/adapters` and `db/migrations`.
- Public HTTP shapes are generated from `contracts/openapi.yaml`.
- No Python product truth. No writable Git worktrees.
- Split files before 500 LOC.
