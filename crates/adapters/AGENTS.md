# crates/adapters

Owner `adapters` (`agent/owner-map.json`). The SQLite ledger, the migration
runner, backup and quarantined restore, and the projections the daemon serves.
This is where durable truth is written.

- All SQL lives here and in `db/migrations`. `crates/domain` and
  `crates/application` never touch a connection.
- `src/sqlite/migrations.rs` is the schema authority: it `include_str!`s and
  checksums every file in `db/migrations`, and verifies the metadata table,
  applied migrations, product schema, foreign-key integrity and the identity
  contract on every open. Never repair a checksum mismatch by editing an
  existing migration; add the next numbered one. The posture is declared in
  `db/migrations/meta.toml`.
- A physically restored database stays quarantined and refuses work with
  `RESTORE_ADMISSION_REQUIRED`. Do not add a bypass.
- `tests/fixtures/formal/` is a hub-synced generated zone
  (`agent/generated-zones.toml`); do not hand-edit it.
- Proof lane: `bash scripts/ci-local.sh required`.
