# db

Owner `data` (`agent/owner-map.json`). The exact, checksummed SQLite schema.

- `migrations/` is append-only. Never edit an applied migration: every file is
  `include_str!`ed and checksummed by
  `crates/adapters/src/sqlite/migrations.rs`, so an edit makes every existing
  database fail `verify_applied_migrations` instead of upgrading. Add the next
  numbered file.
- `migrations/meta.toml` declares the ownership, approval, timeout, rollback and
  verification posture for this directory. Keep it accurate when you add a
  migration; it is read by the audit lane and by the next agent.
- SQLite is embedded and single-writer. There is no `lock_timeout` or
  `statement_timeout`: the bound is `busy_timeout(5s)` set by the adapter when
  it opens the connection.
- There is no down-migration. Rollback is a restore from a verified backup
  receipt (`crates/adapters/src/sqlite/backup.rs`), and a restored database
  stays quarantined until admitted.
- Proof lane: `bash scripts/ci-local.sh required`
  (`crates/adapters/src/sqlite/migrations/tests.rs`).
