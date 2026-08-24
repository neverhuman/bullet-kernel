# bullet-kernel

Control-plane modular monolith for Bullet Farm.

```text
crates/domain        IDs, tokens, state machines, taxonomy — no I/O
crates/application   commands, materializer, leases/fences, demo
crates/adapters      SQLite WAL ledger, simulators
apps/bullet-farmd    HTTP + SSE daemon
apps/bullet          CLI (demo, contracts generate|check)
apps/bullet-runner   trust-boundary stub
apps/bullet-verifier trust-boundary stub
apps/bullet-effects  trust-boundary stub
```

```bash
just setup
just fast
BULLET_DATA_DIR=./target/demo cargo run -p bullet -- demo
```

The demo receipt is re-derived from ledger rows on every run and proves the
permanent fence advanced (fence 1, then fence 2 on the same variant), that a
stale heartbeat and stale token are refused, and that a lost SCM response is
recorded as an unknown outcome rather than a success.

The portal is a projection of this API. It is never an authority source.
