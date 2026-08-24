# bullet-kernel

Control-plane modular monolith for Bullet Farm.

```text
crates/domain        IDs, tokens, state machines, taxonomy — no I/O
crates/application   commands, materializer, leases, demo
crates/adapters      SQLite WAL, CAS, simulators
apps/bullet-farmd    HTTP + SSE daemon
apps/bullet          CLI
apps/bullet-runner   trust-boundary stub
apps/bullet-verifier trust-boundary stub
apps/bullet-effects  trust-boundary stub
```

```bash
just setup
just fast
BULLET_DATA_DIR=./target/demo cargo run -p bullet -- demo
```

The portal is a projection of this API. It is never an authority source.
