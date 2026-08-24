# Kernel architecture

`crates/domain` is pure. `crates/application` owns transitions. `crates/adapters`
owns SQLite and simulators. `apps/bullet-farmd` is the HTTP edge.
