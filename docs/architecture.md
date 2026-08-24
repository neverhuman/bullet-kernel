# Kernel architecture

`crates/domain` is pure: ids, Authority Tokens, and the spec section 24
state machines. `crates/application` owns transitions, the `Ledger` port
(single-transaction lease acquisition, six-column heartbeat, expiry,
outbox), the pure simulators, and the demo. `crates/adapters` owns SQLite
(WAL, `schema_version` migrations, typed authority tables). Both ledger
implementations pass one shared conformance suite.

`apps/bullet-farmd` is the HTTP + SSE edge; errors are typed problem
details with stable reason codes. `contracts/openapi.yaml` is the contract
source of truth; `bullet contracts generate` emits
`contracts/generated/api.ts` and `bullet contracts check` gates CI.

Content-addressed artifact storage is not implemented.
