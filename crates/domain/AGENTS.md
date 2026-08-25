# crates/domain

Owner `domain` (`agent/owner-map.json`). The pure typed core: identities,
states, gates, fences, the mutation guard, observation, the behavior taxonomy
and `DomainError`. Every value here is reproducible from its inputs alone.

- No I/O of any kind: no filesystem, env, process, network, SQL, RNG or
  mutating clock. The exact forbidden import list is `agent/boundaries.toml`
  (`[rust] forbidden_domain_imports`). Durable writes belong in
  `crates/adapters`, effects in `crates/effects`.
- `src/schema_bundle.rs` is a generated, hub-synced zone
  (`agent/generated-zones.toml`). Never hand-edit it; repair it from
  `bullet-farm` with the recorded sync command.
- Every error variant carries a stable `reason_code()`. Those strings are a wire
  contract shared with bullet-git, the runner, the daemon and the portal.
  `tests/invariants.rs::reason_codes_are_stable` pins them; changing one is a
  contract change, never a rename.
- Proof lane: `bash scripts/ci-local.sh fast`. Unit and property tests live in
  `tests/`.
