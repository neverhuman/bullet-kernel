# crates/application

Owner `application` (`agent/owner-map.json`). Use cases and ports: the store
trait, lease transport, launch-grant issuance and live-conformance decisions.
It orchestrates `crates/domain` and talks to adapters only through traits.

- Depends on `crates/domain`; it must not depend on a concrete adapter, on
  `rusqlite`, or on a specific transport. Anything that opens a socket or a file
  belongs in `crates/adapters` or `crates/effects`.
- Failures are typed and carry `reason_code()`; keep those strings stable.
- A launch grant is issued only against a current, non-stale authority subject;
  do not add a path that mints one without that check.
- Proof lane: `bash scripts/ci-local.sh fast`, then
  `bash scripts/ci-local.sh required` before handing off.
