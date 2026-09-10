# Operator read authentication

Status: component implementation; production admission remains incomplete.

All mounted `/api/v1` GET and HEAD requests require the `bullet_session`
cookie issued by `POST /api/v1/auth/bootstrap`. Authentication runs before
path/cursor parsing or ledger access, including mission, readiness, outbox,
command, projection and SSE reads. A supplied Origin must exactly match
the configured Portal origin. Reads require no CSRF token; command mutations
retain their exact Origin, cookie and session-bound CSRF checks.

`/health`, `/openapi.yaml` and the embedded Portal's static assets remain
public. Starting a router without a new bootstrap token retains existing
durable session authority; it cannot issue a new session. A worker bearer or bootstrap token does not substitute for an operator
session. An absent session returns `401 SESSION_REQUIRED`; malformed,
duplicate, expired, revoked or foreign cookies return `401 SESSION_INVALID`.
An unacceptable supplied Origin returns `403 ORIGIN_DENIED`.

Authenticated read responses use `Cache-Control: no-store`. SSE checks the
opening session before each buffered event and polling iteration and closes
when that session expires or is revoked. An idle connection notices this
on its next poll (currently 500 ms). Reconnecting must authenticate again and
provide the last received sequence for bounded replay. Closing a client
connection does not mutate work or terminate provider processes.

After authentication and replay preflight, SSE immediately sends a `connected`
comment. This flushes empty streams through buffering proxies before the
Portal's 10-second header deadline; the default 15-second keepalive arrives too
late for that deadline. The comment carries neither event data nor an id and
does not advance the cursor or write a ledger event. Subsequent frames retain
the session-lifetime checks above.

Operator sessions persist in SQLite with absolute eight-hour expiry, an immutable
local operator identity, session-specific bearer/CSRF digests and restore epoch.
Only digests enter the store. Restart preserves valid sessions and does not
renew a bootstrap token's ten-minute lifetime or reopen a consumed token.
A fresh bootstrap can issue an independent client session for the same local
operator. Every authorization check consults the current database; revocation
from another daemon connection is visible to subsequent reads and stream polls.

`GET /api/v1/auth/session` returns the operator/session identities and absolute
issue/expiry times. `POST /api/v1/auth/revoke` requires the exact Origin, cookie,
its CSRF token, and an empty JSON object. It durably revokes only that session,
expires its browser cookie, and returns a nonsecret acknowledgement. Both
responses use `Cache-Control: no-store`; neither contains credential digests,
bearer tokens or CSRF tokens. Bootstrap retains its existing CSRF response.

Migrations 24 and 25 are append-only. Known schemas 22, 23 and 24 require a separately
supervised upgrade; startup never upgrades them automatically. Restore
quarantine and a changed restore epoch refuse prior authority. These component
changes do not admit an installed upgrade or enable live execution. Operator
identity is durable. New public commands bind that identity atomically with
command/outbox/audit/admission effects. Historical unowned commands stay
preserved and cannot be adopted through retry; their public status is absent.

`GET /api/v1/commands` recovers owned command statuses after local cache loss.
Its optional `after` cursor is an immutable submitted-event sequence; `limit`
is 1..100 (default 50). Canonical decimal parameters must be unique and known.
Pages share an atomic ledger snapshot and stop below a 7 MiB serialized budget;
follow `next_after` until null. Public command status and exact retry validate
the same command/outbox/claim/audit and original nonce/reservation bindings.
A retry returns the original command's current phase after authority movement
without new admission or duplicated quota. UNKNOWN reservations remain held;
this is not provider completion or actual quota settlement. Other shared farm
projections retain their existing authenticated operator access policy.

Implementation: [`auth/read.rs`](../apps/bullet-farmd/src/auth/read.rs),
[`auth.rs`](../apps/bullet-farmd/src/auth.rs),
[`api.rs`](../apps/bullet-farmd/src/api.rs). Contract:
[`openapi.yaml`](../contracts/openapi.yaml). Component checks:
[`read_auth.rs`](../apps/bullet-farmd/tests/read_auth.rs),
[`durable_auth.rs`](../apps/bullet-farmd/tests/durable_auth.rs),
[buffered/idle stream tests](../apps/bullet-farmd/src/auth/read/tests.rs),
[adapter restart/race tests](../crates/adapters/tests/operator_sessions.rs),
[immutability and expiry tests](../crates/adapters/src/sqlite/operator_sessions/tests.rs),
and [corrupt-row/restore tests](../crates/adapters/src/sqlite/operator_sessions/tests/corruption.rs).
The existing command-authentication and projection regressions still apply.
These tests use synthetic sessions and local sockets and establish
`COMPONENT_PROOF` only; they are not production campaign evidence.

Command recovery component evidence: [adapter owner tests](../crates/adapters/src/sqlite/operator_commands/tests.rs),
[binding/corruption and concurrent reads](../crates/adapters/src/sqlite/operator_commands/tests/corruption.rs),
[large-page continuity](../crates/adapters/src/sqlite/operator_commands/tests/page_bytes.rs),
and [real HTTP response-loss/restart tests](../apps/bullet-farmd/tests/operator_commands.rs).
Synthetic component dispatch can establish UNKNOWN only; these tests do not
establish successful native coding or production campaign execution.
