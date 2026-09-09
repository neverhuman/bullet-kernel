# Bullet Farm MCP boundary

Status: read-only component; not live or release evidence  
Last reviewed: 2026-08-25

`bullet-mcpd` is a stdio Model Context Protocol server for inspecting the
existing Kernel projections. It uses the official Rust MCP SDK and exposes
only fixed GET routes on one numeric loopback farmd address. Every result is
the exact public snapshot envelope:

```json
{"data":{},"as_of_sequence":0,"observed_at":"…","source":"bullet-kernel/sqlite-ledger"}
```

The adapter checks the body fields, source, and equality between
`as_of_sequence` and `X-Bullet-As-Of-Sequence`. Unavailable, malformed,
oversized, or conflicting responses are typed tool errors. They never become
an empty projection, PASS, VERIFIED, FAILED, or evidence.

## Run

Start `bullet-farmd`, then configure an MCP client to launch:

```bash
cargo run --locked -p bullet-mcpd -- \
  --farmd-url http://127.0.0.1:7420
```

The endpoint must be `http://` plus an explicit numeric loopback address and a
nonzero port. Hostnames, TLS, credentials, paths, redirects, arbitrary URLs,
and non-loopback addresses are refused. Standard input/output is newline-
delimited MCP JSON-RPC; stdout is protocol-only and diagnostics use stderr.

The server pins exact `rmcp` 3.1.4 in `Cargo.toml` and `Cargo.lock`; that SDK
source implements MCP 2026-07-28 and compatible initialization-era clients.
Incoming frames are limited to 1 MiB before the
SDK parser, farmd connection time is one second, the full read deadline is five
seconds, headers are limited to 16 KiB, decoded `application/json` projection
bodies to 256 KiB, and total response wire bytes to 512 KiB. EOF or an
oversized frame closes the process.

## Exposed tools

- `bullet_missions`, `bullet_mission`
- `bullet_fleet`, `bullet_sessions`, `bullet_context_lineage`
- `bullet_merge_rail`, `bullet_quality_lab`, `bullet_audit`

All eight carry MCP read-only, non-destructive, idempotent, closed-world
annotations. Their paths are compiled in; tool input cannot select another
endpoint.

## Authority boundary

`bullet-mcpd` never:

- accepts or mints a Kernel capability;
- submits or reconciles a command;
- acquires, renews, releases, or supersedes a lease/fence;
- reads or writes a Git repository or calls BulletGit;
- starts a provider or verifier;
- holds SCM, provider, Jeryu, GitHub, or GitLab credentials;
- dispatches or adopts an effect;
- labels any observation PASS or VERIFIED.

There is intentionally no `bullet_submit_command` tool. Today the public
command endpoint is protected by the browser's one-time bootstrap, HttpOnly
session, exact Origin, and session-bound CSRF token. The internal worker bearer
is reconciliation-only. Reusing either as an MCP machine identity would
collapse the browser/automation boundary.

## Gate for command tools

A later command tool is permitted only after all of these land together:

1. farmd defines an independently scoped MCP principal, held as a protected
   file or OS handle—not argv or ambient environment—and authorizes only the
   generated public command DTO;
2. the Rust DTO/client is generated from `contracts/openapi.yaml`; the adapter
   does not copy private handler structs or construct authority claims;
3. `POST /api/v1/commands` still returns `202 PENDING`; MCP transport success is
   not application or verification success;
4. loss of the submission response becomes `UNKNOWN`. The adapter reconciles
   the exact command/idempotency key with `GET /api/v1/commands/{id}` and never
   automatically submits a second write;
5. only durable `VERIFIED` may be rendered as verified. `PENDING`, `APPLIED`,
   `FAILED`, and `UNKNOWN` remain distinct;
6. mutation tests cover missing/wrong/expired/replayed principal, changed
   command fields, duplicate idempotency, farmd outage, response loss, and
   restart, with zero unauthorized state change.

Until that gate passes, MCP is an observation adapter only. Its tests are
`COMPONENT_PROOF`; they advance no transaction, live-adapter, or release gate.
