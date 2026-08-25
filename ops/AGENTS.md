# bullet-kernel operations

CI entrypoints live in `ops/ci/` and are exposed by `scripts/ci-local.sh <lane>`
and the `Justfile`. Every lane is one script; hosted CI and local runs execute
the same file.

| Lane | Script | Hosted (`.github/workflows/ci.yml`) | Exit contract |
| --- | --- | --- | --- |
| `fast` | `ops/ci/fast.sh` | yes | fmt, nextest `fast`, `contracts check` |
| `required` | `ops/ci/required.sh` | yes | fast + `ops/ci/nightly-test.sh` + clippy `-D warnings` |
| `contract` | `ops/ci/contract.sh` | yes | nextest `contract` + `bullet-test-simulation`; offline |
| `security` | `ops/ci/security.sh` | yes | gitleaks + `cargo deny check bans`; missing tool fails |
| `audit` | `ops/ci/audit.sh` | no (local) | Jankurai, ratchet floor `AUDIT_FLOOR`; missing auditor fails |
| `egress` | `ops/ci/egress.sh` | no (local) | live namespace/nft/proxy proofs; 78 neutral when tools or user namespaces are missing |
| `nightly` | `ops/ci/nightly.sh` | no (local) | per-provider refusal test + positive half; 78 when `BULLET_LIVE_PROVIDERS` is unset; real mode needs `BULLET_LIVE_REAL=1` and an absolute `BULLET_POLICY_PATH` |

`ops/ci/lib.sh` supplies `log`, `require_tool`, and `run_tests <profile>`;
`ops/ci/nightly-test.sh` is the meta-test that pins the nightly wrapper's exact
`cargo` calls and both modes. Edits under `ops/` are routed to `just check` by
`agent/test-map.json`. Lane semantics are documented in `README.md#lanes`.
