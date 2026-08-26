#!/usr/bin/env bash
# Canonical security-lane wrapper for bullet-kernel.
#
# The executable lane is ops/ci/security.sh; this wrapper is the stable entry
# point that names the tools the lane runs so a reader (human or agent) does not
# have to reconstruct them from the workflow. It adds no policy of its own and
# it never downgrades a failure: it execs the lane and inherits its exit code.
#
# Tools, all fail-closed (`require_tool` exits non-zero when one is absent, so a
# missing scanner can never produce a green lane):
#   gitleaks detect --source . --no-git --redact --no-banner
#   cargo deny --locked check licenses advisories bans sources   (committed deny.toml)
#   zizmor --offline --no-ignores --strict-collection .          (workflow bytes)
# The lane also proves the RustSec advisory database is present, readable and
# newer than 14 days before it trusts `cargo deny check`, because cargo-deny
# 0.19.8 reports a failed `git fetch` as success.
#
# Declared in agent/security-policy.toml. Do not add `|| true` to any step.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/ops/ci/security.sh"
