#!/usr/bin/env bash
# Security lane: secret scan plus dependency bans. Missing tools fail closed.
# License gating needs a committed deny.toml policy before it can be enforced.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "security lane"
require_tool gitleaks || exit 1
require_tool cargo-deny || exit 1
gitleaks detect --source . --no-git --redact --no-banner
cargo deny check bans
log "security lane passed"
