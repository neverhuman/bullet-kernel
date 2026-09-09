#!/usr/bin/env bash
# Hosted dependency jobs depend on this source/lockfile scan. It installs no
# project dependency and runs before any Rust toolchain or Cargo fetch step.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool git || exit 1
require_tool gitleaks || exit 1
require_exact_output "8.21.2" gitleaks version
[[ -s Cargo.lock ]] || { refuse LOCKFILE_ABSENT "Cargo.lock is missing or empty"; exit 1; }
git diff --check
scan_current_source_secrets
bash ops/ci/workflow-policy.sh
log "preflight passed before dependency installation"
