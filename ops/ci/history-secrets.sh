#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool git || exit 1
require_tool gitleaks || exit 1
require_exact_output "8.21.2" gitleaks version
[[ "$(git rev-parse --is-shallow-repository)" == "false" ]] \
  || { refuse HISTORY_SCAN_SHALLOW "full Git history is required"; exit 1; }
gitleaks git --redact --no-banner --log-opts=--all .
log "full-history secret scan passed"
