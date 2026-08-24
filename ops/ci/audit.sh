#!/usr/bin/env bash
# Jankurai audit lane. Writes .jankurai/repo-score.{json,md}; hosted CI uploads them.
# AUDIT_FLOOR is a ratchet: it may only rise. Missing auditor fails closed.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
AUDIT_FLOOR=57
require_tool jankurai || exit 1
mkdir -p .jankurai
log "audit lane: jankurai audit (floor ${AUDIT_FLOOR})"
jankurai audit . --no-score-history --fail-under "$AUDIT_FLOOR" --fail-on critical \
  --json .jankurai/repo-score.json --md .jankurai/repo-score.md
[[ -f .jankurai/repo-score.json ]] || { echo "[ci] audit artifact missing" >&2; exit 1; }
log "audit lane passed"
