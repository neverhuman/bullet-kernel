#!/usr/bin/env bash
# Jankurai audit lane. Writes .jankurai/repo-score.{json,md}; the hosted
# scheduled `audit` job uploads only the unsigned observation of this lane.
# AUDIT_FLOOR is a ratchet: it may only rise. Missing auditor fails closed:
# locally that is exit 1; on a hosted runner (GITHUB_ACTIONS=true), where the
# pinned 1.6.11 binary is a machine-local build with no checksum-pinned
# artifact, it is the typed neutral exit 78 AUDITOR_UNAVAILABLE_HOSTED, like
# the egress lane. Neither path is ever green without the audit running.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
AUDIT_FLOOR=57
if ! command -v jankurai >/dev/null 2>&1; then
  if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    log "neutral (78): AUDITOR_UNAVAILABLE_HOSTED: jankurai 1.6.11 is a machine-local build with no checksum-pinned hosted artifact; the audit did not run"
    exit 78
  fi
  refuse AUDITOR_MISSING "jankurai is not on PATH; the audit lane fails closed"
  exit 1
fi
mkdir -p .jankurai
log "audit lane: jankurai audit (floor ${AUDIT_FLOOR})"
jankurai audit . --no-score-history --fail-under "$AUDIT_FLOOR" --fail-on critical \
  --json .jankurai/repo-score.json --md .jankurai/repo-score.md
[[ -f .jankurai/repo-score.json ]] || { echo "[ci] audit artifact missing" >&2; exit 1; }
log "audit lane passed"
