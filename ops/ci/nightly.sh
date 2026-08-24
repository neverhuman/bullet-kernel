#!/usr/bin/env bash
# Live harnesses. Skip (do not fail) when binaries or creds are missing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_HARNESS:-}" ]]; then
  log "BULLET_LIVE_HARNESS unset; skip live adapters"
  exit 0
fi
log "live harness requested; no adapters implemented yet"
exit 0
