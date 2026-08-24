#!/usr/bin/env bash
# Registered live-adapter lane. BULLET_LIVE_PROVIDERS unset: neutral, nothing registered.
# Set (comma list of claude,codex,cursor,agy): each named CLI must exist and its live smoke
# test must pass; a missing tool or a refused spawn fails closed instead of skipping.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_PROVIDERS:-}" ]]; then
  log "BULLET_LIVE_PROVIDERS unset; no live lane registered"
  exit 0
fi
status=0
IFS=',' read -ra providers <<< "$BULLET_LIVE_PROVIDERS"
for provider in "${providers[@]}"; do
  provider="${provider// /}"
  case "$provider" in
    claude) crate=bullet-harness-claude; binary=claude ;;
    codex)  crate=bullet-harness-codex; binary=codex ;;
    cursor) crate=bullet-harness-cursor; binary=cursor-agent ;;
    agy)    crate=bullet-harness-antigravity; binary=agy ;;
    *) echo "[ci] unknown live provider: $provider" >&2; exit 1 ;;
  esac
  require_tool "$binary" || exit 1
  log "live smoke: $provider ($crate)"
  cargo test -p "$crate" --features live --test live -- --ignored || status=1
done
exit "$status"
