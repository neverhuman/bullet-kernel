#!/usr/bin/env bash
# Explicit local live-feature refusal entrypoint; no hosted schedule is registered yet.
# BULLET_LIVE_PROVIDERS unset returns 78 to distinguish unregistered from success.
# Set (comma list of claude,codex,cursor,agy): each named CLI must exist and its exact
# feature-gated refusal test must run. Passing this lane is not live conformance.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_PROVIDERS:-}" ]]; then
  log "BULLET_LIVE_PROVIDERS unset; no live lane registered"
  exit 78
fi
status=0
IFS=',' read -ra providers <<< "$BULLET_LIVE_PROVIDERS"
for provider in "${providers[@]}"; do
  provider="${provider// /}"
  case "$provider" in
    claude)
      crate=bullet-harness-claude
      binary=claude
      test_name=live_feature_still_fails_closed_without_authority
      ;;
    codex)
      crate=bullet-harness-codex
      binary=codex
      test_name=live_feature_still_fails_closed_without_authority
      ;;
    cursor)
      crate=bullet-harness-cursor
      binary=cursor-agent
      test_name=live_feature_fails_closed_and_creates_zero_artifacts
      ;;
    agy)
      crate=bullet-harness-antigravity
      binary=agy
      test_name=live_feature_still_fails_closed_without_authority
      ;;
    *) echo "[ci] unknown live provider: $provider" >&2; exit 1 ;;
  esac
  require_tool "$binary" || exit 1
  log "live-feature refusal: $provider ($crate)"
  cargo test --locked -p "$crate" --features live --test live -- "$test_name" --exact || status=1
done
exit "$status"
