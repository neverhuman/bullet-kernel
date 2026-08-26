#!/usr/bin/env bash
# Connected family tests. No sibling fallback is accepted: the Hub must build
# bullet-gitd first and pass its exact canonical absolute path.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool realpath || exit 1
if [[ -z "${BULLET_GITD_BIN:-}" ]]; then
  refuse BULLET_GITD_BIN_REQUIRED "set BULLET_GITD_BIN to the Hub-built daemon's exact absolute path"
  exit 1
fi
if [[ "$BULLET_GITD_BIN" != /* ]]; then
  refuse BULLET_GITD_BIN_NOT_ABSOLUTE "$BULLET_GITD_BIN"
  exit 1
fi
if [[ ! -f "$BULLET_GITD_BIN" || ! -x "$BULLET_GITD_BIN" ]]; then
  refuse BULLET_GITD_BIN_NOT_EXECUTABLE "$BULLET_GITD_BIN"
  exit 1
fi
resolved="$(realpath -e -- "$BULLET_GITD_BIN")" || {
  refuse BULLET_GITD_BIN_UNRESOLVED "$BULLET_GITD_BIN"
  exit 1
}
if [[ "$resolved" != "$BULLET_GITD_BIN" ]]; then
  refuse BULLET_GITD_BIN_NOT_CANONICAL "expected $resolved"
  exit 1
fi
if [[ ! "${BULLET_GITD_SHA256:-}" =~ ^[0-9a-f]{64}$ ]]; then
  refuse BULLET_GITD_SHA256_REQUIRED "set BULLET_GITD_SHA256 to the Hub-built daemon digest"
  exit 1
fi
if [[ "$(sha256_file "$BULLET_GITD_BIN")" != "$BULLET_GITD_SHA256" ]]; then
  refuse BULLET_GITD_DIGEST_MISMATCH before-family
  exit 1
fi
export BULLET_GITD_BIN
export BULLET_GITD_SHA256
run_partition_tests family family "$EXPECTED_FAMILY_TESTS" "$FAMILY_FILTER"
if [[ "$(sha256_file "$BULLET_GITD_BIN")" != "$BULLET_GITD_SHA256" ]]; then
  refuse BULLET_GITD_DIGEST_MISMATCH after-family
  exit 1
fi
log "family lane passed with BULLET_GITD_BIN=$BULLET_GITD_BIN"
