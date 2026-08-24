#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT
export GIT_TERMINAL_PROMPT=0

log() { printf '[ci] %s\n' "$*"; }

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[ci] missing required tool: %s\n' "$1" >&2
    return 1
  fi
}

run_tests() {
  local profile="${1:-fast}"
  if command -v cargo-nextest >/dev/null 2>&1 || cargo nextest --version >/dev/null 2>&1; then
    log "tests via nextest profile=${profile}"
    cargo nextest run --workspace --profile "${profile}"
  else
    log "nextest missing; cargo test --workspace"
    cargo test --workspace
  fi
}
