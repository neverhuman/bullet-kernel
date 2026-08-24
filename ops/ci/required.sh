#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "required lane: fast + clippy"
bash ops/ci/fast.sh
cargo clippy --workspace --all-targets -- -D warnings
log "required lane passed"
