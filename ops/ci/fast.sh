#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "fast lane: fmt + tests + contracts"
cargo fmt --all --check
run_tests fast
cargo run --locked -q -p bullet -- contracts check
log "fast lane passed"
